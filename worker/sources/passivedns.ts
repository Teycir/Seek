/**
 * HackerTarget — passive DNS via hostsearch and reverse-IP lookup.
 *
 * Replaces CIRCL Passive DNS which now requires authentication.
 * HackerTarget is free, no key required, works from Cloudflare Workers.
 *
 * Two endpoints:
 *   hostsearch:        domain → subdomain,ip lines  ("what IPs/hosts for domain?")
 *   reverseiplookup:   IP    → hostname lines        ("what hosts share this IP?")
 *
 * For domain queries both run in parallel: hostsearch on the domain
 * and reverseiplookup on the resolved IP (when available).
 *
 * Response format: plain text, one "hostname,ip" or "hostname" per line.
 * Rate limit: ~100 req/day unauthenticated. Results cached 12h to stay well within.
 *
 * Endpoint: https://api.hackertarget.com/hostsearch/?q={domain}
 *           https://api.hackertarget.com/reverseiplookup/?q={ip}
 * Auth:     none | TTL: 12 hours
 */
import type { LookupQuery, PassiveDNSRecord, SourceResult } from '../../lib/types'
import { cacheGet, cachePut, CacheKey, TTL } from '../../lib/cache'
import { ok, error } from '../../lib/results'
import { safeFetch } from '../../lib/ssrf'

const SOURCE = 'passivedns'

/**
 * Parse HackerTarget plain-text response into PassiveDNSRecord shape.
 * hostsearch lines:      "subdomain.example.com,1.2.3.4"
 * reverseiplookup lines: "hostname.example.com"  (no IP column)
 */
function parseLines(text: string, queryType: 'domain' | 'ip'): PassiveDNSRecord[] {
  if (!text.trim() || text.includes('error') || text.includes('API count')) return []
  const now = Math.floor(Date.now() / 1000)
  return text
    .split('\n')
    .map(l => l.trim())
    .filter(Boolean)
    .map(line => {
      const parts = line.split(',')
      if (queryType === 'domain') {
        // "hostname,ip"
        const rrname = parts[0] ?? line
        const rdata  = parts[1] ?? ''
        return {
          rrname, rrtype: 'A', rdata,
          time_first: now, time_last: now, count: 1,
        } satisfies PassiveDNSRecord
      } else {
        // "hostname" — we know the IP (it's what we queried)
        return {
          rrname: line, rrtype: 'A', rdata: '',
          time_first: now, time_last: now, count: 1,
        } satisfies PassiveDNSRecord
      }
    })
}

async function htGet(endpoint: string, q: string): Promise<string> {
  const res = await safeFetch(
    `https://api.hackertarget.com/${endpoint}/?q=${encodeURIComponent(q)}`,
    { signal: AbortSignal.timeout(10000) },
  )
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  return res.text()
}

export async function fetchPassiveDNS(
  query: LookupQuery,
  db: D1Database,
  ipQuery?: LookupQuery | null,
): Promise<SourceResult<PassiveDNSRecord[]>> {
  const cacheKey = CacheKey.passivedns(query.normalised)
  const cached = await cacheGet<PassiveDNSRecord[]>(db, cacheKey, query.forceRefresh)
  if (cached) return ok(SOURCE, cached, true)

  try {
    const tasks: Promise<PassiveDNSRecord[]>[] = []

    if (query.type === 'domain') {
      // hostsearch: subdomains + IPs for the domain
      tasks.push(
        htGet('hostsearch', query.normalised)
          .then(t => parseLines(t, 'domain'))
          .catch(() => []),
      )
      // reverseiplookup on the resolved IP: other hosts sharing same IP
      if (ipQuery) {
        tasks.push(
          htGet('reverseiplookup', ipQuery.normalised)
            .then(t => parseLines(t, 'ip'))
            .catch(() => []),
        )
      }
    } else {
      // IP query: reverse lookup
      tasks.push(
        htGet('reverseiplookup', query.normalised)
          .then(t => parseLines(t, 'ip'))
          .catch(err => { throw err }),  // primary — re-throw so outer catch fires
      )
    }

    const results = await Promise.all(tasks)

    // Merge and deduplicate by (rrname, rdata) pair
    const seen = new Set<string>()
    const data: PassiveDNSRecord[] = []
    for (const batch of results) {
      for (const r of batch) {
        const key = `${r.rrname}|${r.rdata}`
        if (seen.has(key)) continue
        seen.add(key)
        data.push(r)
      }
    }

    await cachePut(db, cacheKey, data, TTL.PASSIVEDNS)
    return ok(SOURCE, data)
  } catch (err) {
    console.error(`[${SOURCE}] fetch failed for ${query.normalised}`, err)
    return error(SOURCE, String(err))
  }
}
