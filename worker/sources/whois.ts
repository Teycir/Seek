/**
 * WHOIS — raw registration data via whoisjson.com (free, no auth).
 *
 * Complements RDAP with fields RDAP registries often omit:
 *   • Registrant / admin / tech contact names and emails
 *   • Abuse contact email
 *   • Raw WHOIS text (for copy-paste into other tools)
 *   • DNSSEC status
 *
 * Domain queries only — IPs are already covered by RDAP + BGPView.
 * Falls back gracefully: if the field is absent in the response it is
 * simply omitted from the result rather than erroring.
 *
 * Endpoint: https://whoisjson.com/api/v1/whois?domain={domain}
 * Auth:     none (free tier, rate-limited to ~100 req/hr per IP)
 * TTL:      24 hours (registration data changes rarely)
 */
import type { LookupQuery, SourceResult, WhoisResult } from '../../lib/types'
import { cacheGet, cachePut, CacheKey, TTL } from '../../lib/cache'
import { ok, error, skipped } from '../../lib/results'
import { safeFetch } from '../../lib/ssrf'

const SOURCE = 'whois'

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function str(v: unknown): string | undefined {
  if (typeof v === 'string' && v.trim()) return v.trim()
  return undefined
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function normalise(raw: any, domain: string): WhoisResult {
  const registrar       = str(raw.registrar)
  const registrarUrl    = str(raw.registrar_url)
  const registrant      = str(raw.registrant_name)     ?? str(raw.registrant?.name)
  const registrantOrg   = str(raw.registrant_org)      ?? str(raw.registrant?.organization)
  const registrantEmail = str(raw.registrant_email)    ?? str(raw.registrant?.email)
  const adminEmail      = str(raw.admin_email)         ?? str(raw.admin?.email)
  const techEmail       = str(raw.tech_email)          ?? str(raw.tech?.email)
  const abuseEmail      = str(raw.abuse_email)
  const created         = str(raw.creation_date)       ?? str(raw.created)
  const updated         = str(raw.updated_date)        ?? str(raw.updated)
  const expires         = str(raw.expiration_date)     ?? str(raw.expires)
  const dnssec          = str(raw.dnssec)
  const rawText         = str(raw.raw_text)

  const nameservers = Array.isArray(raw.name_servers)
    ? (raw.name_servers as string[]).map(s => s.toLowerCase().trim()).filter(Boolean)
    : undefined

  const status = Array.isArray(raw.status)
    ? (raw.status as string[]).map(s => String(s).trim()).filter(Boolean)
    : str(raw.status)
      ? [str(raw.status)!]
      : undefined

  return {
    domain: str(raw.domain) ?? domain,
    ...(registrar       && { registrar }),
    ...(registrarUrl    && { registrarUrl }),
    ...(registrant      && { registrant }),
    ...(registrantOrg   && { registrantOrg }),
    ...(registrantEmail && { registrantEmail }),
    ...(adminEmail      && { adminEmail }),
    ...(techEmail       && { techEmail }),
    ...(abuseEmail      && { abuseEmail }),
    ...(created         && { created }),
    ...(updated         && { updated }),
    ...(expires         && { expires }),
    ...(nameservers && nameservers.length > 0 && { nameservers }),
    ...(dnssec          && { dnssec }),
    ...(status && status.length > 0 && { status }),
    ...(rawText         && { rawText }),
  }
}

export async function fetchWhois(
  query: LookupQuery,
  db: D1Database,
): Promise<SourceResult<WhoisResult>> {
  if (query.type !== 'domain') return skipped(SOURCE)

  const cacheKey = CacheKey.whois(query.normalised)
  const cached = await cacheGet<WhoisResult>(db, cacheKey, query.forceRefresh)
  if (cached) return ok(SOURCE, cached, true)

  try {
    const url = `https://whoisjson.com/api/v1/whois?domain=${encodeURIComponent(query.normalised)}`
    const res = await safeFetch(url, { signal: AbortSignal.timeout(15000) })

    if (res.status === 429) {
      console.warn(`[${SOURCE}] rate limited — skipping`)
      return skipped(SOURCE)
    }

    if (!res.ok) throw new Error(`HTTP ${res.status}`)

    const ct = res.headers.get('content-type') ?? ''
    if (!ct.includes('json')) {
      console.warn(`[${SOURCE}] unexpected content-type "${ct}"`)
      return skipped(SOURCE)
    }

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    let raw: any
    try {
      raw = await res.json()
    } catch (parseErr) {
      throw new Error(`JSON parse failed: ${parseErr}`)
    }

    if (!raw || typeof raw !== 'object') return skipped(SOURCE)

    // whoisjson wraps results in a "whois" key on some endpoints
    const data = raw.whois ?? raw
    const result = normalise(data, query.normalised)

    await cachePut(db, cacheKey, result, TTL.RDAP) // 24-hour TTL — same as RDAP
    return ok(SOURCE, result)
  } catch (err) {
    console.error(`[${SOURCE}] fetch failed for ${query.normalised}`, err)
    return error(SOURCE, String(err))
  }
}
