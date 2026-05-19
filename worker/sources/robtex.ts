/**
 * Robtex — ASN/BGP routing data with passive DNS for an IP.
 *
 * IP queries only. Provides passive DNS (outgoing) and reverse DNS (incoming)
 * correlated with BGP/WHOIS context.
 *
 * Endpoint: https://freeapi.robtex.com/ipquery/{ip}
 * Auth:     none | Limits: unlimited | TTL: 24 hours
 */
import type { LookupQuery, RobtexResult, SourceResult } from '../../lib/types'
import { cacheGet, cachePut, CacheKey, TTL } from '../../lib/cache'
import { ok, error, skipped, safeJson } from '../../lib/results'
import { safeFetch } from '../../lib/ssrf'

const SOURCE = 'robtex'
const MAX_DNS_RECORDS = 100

export async function fetchRobtex(
  query: LookupQuery,
  db: D1Database,
): Promise<SourceResult<RobtexResult>> {
  if (query.type !== 'ip') return skipped(SOURCE)

  const cacheKey = CacheKey.robtex(query.normalised)
  const cached = await cacheGet<RobtexResult>(db, cacheKey, query.forceRefresh)
  if (cached) return ok(SOURCE, cached, true)

  try {
    const res = await safeFetch(
      `https://freeapi.robtex.com/ipquery/${query.normalised}`,
      { signal: AbortSignal.timeout(8000) },
    )

    if (!res.ok) {
      // 400 / 404 for reserved or CDN anycast IPs — not a real upstream failure
      if (res.status === 400 || res.status === 404) {
        console.warn(`[${SOURCE}] HTTP ${res.status} for ${query.normalised} (likely CDN/reserved IP)`)
        return skipped(SOURCE)
      }
      console.error(`[${SOURCE}] HTTP ${res.status} for ${query.normalised}`)
      return error(SOURCE, `HTTP ${res.status}`)
    }

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const json = await safeJson<any>(
      res,
      (v): v is Record<string, unknown> => typeof v === 'object' && v !== null,
      SOURCE,
    )

    const data: RobtexResult = {
      as:         json.as ?? 0,
      asname:     json.asname ?? '',
      whoisdesc:  json.whoisdesc ?? '',
      routedesc:  json.routedesc ?? '',
      bgproute:   json.bgproute ?? '',
      city:       json.city ?? '',
      country:    json.country ?? '',
      passiveDNS: (json.pas ?? []).slice(0, MAX_DNS_RECORDS).map((p: { o: string; t: number }) => ({
        o: p.o,
        t: p.t,
      })),
      reverseDNS: (json.ras ?? []).slice(0, MAX_DNS_RECORDS).map((r: { o: string; t: number }) => ({
        o: r.o,
        t: r.t,
      })),
    }

    await cachePut(db, cacheKey, data, TTL.ROBTEX)
    return ok(SOURCE, data)
  } catch (err) {
    console.error(`[${SOURCE}] fetch failed for ${query.normalised}`, err)
    return error(SOURCE, String(err))
  }
}
