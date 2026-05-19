/**
 * ipinfo.io — geo, ASN, org, anycast flag.
 *
 * Replaces ip-api.com which blocks Cloudflare Workers egress IPs (HTTP 403).
 * ipinfo.io free tier: 50k req/month, no key required, works from Workers.
 *
 * Free fields: ip, hostname, city, region, country, loc (lat,lon),
 *              org ("AS15169 Google LLC"), timezone, anycast, postal.
 * proxy/hosting/mobile flags require a paid key — omitted on free tier.
 *
 * Endpoint: https://ipinfo.io/{ip}/json
 * Auth:     none (free tier) | Limits: 50k/month | TTL: 1 hour
 */
import type { IPAPIResult, LookupQuery, SourceResult } from '../../lib/types'
import { cacheGet, cachePut, CacheKey, TTL } from '../../lib/cache'
import { ok, error, skipped, safeJson } from '../../lib/results'
import { safeFetch } from '../../lib/ssrf'

const SOURCE = 'ipapi'

interface RawIPInfo {
  ip: string
  hostname?: string
  city?: string
  region?: string
  country?: string
  loc?: string       // "lat,lon"
  org?: string       // "AS15169 Google LLC"
  timezone?: string
  anycast?: boolean
  bogon?: boolean    // true for private/reserved IPs
}

function isRawIPInfo(v: unknown): v is RawIPInfo {
  if (typeof v !== 'object' || v === null) return false
  return typeof (v as Record<string, unknown>).ip === 'string'
}

export async function fetchIPAPI(
  query: LookupQuery,
  db: D1Database,
): Promise<SourceResult<IPAPIResult>> {
  if (query.type !== 'ip') return skipped(SOURCE)

  const cacheKey = CacheKey.ipapi(query.normalised)
  const cached = await cacheGet<IPAPIResult>(db, cacheKey, query.forceRefresh)
  if (cached) return ok(SOURCE, cached, true)

  try {
    const res = await safeFetch(
      `https://ipinfo.io/${query.normalised}/json`,
      { signal: AbortSignal.timeout(8000) },
    )

    if (!res.ok) {
      console.error(`[${SOURCE}] HTTP ${res.status} for ${query.normalised}`)
      return error(SOURCE, `HTTP ${res.status}`)
    }

    const raw = await safeJson<RawIPInfo>(res, isRawIPInfo, SOURCE)

    // bogon = private/reserved IP — not an error, just nothing to show
    if (raw.bogon) {
      console.warn(`[${SOURCE}] bogon IP skipped: ${query.normalised}`)
      return skipped(SOURCE)
    }

    // loc = "37.4056,-122.0775"
    const [latStr, lonStr] = (raw.loc ?? '0,0').split(',')
    const lat = parseFloat(latStr ?? '0')
    const lon = parseFloat(lonStr ?? '0')

    // org = "AS15169 Google LLC" — split into ASN and ISP name
    const org = raw.org ?? ''
    const asnMatch = org.match(/^(AS\d+)\s+(.+)$/)
    const asn = asnMatch?.[1] ?? ''
    const isp = asnMatch?.[2] ?? org

    const data: IPAPIResult = {
      ip:          raw.ip,
      country:     raw.country ?? '',
      countryCode: raw.country ?? '',
      region:      raw.region ?? '',
      city:        raw.city ?? '',
      lat,
      lon,
      org,
      asn,
      isp,
      timezone:    raw.timezone ?? '',
      // proxy/hosting/mobile require paid key — default false on free tier
      proxy:       false,
      hosting:     raw.anycast ?? false,
      mobile:      false,
    }

    await cachePut(db, cacheKey, data, TTL.CORE)
    return ok(SOURCE, data)
  } catch (err) {
    console.error(`[${SOURCE}] fetch failed for ${query.normalised}`, err)
    return error(SOURCE, String(err))
  }
}
