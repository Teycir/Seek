/**
 * RIPE stat — ASN info, prefixes, RIR. Replaces BGPView (domain gone).
 *
 * Two RIPE stat endpoints used:
 *   network-info:         IP -> { asns, prefix }  (fast, single call)
 *   as-overview:          ASN -> { holder, announced }
 *   announced-prefixes:   ASN -> prefix list
 *
 * For IP queries a single network-info call gives the ASN; a second
 * as-overview call fills in the holder name and description.
 * For ASN queries as-overview + announced-prefixes run in parallel.
 *
 * Endpoint: https://stat.ripe.net/data/{endpoint}/data.json
 * Auth:     none | Limits: generous public API | TTL: 24 hours
 */
import type { BGPViewResult, LookupQuery, SourceResult } from '../../lib/types'
import { cacheGet, cachePut, CacheKey, TTL } from '../../lib/cache'
import { ok, error, skipped, safeJson } from '../../lib/results'
import { safeFetch } from '../../lib/ssrf'

const SOURCE = 'bgpview'
const BASE    = 'https://stat.ripe.net/data'

// ─── RIPE stat helpers ────────────────────────────────────────────────────────

interface NetworkInfoData {
  asns:   string[]   // ["15169"]
  prefix: string     // "8.8.8.0/24"
}

interface ASOverviewData {
  holder:    string   // "GOOGLE - Google LLC"
  announced: boolean
}

interface AnnouncedPrefixesData {
  prefixes: { prefix: string }[]
}

async function ripeGet<T>(path: string): Promise<T> {
  const res = await safeFetch(`${BASE}/${path}`, {
    headers: { Accept: 'application/json' },
    signal:  AbortSignal.timeout(8000),
  })
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const json = await safeJson<any>(
    res,
    (v): v is Record<string, unknown> => typeof v === 'object' && v !== null,
    SOURCE,
  )
  if (json.status !== 'ok') throw new Error(`RIPE status: ${json.status}`)
  return json.data as T
}

// ─── Main fetch ───────────────────────────────────────────────────────────────

export async function fetchBGPView(
  query: LookupQuery,
  db: D1Database,
): Promise<SourceResult<BGPViewResult>> {
  if (query.type === 'domain') return skipped(SOURCE)

  let cacheKey: string

  if (query.type === 'asn') {
    cacheKey = CacheKey.bgpASN(query.normalised)
  } else {
    cacheKey = CacheKey.bgpIP(query.normalised)
  }

  const cached = await cacheGet<BGPViewResult>(db, cacheKey, query.forceRefresh)
  if (cached) return ok(SOURCE, cached, true)

  try {
    let asnNum: string
    let prefixes: string[]
    let holder: string
    let prefix: string | undefined

    if (query.type === 'asn') {
      asnNum = query.normalised.replace(/^as/i, '')
      const [overview, announced] = await Promise.all([
        ripeGet<ASOverviewData>(`as-overview/data.json?resource=AS${asnNum}`),
        ripeGet<AnnouncedPrefixesData>(`announced-prefixes/data.json?resource=AS${asnNum}`),
      ])
      holder   = overview.holder ?? ''
      prefixes = (announced.prefixes ?? []).map(p => p.prefix)
    } else {
      // IP query: network-info gives ASN + prefix, then as-overview for name
      const netInfo = await ripeGet<NetworkInfoData>(
        `network-info/data.json?resource=${query.normalised}`,
      )
      asnNum = (netInfo.asns?.[0] ?? '').replace(/^AS/i, '')
      prefix = netInfo.prefix

      if (!asnNum) {
        // Unrouted / bogon IP
        const data: BGPViewResult = {
          asn: 0, name: '', description: '', country: '',
          prefixes: prefix ? [prefix] : [],
          upstreams: [], peers: [], rir: '',
        }
        await cachePut(db, cacheKey, data, TTL.BGP)
        return ok(SOURCE, data)
      }

      const overview = await ripeGet<ASOverviewData>(
        `as-overview/data.json?resource=AS${asnNum}`,
      )
      holder   = overview.holder ?? ''
      prefixes = prefix ? [prefix] : []
    }

    // holder = "GOOGLE - Google LLC" — take the part after " - " as description
    const dashIdx   = holder.indexOf(' - ')
    const name      = dashIdx >= 0 ? holder.slice(dashIdx + 3) : holder
    const shortName = dashIdx >= 0 ? holder.slice(0, dashIdx) : holder

    const data: BGPViewResult = {
      asn:         parseInt(asnNum, 10) || 0,
      name:        shortName,
      description: name,
      country:     '',   // RIPE stat as-overview doesn't return country on free path
      prefixes,
      upstreams:   [],   // not available without additional API call
      peers:       [],
      rir:         '',   // derivable from block.desc but not critical
    }

    await cachePut(db, cacheKey, data, TTL.BGP)
    return ok(SOURCE, data)
  } catch (err) {
    console.error(`[${SOURCE}] fetch failed for ${query.normalised}`, err)
    return error(SOURCE, String(err))
  }
}
