/**
 * Wayback CDX API — historical web snapshots.
 *
 * Domain queries only. Returns up to 100 collapsed snapshot records.
 * The CDX API response is a JSON array of arrays (first row = field names).
 *
 * Endpoint: https://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&...
 * Auth:     none | Limits: unlimited | TTL: 7 days
 */
import type { LookupQuery, SourceResult, WaybackResult } from '../../lib/types'
import { cacheGet, cachePut, CacheKey, TTL } from '../../lib/cache'
import { ok, error, skipped, safeJson } from '../../lib/results'
import { safeFetch } from '../../lib/ssrf'

const SOURCE = 'wayback'

export async function fetchWayback(
  query: LookupQuery,
  db: D1Database,
): Promise<SourceResult<WaybackResult[]>> {
  if (query.type !== 'domain') return skipped(SOURCE)

  const cacheKey = CacheKey.wayback(query.normalised)
  const cached = await cacheGet<WaybackResult[]>(db, cacheKey, query.forceRefresh)
  if (cached) return ok(SOURCE, cached, true)

  try {
    const params = new URLSearchParams({
      url:      `${query.normalised}/*`,
      output:   'json',
      fl:       'original,timestamp,statuscode,mimetype',
      limit:    '100',
      collapse: 'urlkey',
    })

    const res = await safeFetch(
      `https://web.archive.org/cdx/search/cdx?${params}`,
      { signal: AbortSignal.timeout(8000) },
    )

    if (!res.ok) {
      console.error(`[${SOURCE}] HTTP ${res.status} for ${query.normalised}`)
      return error(SOURCE, `HTTP ${res.status}`)
    }

    // CDX returns a JSON array of arrays; first row is the field header.
    // When there are no results the API returns an empty array [] — guard
    // against that before slicing so we don't treat row[0] as a data row.
    const rows = await safeJson<string[][]>(
      res,
      (v): v is string[][] => Array.isArray(v),
      SOURCE,
    )
    if (!Array.isArray(rows) || rows.length <= 1) {
      await cachePut(db, cacheKey, [], TTL.WAYBACK)
      return ok(SOURCE, [])
    }

    // Skip header row (index 0)
    const data: WaybackResult[] = rows.slice(1).map(row => ({
      url:        row[0] ?? '',
      timestamp:  row[1] ?? '',
      statusCode: row[2] ?? '',
      mimeType:   row[3] ?? '',
    }))

    await cachePut(db, cacheKey, data, TTL.WAYBACK)
    return ok(SOURCE, data)
  } catch (err) {
    console.error(`[${SOURCE}] fetch failed for ${query.normalised}`, err)
    return error(SOURCE, String(err))
  }
}
