/**
 * GrayHatWarfare — exposed cloud bucket discovery.
 *
 * Domain queries only — never called for raw IP lookups.
 * Uses KeyRing rotation across 18 API keys.
 * On HTTP 429/403, marks the current key exhausted and retries once.
 *
 * Endpoint: https://buckets.grayhatwarfare.com/api/v2/buckets?keywords={domain}&access_token={key}
 * Auth:     rotating API key | TTL: 6 hours
 */
import type { BucketResult, LookupQuery, SourceResult } from '../../lib/types'
import { cacheGet, cachePut, CacheKey, TTL } from '../../lib/cache'
import { ok, error, skipped, safeJson } from '../../lib/results'
import { safeFetch } from '../../lib/ssrf'
import type { KeyRing } from '../../lib/keyring'

const SOURCE = 'ghw'

interface GHWBucket {
  bucket: string
  fileCount: number
  type: string       // "aws-s3" | "azure-blob" | "gcp-storage"
  url: string
  lastSeen: string
}

interface GHWResponse {
  buckets: GHWBucket[]
}

function mapProvider(type: string): 'aws' | 'azure' | 'gcp' {
  if (type.includes('azure')) return 'azure'
  if (type.includes('gcp') || type.includes('google')) return 'gcp'
  return 'aws'
}

async function doFetch(domain: string, key: string): Promise<BucketResult[]> {
  const url = `https://buckets.grayhatwarfare.com/api/v2/buckets?keywords=${encodeURIComponent(domain)}&access_token=${key}`
  const res = await safeFetch(url, { signal: AbortSignal.timeout(8000) })
  if (!res.ok) throw Object.assign(new Error(`HTTP ${res.status}`), { status: res.status })
  const json = await safeJson<GHWResponse>(
    res,
    (v): v is GHWResponse => typeof v === 'object' && v !== null && 'buckets' in (v as object),
    'ghw',
  )
  return (json.buckets ?? []).map(b => ({
    bucket:    b.bucket,
    fileCount: b.fileCount,
    provider:  mapProvider(b.type),
    url:       b.url,
    lastSeen:  b.lastSeen,
  }))
}

export async function fetchGHW(
  domain: string,
  db: D1Database,
  ring: KeyRing,
  forceRefresh = false,
): Promise<SourceResult<BucketResult[]>> {
  const cacheKey = CacheKey.ghwBuckets(domain)
  const cached = await cacheGet<BucketResult[]>(db, cacheKey, forceRefresh)
  if (cached) return ok(SOURCE, cached, true)

  const key = await ring.nextHealthy()
  if (!key) {
    console.error(`[${SOURCE}] all keys exhausted`)
    return error(SOURCE, 'All API keys exhausted')
  }

  try {
    const data = await doFetch(domain, key)
    await cachePut(db, cacheKey, data, TTL.GHW)
    return ok(SOURCE, data)
  } catch (err: unknown) {
    const status = (err as { status?: number }).status
    if (status === 429 || status === 403) {
      await ring.markExhausted(key)
      // Retry once with next healthy key
      const next = await ring.nextHealthy()
      if (next) {
        try {
          const data = await doFetch(domain, next)
          await cachePut(db, cacheKey, data, TTL.GHW)
          return ok(SOURCE, data)
        } catch (retryErr) {
          const retryStatus = (retryErr as { status?: number }).status
          if (retryStatus === 429 || retryStatus === 403) await ring.markExhausted(next)
          console.error(`[${SOURCE}] retry also failed`, retryErr)
          return error(SOURCE, String(retryErr))
        }
      }
      return error(SOURCE, `Rate limited and no healthy keys remain`)
    }
    console.error(`[${SOURCE}] fetch failed for ${domain}`, err)
    return error(SOURCE, String(err))
  }
}

/**
 * Thin wrapper so the orchestrator can call fetchGHW via a LookupQuery.
 * Skips automatically on non-domain queries.
 */
export async function fetchGHWForQuery(
  query: LookupQuery,
  db: D1Database,
  ring: KeyRing,
): Promise<SourceResult<BucketResult[]>> {
  if (query.type !== 'domain') return skipped(SOURCE)
  return fetchGHW(query.normalised, db, ring, query.forceRefresh)
}
