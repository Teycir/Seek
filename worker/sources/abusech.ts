/**
 * abuse.ch — five threat intel sources under one API key.
 *
 * All five use POST with application/x-www-form-urlencoded.
 * Feodo and SSLBL use D1 tables (populated by the cron worker hourly).
 * Lookups are a single indexed SELECT — no in-memory scanning.
 *
 * Sources: URLhaus, ThreatFox, MalwareBazaar, Feodo Tracker, SSLBL
 * Auth:    single ABUSECH_KEY for URLhaus, ThreatFox, MalwareBazaar
 * TTL:     30 minutes (threat intel) | blocklists refreshed hourly via cron
 */
import type {
  FeodoEntry,
  LookupQuery,
  MalwareBazaarResult,
  SSLBLEntry,
  SourceResult,
  ThreatFoxResult,
  URLhausResult,
} from '../../lib/types'
import { cacheGet, cachePut, CacheKey, TTL } from '../../lib/cache'
import { ok, error, skipped, safeJson } from '../../lib/results'
import { safeFetch } from '../../lib/ssrf'

// ─── Shared POST helper ───────────────────────────────────────────────────────

async function abusePost<T>(
  url: string,
  body: Record<string, string>,
  apiKey: string,
): Promise<T> {
  const params = new URLSearchParams({ ...body, 'Auth-Key': apiKey })
  const res = await safeFetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: params.toString(),
    signal: AbortSignal.timeout(8000),
  })
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  return safeJson<T>(res, undefined, url)
}

// ─── URLhaus ──────────────────────────────────────────────────────────────────

export async function fetchURLhaus(
  query: LookupQuery,
  db: D1Database,
  apiKey: string,
): Promise<SourceResult<URLhausResult>> {
  const SOURCE = 'urlhaus'
  const cacheKey = CacheKey.urlhaus(query.normalised)

  const cached = await cacheGet<URLhausResult>(db, cacheKey, query.forceRefresh)
  if (cached) return ok(SOURCE, cached, true)

  try {
    const data = await abusePost<URLhausResult>(
      'https://urlhaus-api.abuse.ch/v1/host/',
      { host: query.normalised },
      apiKey,
    )
    await cachePut(db, cacheKey, data, TTL.ABUSECH)
    return ok(SOURCE, data)
  } catch (err) {
    console.error(`[${SOURCE}] fetch failed for ${query.normalised}`, err)
    return error(SOURCE, String(err))
  }
}

// ─── ThreatFox ────────────────────────────────────────────────────────────────

export async function fetchThreatFox(
  query: LookupQuery,
  db: D1Database,
  apiKey: string,
): Promise<SourceResult<ThreatFoxResult>> {
  const SOURCE = 'threatfox'
  const cacheKey = CacheKey.threatfox(query.normalised)

  const cached = await cacheGet<ThreatFoxResult>(db, cacheKey, query.forceRefresh)
  if (cached) return ok(SOURCE, cached, true)

  try {
    const res = await safeFetch('https://threatfox-api.abuse.ch/api/v1/', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Auth-Key': apiKey,
      },
      body: JSON.stringify({
        query: 'search_ioc',
        search_term: query.normalised,
      }),
      signal: AbortSignal.timeout(8000),
    })
    if (!res.ok) throw new Error(`HTTP ${res.status}`)
    const data = await safeJson<ThreatFoxResult>(
      res,
      (v): v is ThreatFoxResult =>
        typeof v === 'object' && v !== null && 'query_status' in (v as object),
      'threatfox',
    )
    await cachePut(db, cacheKey, data, TTL.ABUSECH)
    return ok(SOURCE, data)
  } catch (err) {
    console.error(`[${SOURCE}] fetch failed for ${query.normalised}`, err)
    return error(SOURCE, String(err))
  }
}

// ─── MalwareBazaar ────────────────────────────────────────────────────────────
// Supports hash lookups (SHA256) and tag/signature queries.
// For IP/domain queries we search by the query value as a tag/signature term.
// Results are cached by query value.

export async function fetchMalwareBazaar(
  query: LookupQuery,
  db: D1Database,
  apiKey: string,
  hash?: string,
): Promise<SourceResult<MalwareBazaarResult>> {
  const SOURCE = 'malwarebazaar'
  const lookupValue = hash ?? query.normalised
  const cacheKey = CacheKey.malwarebazaar(lookupValue)

  const cached = await cacheGet<MalwareBazaarResult>(db, cacheKey, query.forceRefresh)
  if (cached) return ok(SOURCE, cached, true)

  try {
    // Use search_ioc for IP/domain queries — search_tag matches malware family
    // names only and silently returns nothing for network IOCs.
    const body = hash
      ? { query: 'search_hash', hash }
      : { query: 'search_ioc', ioc: query.normalised }

    const data = await abusePost<MalwareBazaarResult>(
      'https://mb-api.abuse.ch/api/v1/',
      body,
      apiKey,
    )
    await cachePut(db, cacheKey, data, TTL.ABUSECH)
    return ok(SOURCE, data)
  } catch (err) {
    console.error(`[${SOURCE}] fetch failed for ${lookupValue}`, err)
    return error(SOURCE, String(err))
  }
}

// ─── Feodo Tracker ────────────────────────────────────────────────────────────
// Lookup is a single indexed SELECT on D1 (populated hourly by cron).

export async function fetchFeodo(
  query: LookupQuery,
  db: D1Database,
): Promise<SourceResult<FeodoEntry | null>> {
  const SOURCE = 'feodo'

  if (query.type !== 'ip') return skipped(SOURCE)

  try {
    const row = await db
      .prepare(
        `SELECT ip_address, port, status, hostname, as_number, as_name,
                country, first_seen, last_seen, malware
         FROM feodo_blocklist WHERE ip_address = ?`,
      )
      .bind(query.normalised)
      .first<FeodoEntry>()

    return ok(SOURCE, row ?? null)
  } catch (err) {
    console.error(`[${SOURCE}] D1 lookup failed for ${query.normalised}`, err)
    return error(SOURCE, String(err))
  }
}

// ─── SSLBL ────────────────────────────────────────────────────────────────────
// Lookup by dst_ip via an index on sslbl_blocklist.dst_ip (populated hourly by cron).

export async function fetchSSLBL(
  query: LookupQuery,
  db: D1Database,
): Promise<SourceResult<SSLBLEntry[]>> {
  const SOURCE = 'sslbl'

  if (query.type !== 'ip') return skipped(SOURCE)

  try {
    const { results } = await db
      .prepare(
        `SELECT sha1 as SHA1, listing_date as Listingdate, listing_time as Listingtime,
                suspicious_reason as SuspiciousReason,
                dst_ip as DstIP, dst_port as DstPort, subject as Subject
         FROM sslbl_blocklist WHERE dst_ip = ?`,
      )
      .bind(query.normalised)
      .all<SSLBLEntry>()

    return ok(SOURCE, results ?? [])
  } catch (err) {
    console.error(`[${SOURCE}] D1 lookup failed for ${query.normalised}`, err)
    return error(SOURCE, String(err))
  }
}
