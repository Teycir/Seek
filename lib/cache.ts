// ─── TTL constants (seconds) ──────────────────────────────────────────────────

export const TTL = {
  CVE:        60 * 60 * 24 * 30, // 30 days  — CVE data is immutable post-publish
  WAYBACK:    60 * 60 * 24 * 7,  // 7 days
  BGP:        60 * 60 * 24,      // 24 hours
  RDAP:       60 * 60 * 24,
  ROBTEX:     60 * 60 * 24,
  CERTS:      60 * 60 * 12,      // 12 hours
  PASSIVEDNS: 60 * 60 * 12,
  GHW:        60 * 60 * 6,       // 6 hours
  CORE:       60 * 60,           // 1 hour   — internetdb, ipapi
  BLOCKLIST:  60 * 60,           //           Feodo + SSLBL bulk downloads
  ABUSECH:    60 * 30,           // 30 minutes
  DNS:        60 * 5,            // 5 minutes — DNS resolution
} as const

// ─── Cache key helpers ────────────────────────────────────────────────────────

export const CacheKey = {
  internetdb:  (ip: string)      => `internetdb:${ip}`,
  ipapi:       (ip: string)      => `ipapi:${ip}`,
  bgpIP:       (ip: string)      => `bgp:ip:${ip}`,
  bgpASN:      (asn: string)     => `bgp:asn:${asn}`,
  rdapIP:      (ip: string)      => `rdap:ip:${ip}`,
  rdapDomain:  (domain: string)  => `rdap:domain:${domain}`,
  crtsh:       (domain: string)  => `crtsh:${domain}`,
  whois:       (domain: string)  => `whois:${domain}`,
  passivedns:  (query: string)   => `passivedns:${query}`,
  robtex:      (ip: string)      => `robtex:${ip}`,
  malwarebazaar: (hash: string)  => `malwarebazaar:${hash}`,
  urlhaus:     (query: string)   => `urlhaus:${query}`,
  threatfox:   (query: string)   => `threatfox:${query}`,
  feodoList:   ()                => 'feodo:blocklist',
  sslblList:   ()                => 'sslbl:blocklist',
  nvd:         (cveId: string)   => `nvd:${cveId}`,
  osv:         (cveId: string)   => `osv:${cveId}`,
  ghwBuckets:  (domain: string)  => `ghw:buckets:${domain}`,
  ghwFiles:    (keyword: string) => `ghw:files:${keyword}`,
  wayback:     (domain: string)  => `wayback:${domain}`,
  rdapBootDNS: ()                => 'rdap:boot:dns',
  rdapBootIP:  ()                => 'rdap:boot:ip',
} as const

// ─── D1 cache read / write ────────────────────────────────────────────────────
//
// Source response caches live in D1 (not KV) to preserve KV write quota for
// hot-path counters (rate limiting, concurrency, circuit breakers).
// D1 is well-suited here: values are written once, read occasionally, and
// are large enough that KV's 1 write = 1 quota unit cost adds up fast.
//
// TTL is enforced manually via the `expires_at` column — D1 has no native TTL.
// Expired rows are returned as a miss and lazily overwritten on next fetch.
// A periodic cleanup is not strictly necessary (expired rows are ignored),
// but can be added as a cron if the table grows too large.

/**
 * Read a JSON value from D1 cache. Returns null on miss, expiry, or parse error.
 * Pass `bypass = true` for the ?refresh=1 force-refresh path.
 */
export async function cacheGet<T>(
  db: D1Database,
  key: string,
  bypass = false,
): Promise<T | null> {
  if (bypass) return null
  try {
    const now = Math.floor(Date.now() / 1000)
    const row = await db
      .prepare('SELECT value FROM cache WHERE key = ? AND expires_at > ?')
      .bind(key, now)
      .first<{ value: string }>()
    return row ? (JSON.parse(row.value) as T) : null
  } catch (err) {
    console.error(`[cache] D1 get failed key=${key}`, err)
    return null
  }
}

/**
 * Write a JSON value to D1 cache with a TTL in seconds.
 * Uses INSERT OR REPLACE so repeated writes for the same key are idempotent.
 * Swallows errors — a failed cache write should never break a response.
 */
export async function cachePut<T>(
  db: D1Database,
  key: string,
  value: T,
  ttl: number,
): Promise<void> {
  try {
    const expiresAt = Math.floor(Date.now() / 1000) + ttl
    await db
      .prepare('INSERT OR REPLACE INTO cache (key, value, expires_at) VALUES (?, ?, ?)')
      .bind(key, JSON.stringify(value), expiresAt)
      .run()
  } catch (err) {
    console.error(`[cache] D1 put failed key=${key}`, err)
  }
}
