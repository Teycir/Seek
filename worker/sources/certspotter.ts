/**
 * certspotter — SSLMate's Certificate Spotter (https://sslmate.com/certspotter).
 *
 * Free tier: no API key required, returns all certificates logged to
 * Certificate Transparency (CT) logs for a domain and its subdomains.
 *
 * Used as a fallback / supplement to crt.sh.  The two sources cover
 * overlapping but not identical log sets, so merging them gives better
 * coverage — especially when crt.sh is rate-limiting or returning HTML.
 *
 * Endpoint: https://api.certspotter.com/v1/issuances
 *   ?domain=<domain>&include_subdomains=true&expand=dns_names&expand=issuer&expand=cert
 *
 * Auth:     none (free tier; add ?Authorization= header for paid tier)
 * Limits:   100 req/hr per IP (unauthenticated)
 * TTL:      12 hours (matches crt.sh TTL)
 */
import type { CertRecord, LookupQuery, SourceResult } from '../../lib/types'
import { cacheGet, cachePut, CacheKey, TTL } from '../../lib/cache'
import { ok, error, skipped } from '../../lib/results'
import { safeFetch } from '../../lib/ssrf'

const SOURCE = 'certspotter'
const MAX_RESULTS = 500

interface CertSpotterIssuance {
  id: string
  tbs_sha256: string
  cert_sha256?: string
  dns_names: string[]
  not_before: string
  not_after: string
  revoked: boolean
  issuer?: {
    name: string
  }
  cert?: {
    serial: string
  }
}

export async function fetchCertSpotter(
  query: LookupQuery,
  db: D1Database,
): Promise<SourceResult<CertRecord[]>> {
  if (query.type !== 'domain') return skipped(SOURCE)

  const cacheKey = `certspotter:${query.normalised}`
  const cached = await cacheGet<CertRecord[]>(db, cacheKey, query.forceRefresh)
  if (cached) return ok(SOURCE, cached, true)

  try {
    const url =
      `https://api.certspotter.com/v1/issuances` +
      `?domain=${encodeURIComponent(query.normalised)}` +
      `&include_subdomains=true` +
      `&expand=dns_names` +
      `&expand=issuer` +
      `&expand=cert`

    const res = await safeFetch(url, { signal: AbortSignal.timeout(20000) })

    if (res.status === 429) {
      console.warn(`[${SOURCE}] rate limited — skipping`)
      return skipped(SOURCE)
    }

    if (!res.ok) throw new Error(`HTTP ${res.status}`)

    const ct = res.headers.get('content-type') ?? ''
    if (!ct.includes('json')) {
      console.warn(`[${SOURCE}] unexpected content-type "${ct}" — skipping`)
      return ok(SOURCE, [], false)
    }

    let parsed: unknown
    try {
      parsed = await res.json()
    } catch (parseErr) {
      throw new Error(`JSON parse failed: ${parseErr}`)
    }

    if (!Array.isArray(parsed)) return ok(SOURCE, [], false)

    const issuances = parsed as CertSpotterIssuance[]

    // Deduplicate by tbs_sha256 (unique per unique TBS cert structure)
    const seen = new Set<string>()
    const data: CertRecord[] = []

    for (const iss of issuances) {
      if (seen.has(iss.tbs_sha256)) continue
      seen.add(iss.tbs_sha256)

      data.push({
        // certspotter uses hex string IDs — convert to number for type compat,
        // using a stable hash of the tbs_sha256 prefix (first 8 hex chars → int)
        id:           parseInt(iss.tbs_sha256.slice(0, 8), 16),
        issuer:       iss.issuer?.name ?? 'Unknown',
        commonName:   iss.dns_names[0] ?? query.normalised,
        nameValue:    iss.dns_names.join('\n'),
        notBefore:    iss.not_before,
        notAfter:     iss.not_after,
        serialNumber: iss.cert?.serial ?? iss.tbs_sha256.slice(0, 32),
      })

      if (data.length >= MAX_RESULTS) break
    }

    await cachePut(db, cacheKey, data, TTL.CERTS)
    return ok(SOURCE, data)
  } catch (err) {
    console.error(`[${SOURCE}] fetch failed for ${query.normalised}`, err)
    return error(SOURCE, String(err))
  }
}
