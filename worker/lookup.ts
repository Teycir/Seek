/**
 * lookup.ts — 4-layer execution orchestrator.
 *
 * Layer 1  always runs (Promise.allSettled — 8 sources)
 * Layer 2  runs in parallel with Layer 1 (no dependency)
 * Layer 3  fires only when InternetDB returns CVE IDs
 * Layer 4  domain queries only (GHW + Wayback); skipped for IP/ASN
 *
 * Circuit breakers
 * ─────────────────
 * Before each source is called, its breaker state is checked in KV.
 * If the breaker is OPEN the source is short-circuited with a 'skipped'
 * result — the 5-minute failure-ratio window stays intact and the source
 * auto-recovers after the 15-minute cooldown TTL expires.
 * Success / failure outcomes are fed back to the breaker after each call.
 *
 * Non-blocking D1 persistence via ctx.waitUntil().
 */
import type {
  BGPViewResult,
  BucketResult,
  CertRecord,
  CVEDetail,
  Env,
  HostResult,
  InternetDBResult,
  LookupQuery,
  SourceResult,
  URLhausResult,
  ThreatFoxResult,
  MalwareBazaarResult,
  WaybackResult,
} from '../lib/types'
import { KeyRing } from '../lib/keyring'
import { mergeResults } from '../lib/merge'
import { skipped, unwrap } from '../lib/results'
import { collectSecrets } from '../lib/validate'
import { safeFetch, validateSSRFResolved } from '../lib/ssrf'
import {
  getBreakerState,
  getAllBreakerStatuses,
  recordBreakerSuccess,
  recordBreakerFailure,
} from '../lib/ratelimit'

import { fetchInternetDB } from './sources/internetdb'
import { fetchIPAPI }      from './sources/ipapi'
import { fetchBGPView }    from './sources/bgpview'
import { fetchRDAP }       from './sources/rdap'
import { fetchWhois }      from './sources/whois'
import { fetchCRTSH }      from './sources/crtsh'
import { fetchCertSpotter } from './sources/certspotter'
import { fetchPassiveDNS } from './sources/passivedns'
import { fetchRobtex }     from './sources/robtex'
import {
  fetchURLhaus,
  fetchThreatFox,
  fetchMalwareBazaar,
  fetchFeodo,
  fetchSSLBL,
} from './sources/abusech'
import { CVE as CVE_CONFIG, GHW as GHW_CONFIG } from '../lib/config'
import { fetchCVE }           from './sources/nvd'
import { fetchGHWForQuery }   from './sources/grayhatwarfare'
import { fetchWayback }       from './sources/wayback'
import type { InflightCache } from '../lib/inflight'

// ─── DNS resolution (domain → IP) ─────────────────────────────────────────────

/**
 * Resolve a domain to an IP using Cloudflare DoH.
 * Tries A records first; falls back to AAAA if no A record is returned.
 * Returns null only when both record types fail or SSRF guard blocks the result.
 * Retries once on network/timeout error (not on NXDOMAIN or SSRF block).
 * Result is cached in KV for 5 minutes.
 */
async function resolveDomainToIP(
  domain: string,
  kv: KVNamespace,
  forceRefresh: boolean,
): Promise<string | null> {
  const cacheKey = `dns:a:${domain}`

  if (!forceRefresh) {
    const cached = await kv.get(cacheKey)
    if (cached) return cached
  }

  async function doQuery(type: 'A' | 'AAAA'): Promise<string | null> {
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        const res = await safeFetch(
          `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=${type}`,
          {
            headers: { Accept: 'application/dns-json' },
            signal: AbortSignal.timeout(6000),
          },
        )
        if (!res.ok) {
          console.warn(`[lookup] DoH ${type} HTTP ${res.status} for ${domain} (attempt ${attempt + 1})`)
          continue
        }
        const json = await res.json() as { Answer?: { type: number; data: string }[] }
        // type 1 = A, type 28 = AAAA
        // Many CDN domains resolve via CNAME chains — the Answer section contains
        // both CNAME records (type 5) and the final A/AAAA record. We must scan
        // all records for the right type, not just the first entry.
        const rrType = type === 'A' ? 1 : 28
        const ip = json.Answer?.find(r => r.type === rrType)?.data ?? null
        if (ip) {
          try {
            validateSSRFResolved(ip)
          } catch (err) {
            console.error('[lookup] DNS resolution blocked by SSRF guard:', domain, ip, err)
            return null  // private IP in answer — do not retry
          }
        }
        return ip  // null = NXDOMAIN/no record — valid outcome, stop retrying
      } catch (err) {
        console.warn(`[lookup] DoH ${type} attempt ${attempt + 1} failed for ${domain}:`, err)
      }
    }
    return null
  }

  const ip = (await doQuery('A')) ?? (await doQuery('AAAA'))

  if (ip) {
    try {
      await kv.put(cacheKey, ip, { expirationTtl: 300 })
    } catch (err) {
      console.warn('[lookup] resolveDomainToIP: KV write failed (ignoring):', err)
    }
  } else {
    console.error(`[lookup] DNS resolution failed for ${domain} (A and AAAA both returned nothing)`)
  }

  return ip
}

// ─── All source names (must match the strings used inside each fetcher) ────────

const ALL_SOURCES = [
  'internetdb', 'ipapi', 'bgpview', 'rdap', 'whois', 'crtsh',
  'passivedns', 'robtex',
  'urlhaus', 'threatfox', 'malwarebazaar', 'feodo', 'sslbl',
  'nvd', 'ghw', 'wayback',
] as const

// ─── Breaker-aware fetch wrapper ─────────────────────────────────────────────

/**
 * Wraps a source fetch with circuit-breaker guard.
 * - OPEN + cache hit  → returns cached data (status 'cached') so stale
 *   results are still shown while the upstream recovers.
 * - OPEN + cache miss → returns skipped() — nothing to show.
 * - CLOSED / HALF-OPEN → calls fetcher, records success/failure.
 *
 * The optional `cacheKey` enables the cache-fallback path.  Pass it for
 * any source whose KV key is trivially derivable here (crtsh, rdap, etc.)
 * If omitted, OPEN always returns skipped() (original behaviour).
 */
async function withBreaker<T>(
  source: string,
  kv: KVNamespace,
  fetcher: () => Promise<SourceResult<T>>,
  cacheKey?: string,
): Promise<SourceResult<T>> {
  const state = await getBreakerState(source, kv)
  if (state === 'open') {
    // Try to serve stale cache rather than returning nothing
    if (cacheKey) {
      try {
        const raw = await kv.get(cacheKey)
        if (raw) {
          return { source, status: 'cached', data: JSON.parse(raw) as T }
        }
      } catch {
        // Cache read failed — fall through to skipped
      }
    }
    return skipped<T>(source)
  }

  const result = await fetcher()

  if (result.status === 'error') {
    await recordBreakerFailure(source, kv)
  } else if (result.status !== 'skipped') {
    // ok, cached — non-failures. skipped is intentional and must NOT reset an
    // open breaker (e.g. Feodo skipped for domain queries must not clear a
    // breaker that tripped open due to real upstream failures).
    await recordBreakerSuccess(source, kv)
  }

  return result
}

// ─── CVE batch helper ─────────────────────────────────────────────────────────

/**
 * Fetch CVE details in batches of CVE_CONFIG.MAX_CONCURRENT (default 5).
 * Sequential batches prevent stampeding NVD's rate limit while still being
 * ~5× faster than fully sequential lookups on CVE-heavy hosts.
 */
async function fetchCVEsBatched(
  cveIds: string[],
  kv: KVNamespace,
  nvdKey: string,
  forceRefresh: boolean,
  inflight?: InflightCache,
): Promise<PromiseSettledResult<SourceResult<CVEDetail>>[]> {
  const results: PromiseSettledResult<SourceResult<CVEDetail>>[] = []
  const batchSize = CVE_CONFIG.MAX_CONCURRENT  // 5

  for (let i = 0; i < cveIds.length; i += batchSize) {
    const batch = cveIds.slice(i, i + batchSize)
    const settled = await Promise.allSettled(
      batch.map(id =>
        withBreaker('nvd', kv, () => fetchCVE(id, kv, nvdKey, forceRefresh, inflight)),
      ),
    )
    results.push(...settled)
  }

  return results
}

async function persistSearch(
  query: LookupQuery,
  result: HostResult,
  db: D1Database,
): Promise<void> {
  try {
    await db.prepare(
      `INSERT INTO searches (query, query_type, result_json, duration_ms)
       VALUES (?, ?, ?, ?)`,
    )
      .bind(
        query.normalised,
        query.type,
        JSON.stringify(result),
        result.meta.durationMs,
      )
      .run()
  } catch (err) {
    // Non-critical — log and continue
    console.error('[persist] D1 write failed', err)
  }
}

// ─── Main orchestrator ────────────────────────────────────────────────────────

export async function runLookup(
  query: LookupQuery,
  env: Env,
  ctx: ExecutionContext,
  inflight?: InflightCache,
): Promise<HostResult> {
  const start = Date.now()

  // Key rings
  const ghwKeys = collectSecrets(env as Record<string, unknown>, 'GRAYHATWARFARE_API_KEY', GHW_CONFIG.KEY_COUNT)
  const ghwRing = new KeyRing(ghwKeys, env.KV, 'ghw')

  // ── For domain queries: resolve to IP first so IP-only sources are useful ──
  // This runs before the main layer fan-out and adds ~50ms in the best case
  // (DoH is fast; result is KV-cached for 5 min).
  let ipQuery: LookupQuery | null = null
  if (query.type === 'domain') {
    const resolvedIP = await resolveDomainToIP(
      query.normalised,
      env.KV,
      query.forceRefresh ?? false,
    )
    if (resolvedIP) {
      ipQuery = {
        raw: resolvedIP,
        type: 'ip',
        normalised: resolvedIP,
        forceRefresh: query.forceRefresh ?? false,
      }
    }
  }

  // ── For ASN queries: derive a representative IP from the first announced
  //    prefix so that IP-only sources (InternetDB, ip-api, Robtex, threat
  //    intel) can be fanned in.  Without this every ASN query returns only
  //    the single BGPView card.
  let asnSyntheticIPQuery: LookupQuery | null = null
  // Capture the pre-flight BGPView result so the main fan-out can reuse it
  // rather than fetching BGPView a second time (which wastes quota and fires
  // the circuit-breaker accounting twice for the same request).
  let bgpPreflightResult: SourceResult<BGPViewResult> | null = null
  if (query.type === 'asn') {
    // BGPView is called first in a short pre-flight to get the prefix list.
    // We use it to pick the first /24 host (.1) as the representative IP.
    const bgpPreflight = await withBreaker(
      'bgpview', env.KV, () => fetchBGPView(query, env.KV),
    )
    bgpPreflightResult = bgpPreflight
    const bgpData = (bgpPreflight.status === 'ok' || bgpPreflight.status === 'cached') 
      ? bgpPreflight.data as BGPViewResult | null
      : null
    const firstPrefix = bgpData?.prefixes?.[0]
    if (firstPrefix) {
      // Derive a representative host IP from the first announced prefix.
      // Try .1, .2, and .254 in order — .1 is often firewalled or absent
      // from Shodan on some ASNs, so we attempt a few common host addresses
      // and use the first one that looks like a real routable host.
      // For CDN detection purposes any of them will do; we skip CDN detection
      // entirely for ASN queries (synthetic IPs are never CDN-tagged).
      const network = firstPrefix.split('/')[0]
      if (network) {
        const parts = network.split('.')
        if (parts.length === 4) {
          // Pick the first candidate; CDN detection is skipped for ASN queries
          // so we don't need InternetDB pre-flight to select among candidates.
          parts[3] = '1'
          const syntheticIP = parts.join('.')
          asnSyntheticIPQuery = {
            raw: syntheticIP,
            type: 'ip',
            normalised: syntheticIP,
            forceRefresh: query.forceRefresh ?? false,
          }
        }
      }
    }
  }

  // The effective IP query used for IP-only sources:
  //   IP query   → the original query
  //   domain     → the DNS-resolved IP
  //   ASN        → the synthetic IP derived from the first announced prefix
  const effectiveIPQuery: LookupQuery = ipQuery ?? asnSyntheticIPQuery ?? query

  // ── CDN / anycast detection ────────────────────────────────────────────────
  // Run InternetDB as a pre-flight. If the effective IP is tagged as CDN/proxy,
  // IP-specific sources (ip-api, robtex, bgpview, feodo, sslbl, threat-intel-IP)
  // will either fail or return meaningless shared-infrastructure data.
  // We skip them and rely on domain-string sources instead, which avoids
  // tripping circuit breakers on every Cloudflare-proxied domain lookup.
  //
  // CDN tags in InternetDB: 'cdn', 'cloud', 'proxy' (set by Shodan)
  const CDN_TAGS = new Set(['cdn', 'cloud', 'proxy'])

  let internetdbPreflight: SourceResult<InternetDBResult> | null = null
  let isCDNIP = false

  // Only run the pre-flight when we have a resolved IP from a domain query
  // (ASN synthetic IPs and direct IP queries are never CDN-tagged meaningfully).
  if (query.type === 'domain' && ipQuery !== null) {
    const resolvedIPQuery = ipQuery  // Capture for closure
    const preflight = await withBreaker(
      'internetdb', env.KV, () => fetchInternetDB(resolvedIPQuery, env.KV),
    )
    internetdbPreflight = preflight
    if (preflight.status === 'ok' || preflight.status === 'cached') {
      const tags = (preflight.data?.tags ?? []).map(t => t.toLowerCase())
      isCDNIP = tags.some(t => CDN_TAGS.has(t))
      if (isCDNIP) {
        console.log(
          `[lookup] CDN IP detected for ${query.normalised} (${resolvedIPQuery.normalised}) — skipping IP-specific sources`,
        )
      }
    }
  }

  // ── Layers 1 + 2 run concurrently (each guarded by its circuit breaker) ──
  //
  // For domain queries, threat intel is run against BOTH the original domain
  // string AND the resolved IP in parallel, then the best result is selected.
  // A domain listed as malicious in URLhaus/ThreatFox must not get a clean
  // result just because we searched the resolved IP instead of the domain name.
  //
  // Exception: when isCDNIP is true, the IP-path threat intel is skipped —
  // searching a shared Cloudflare anycast IP in abuse.ch returns noise.
  const domainQuery = query.type === 'domain' ? query : null

  const [
    // Layer 1
    internetdbResult,
    geoResult,
    bgpResult,
    rdapResult,
    whoisResult,
    certsResult,
    passivednsResult,
    robtexResult,
    // Layer 2 — IP-based threat intel
    urlhausIPResult,
    threatfoxIPResult,
    malwarebazaarIPResult,
    feodoResult,
    sslblResult,
    // Layer 2 — domain-string threat intel (null slots for non-domain queries)
    urlhausDomainResult,
    threatfoxDomainResult,
    malwarebazaarDomainResult,
  ] = await Promise.allSettled([
    // InternetDB: use pre-flight result when available (CDN detection ran it already)
    internetdbPreflight !== null
      ? Promise.resolve(internetdbPreflight)
      : withBreaker('internetdb', env.KV, () => fetchInternetDB(effectiveIPQuery, env.KV)),

    // ip-api: skip for CDN IPs — geo of a shared anycast edge node is meaningless.
    isCDNIP
      ? Promise.resolve({ source: 'ipapi', status: 'skipped' as const, data: null })
      : withBreaker('ipapi', env.KV, () => fetchIPAPI(effectiveIPQuery, env.KV)),
    // BGPView: always run even for CDN IPs — knowing the CDN's ASN/prefix is
    // genuinely useful (confirms Cloudflare/Fastly/Akamai proxying).
    // For ASN queries, reuse the pre-flight result to avoid a duplicate fetch.
    bgpPreflightResult !== null
      ? Promise.resolve(bgpPreflightResult)
      : withBreaker('bgpview', env.KV, () => fetchBGPView(effectiveIPQuery, env.KV), `bgp:ip:${effectiveIPQuery.normalised}`),

    // Domain + IP sources: always run regardless of CDN status
    withBreaker('rdap',  env.KV, () => fetchRDAP(query, env.KV),  `rdap:domain:${query.normalised}`),
    withBreaker('whois', env.KV, () => fetchWhois(query, env.KV), `whois:${query.normalised}`),
    // crtsh: certspotter acts as a permanent fallback at every level:
    //   1. crt.sh returns empty → certspotter supplements inside fetchCRTSH
    //   2. crt.sh errors        → certspotter runs standalone (below)
    //   3. breaker open + stale cache hit → stale cache is served
    //   4. breaker open + cache COLD → certspotter runs standalone (cold-start gap fix)
    //
    // We deliberately do NOT use withBreaker here so we can intercept the
    // open+cold case and route to certspotter instead of returning skipped().
    (async (): Promise<SourceResult<CertRecord[]>> => {
      const breakerState = await getBreakerState('crtsh', env.KV)
      if (breakerState === 'open') {
        // Try stale cache first
        try {
          const raw = await env.KV.get(`crtsh:${query.normalised}`)
          if (raw) {
            return { source: 'crtsh', status: 'cached', data: JSON.parse(raw) as CertRecord[] }
          }
        } catch { /* fall through to certspotter */ }
        // Cache cold — run certspotter standalone; surface under 'crtsh' so
        // the UI card renders as normal (the user sees certs, not an error).
        // Record success/failure against the crtsh breaker so that a run of
        // successful certspotter fallbacks eventually clears the open state
        // and the breaker can recover before the 15-min KV TTL expires.
        console.warn('[lookup] crtsh breaker open + cache cold — running certspotter standalone')
        const spotterResult = await fetchCertSpotter(query, env.KV)
        if (spotterResult.status === 'error') {
          await recordBreakerFailure('crtsh', env.KV)
        } else if (spotterResult.status !== 'skipped') {
          await recordBreakerSuccess('crtsh', env.KV)
        }
        return { ...spotterResult, source: 'crtsh' }
      }

      // Breaker closed / half-open — normal path
      const crtResult = await fetchCRTSH(query, env.KV)
      if (crtResult.status === 'error') {
        await recordBreakerFailure('crtsh', env.KV)
        console.warn('[lookup] crtsh errored — trying certspotter standalone')
        return fetchCertSpotter(query, env.KV)
      }
      await recordBreakerSuccess('crtsh', env.KV)
      return crtResult
    })(),
    withBreaker('passivedns', env.KV, () => fetchPassiveDNS(query, env.KV, ipQuery), `passivedns:${query.normalised}`),

    // Robtex — skip for CDN IPs; also pass stale-cache key so open breaker still serves data
    isCDNIP
      ? Promise.resolve(skipped<ReturnType<typeof fetchRobtex> extends Promise<SourceResult<infer T>> ? T : never>('robtex'))
      : withBreaker('robtex', env.KV, () => fetchRobtex(effectiveIPQuery, env.KV), `robtex:${effectiveIPQuery.normalised}`),

    // Threat intel — IP path: skip for CDN IPs (shared anycast = noise)
    isCDNIP
      ? Promise.resolve({ source: 'urlhaus',       status: 'skipped' as const, data: null })
      : withBreaker('urlhaus',       env.KV, () => fetchURLhaus(effectiveIPQuery, env.KV, env.ABUSECH_KEY)),
    isCDNIP
      ? Promise.resolve({ source: 'threatfox',     status: 'skipped' as const, data: null })
      : withBreaker('threatfox',     env.KV, () => fetchThreatFox(effectiveIPQuery, env.KV, env.ABUSECH_KEY)),
    isCDNIP
      ? Promise.resolve({ source: 'malwarebazaar', status: 'skipped' as const, data: null })
      : withBreaker('malwarebazaar', env.KV, () => fetchMalwareBazaar(effectiveIPQuery, env.KV, env.ABUSECH_KEY)),

    // Feodo / SSLBL: D1 blocklists — skip for CDN IPs
    isCDNIP
      ? Promise.resolve({ source: 'feodo', status: 'skipped' as const, data: null })
      : withBreaker('feodo', env.KV, () => fetchFeodo(effectiveIPQuery, env.DB)),
    isCDNIP
      ? Promise.resolve({ source: 'sslbl', status: 'skipped' as const, data: null })
      : withBreaker('sslbl', env.KV, () => fetchSSLBL(effectiveIPQuery, env.DB)),

    // Threat intel — domain-string path (only for domain queries; always runs regardless of CDN)
    domainQuery
      ? withBreaker('urlhaus',       env.KV, () => fetchURLhaus(domainQuery, env.KV, env.ABUSECH_KEY))
      : Promise.resolve({ source: 'urlhaus',       status: 'skipped' as const, data: null }),
    domainQuery
      ? withBreaker('threatfox',     env.KV, () => fetchThreatFox(domainQuery, env.KV, env.ABUSECH_KEY))
      : Promise.resolve({ source: 'threatfox',     status: 'skipped' as const, data: null }),
    domainQuery
      ? withBreaker('malwarebazaar', env.KV, () => fetchMalwareBazaar(domainQuery, env.KV, env.ABUSECH_KEY))
      : Promise.resolve({ source: 'malwarebazaar', status: 'skipped' as const, data: null }),
  ])

  // ── Merge dual threat intel results — prefer the more alarming result ──────
  // If either the IP or domain query shows a hit, that result wins.
  // Tiebreak: prefer whichever has status 'ok' or 'cached' over 'error'/'skipped'.
  //
  // preferOk is ONLY called when no positive malicious signal was found on
  // either path — it is a tie-breaker for "which clean/empty result do we show".
  // When this function is reached, returning either result is equivalent for
  // risk purposes; we prefer the domain path (b) so that a CDN-blocked IP error
  // or 'skipped' status never shadows a valid domain-path clean result.
  function preferOk<T>(
    a: PromiseSettledResult<SourceResult<T>>,
    b: PromiseSettledResult<SourceResult<T>>,
  ): PromiseSettledResult<SourceResult<T>> {
    const aOk = a.status === 'fulfilled' && (a.value.status === 'ok' || a.value.status === 'cached')
    const bOk = b.status === 'fulfilled' && (b.value.status === 'ok' || b.value.status === 'cached')
    if (aOk && !bOk) return a
    if (bOk && !aOk) return b
    // Both ok, or both non-ok: prefer domain path (b). bUsable handles the
    // neither-ok case — if b is skipped/error, fall back to a.
    const bUsable = b.status === 'fulfilled' && b.value.status !== 'error'
    return bUsable ? b : a
  }

  function pickWorstURLhaus(
    a: PromiseSettledResult<SourceResult<URLhausResult>>,
    b: PromiseSettledResult<SourceResult<URLhausResult>>,
  ): PromiseSettledResult<SourceResult<URLhausResult>> {
    const dataA = a.status === 'fulfilled' ? (a.value.data as URLhausResult | null) : null
    const dataB = b.status === 'fulfilled' ? (b.value.data as URLhausResult | null) : null
    const aHit = dataA?.query_status === 'is_host'
    const bHit = dataB?.query_status === 'is_host'
    // Both paths show a hit — prefer whichever has more associated URLs so we
    // don't silently drop domain-path URL entries when the IP is also listed.
    // IP path (a) is the tiebreak when counts are equal.
    if (aHit && bHit) {
      return (dataB?.urls?.length ?? 0) > (dataA?.urls?.length ?? 0) ? b : a
    }
    if (aHit) return a
    if (bHit) return b
    // Neither is a positive hit — prefer whichever actually succeeded.
    return preferOk(a, b)
  }

  function pickWorstThreatFox(
    a: PromiseSettledResult<SourceResult<ThreatFoxResult>>,
    b: PromiseSettledResult<SourceResult<ThreatFoxResult>>,
  ): PromiseSettledResult<SourceResult<ThreatFoxResult>> {
    const dataA = a.status === 'fulfilled' ? (a.value.data as ThreatFoxResult | null) : null
    const dataB = b.status === 'fulfilled' ? (b.value.data as ThreatFoxResult | null) : null
    const countA = dataA?.data?.length ?? 0
    const countB = dataB?.data?.length ?? 0

    // Unequal counts — the higher count wins straightforwardly.
    if (countA !== countB) return countA > countB ? a : b

    // Equal non-zero counts — both paths may have *different* IOCs (e.g.
    // the domain is listed under one ID and its resolved IP under another).
    // Merge and deduplicate by IOC id so neither path's results are dropped.
    if (countA > 0 && a.status === 'fulfilled' && b.status === 'fulfilled' && dataA !== null) {
      const seen = new Set<string>()
      const mergedIOCs = [...(dataA.data ?? []), ...(dataB?.data ?? [])].filter(ioc => {
        if (seen.has(ioc.id)) return false
        seen.add(ioc.id)
        return true
      })
      return {
        status: 'fulfilled' as const,
        value: {
          source:     'threatfox',
          status:     a.value.status,
          data:       { ...dataA, data: mergedIOCs } as ThreatFoxResult,
          fetchedAt:  Date.now(),
        } satisfies SourceResult<ThreatFoxResult>,
      }
    }

    // Both have 0 IOCs — prefer whichever actually succeeded.
    return preferOk(a, b)
  }

  function pickWorstMB(
    a: PromiseSettledResult<SourceResult<MalwareBazaarResult>>,
    b: PromiseSettledResult<SourceResult<MalwareBazaarResult>>,
  ): PromiseSettledResult<SourceResult<MalwareBazaarResult>> {
    const dataA = a.status === 'fulfilled' ? (a.value.data as MalwareBazaarResult | null) : null
    const dataB = b.status === 'fulfilled' ? (b.value.data as MalwareBazaarResult | null) : null
    const aHit = dataA?.query_status === 'ok'
    const bHit = dataB?.query_status === 'ok'
    // Both paths show hits — prefer whichever has more sample entries so we
    // don't silently drop domain-path results when both paths return data.
    // IP path (a) is the tiebreak when counts are equal.
    if (aHit && bHit) {
      return (dataB?.data?.length ?? 0) > (dataA?.data?.length ?? 0) ? b : a
    }
    if (aHit) return a
    if (bHit) return b
    // Neither is a positive hit — prefer whichever actually succeeded.
    return preferOk(a, b)
  }

  const urlhausResult       = pickWorstURLhaus(urlhausIPResult as PromiseSettledResult<SourceResult<URLhausResult>>,       urlhausDomainResult as PromiseSettledResult<SourceResult<URLhausResult>>)
  const threatfoxResult     = pickWorstThreatFox(threatfoxIPResult as PromiseSettledResult<SourceResult<ThreatFoxResult>>,   threatfoxDomainResult as PromiseSettledResult<SourceResult<ThreatFoxResult>>)
  const malwarebazaarResult = pickWorstMB(malwarebazaarIPResult as PromiseSettledResult<SourceResult<MalwareBazaarResult>>, malwarebazaarDomainResult as PromiseSettledResult<SourceResult<MalwareBazaarResult>>)

  // ── Layer 3: CVE enrichment — batched 5-at-a-time ────────────────────────
  const idbData = unwrap<InternetDBResult>(internetdbResult)
  const cveIds = (idbData?.vulns ?? []).slice(0, CVE_CONFIG.MAX_PER_LOOKUP)

  const vulns = await fetchCVEsBatched(
    cveIds, env.KV, env.NVD_KEY, query.forceRefresh ?? false, inflight,
  ) as PromiseSettledResult<SourceResult<CVEDetail>>[]

  // ── Layer 4: Bucket recon + Wayback — domain queries only ────────────────
  // Skip entirely for IP/ASN queries to avoid two no-op promise slots
  const [bucketsResult, waybackResult] = query.type === 'domain'
    ? await Promise.allSettled([
        withBreaker('ghw',     env.KV, () => fetchGHWForQuery(query, env.KV, ghwRing)),
        withBreaker('wayback', env.KV, () => fetchWayback(query, env.KV)),
      ])
    : [
        { status: 'fulfilled' as const, value: skipped<BucketResult[]>('ghw') },
        { status: 'fulfilled' as const, value: skipped<WaybackResult[]>('wayback') },
      ]

  // ── Collect breaker statuses for meta (non-blocking, best-effort) ─────────
  const circuitBreakers = await getAllBreakerStatuses([...ALL_SOURCES], env.KV)

  // ── Merge & return ────────────────────────────────────────────────────────
  const result = mergeResults({
    query,
    // Pass the DoH-resolved IP explicitly so merge always shows it even
    // when geo/ipapi was skipped (CDN path). Also signals DNS failure.
    resolvedIP:           ipQuery?.normalised ?? null,
    dnsResolutionFailed:  query.type === 'domain' && ipQuery === null,
    asnIPDerivationFailed: query.type === 'asn' && asnSyntheticIPQuery === null,
    core: {
      internetdb: internetdbResult,
      geo:        geoResult,
      bgp:        bgpResult,
      rdap:       rdapResult,
      whois:      whoisResult,
      certs:      certsResult,
      passivedns: passivednsResult,
      robtex:     robtexResult,
    },
    threat: {
      urlhaus:       urlhausResult,
      threatfox:     threatfoxResult,
      malwarebazaar: malwarebazaarResult,
      feodo:         feodoResult,
      sslbl:         sslblResult,
    },
    vulns,
    recon: {
      buckets: bucketsResult,
      wayback: waybackResult,
    },
    durationMs:      Date.now() - start,
    circuitBreakers,
  })

  // Non-blocking D1 write
  ctx.waitUntil(persistSearch(query, result, env.DB))

  return result
}
