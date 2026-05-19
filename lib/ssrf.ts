/**
 * lib/ssrf.ts — SSRF (Server-Side Request Forgery) hardening.
 *
 * Provides safeFetch() — a drop-in replacement for fetch() used by every
 * outbound source call.  Before dispatching the request it:
 *
 *   1. Parses and normalises the URL (rejects non-HTTP/HTTPS schemes).
 *   2. Checks the hostname against ALLOWED_HOSTS — an explicit allowlist of
 *      every external service this application is permitted to call.
 *      Anything not on this list is rejected, regardless of what the URL
 *      contains.
 *   3. Checks the literal hostname string against BLOCKED_HOST_PATTERNS —
 *      a secondary guard for metadata / link-local / loopback endpoints that
 *      could appear via hostname injection (e.g. 169.254.169.254).
 *   4. Follows redirects manually (up to MAX_REDIRECTS hops), re-running
 *      the full validation on each Location header — prevents open-redirect
 *      chains that land on internal endpoints.
 *   5. Applies a default timeout (DEFAULT_TIMEOUT_MS) when the caller does
 *      not supply a signal, so no fetch can hang indefinitely.
 *
 * Why an allowlist rather than just a blocklist?
 * ─────────────────────────────────────────────
 * Blocklists are inherently incomplete — new RFC-6890 special ranges,
 * IPv6 link-local, AWS instance-metadata v2, GCP metadata, and future
 * cloud provider endpoints can all be bypassed if we only enumerate what
 * is forbidden.  The allowlist inverts the problem: unknown destinations
 * are denied by default, which is the only safe default for an OSINT
 * worker that fans out to 15 upstream APIs.
 *
 * DNS rebinding
 * ─────────────
 * validateSSRFResolved(ip) lets the lookup layer validate a DoH-resolved IP
 * against BLOCKED_HOST_PATTERNS before using it for further requests.  This
 * closes the DNS rebinding window where a DNS answer returns a private IP
 * after the hostname allowlist check already passed.
 *
 * Cloudflare Workers note
 * ───────────────────────
 * Workers already sandbox outbound network access, but that sandbox is
 * bypassed by any Worker that injects a URL under attacker control.
 * This module is defence-in-depth for exactly that attack surface.
 */

// ─── Redirect / timeout constants ────────────────────────────────────────────

/** Maximum number of HTTP redirects safeFetch will follow before aborting. */
const MAX_REDIRECTS = 3

/**
 * Default fetch timeout when the caller does not supply an AbortSignal.
 * Individual source fetchers may pass a shorter signal via RequestInit;
 * when they do, that signal wins (it is passed directly to fetch()).
 */
const DEFAULT_TIMEOUT_MS = 10_000

// ─── Allowed outbound hosts ───────────────────────────────────────────────────

/**
 * Exact hostname allowlist.  Every external service this application calls
 * must be listed here.  Sub-paths are not relevant — only the hostname is
 * checked.  Wildcards are intentionally not supported: if an API uses a
 * regional subdomain (e.g. rdap registries), add each concrete hostname.
 *
 * Keeping the list readable is a design goal — if you need to add an API
 * key you should also add its hostname here, in the same PR.
 */
export const ALLOWED_HOSTS = new Set<string>([
  // Shodan InternetDB
  'internetdb.shodan.io',

  // ipinfo.io — geo / ASN (replaces ip-api.com which blocks CF Workers)
  'ipinfo.io',

  // RIPE stat — BGP / ASN data (replaces BGPView which shut down)
  'stat.ripe.net',

  // HackerTarget — passive DNS (replaces CIRCL which now requires auth)
  'api.hackertarget.com',

  // BGPView (kept for any cached calls, domain is dead but harmless)
  // 'api.bgpview.io',  — removed, NXDOMAIN

  // RDAP bootstrap + RIR registries
  'data.iana.org',
  'rdap.arin.net',
  'rdap.db.ripe.net',
  'rdap.apnic.net',
  'rdap.lacnic.net',
  'rdap.afrinic.net',
  'rdap.verisign.com',        // .com / .net default fallback
  'rdap.identitydigital.services',
  // NB: IANA bootstrap may return other RDAP registry hostnames at runtime.
  // See DYNAMIC_RDAP_ALLOWED below for the mechanism that covers those.

  // crt.sh
  'crt.sh',

  // SSLMate CertSpotter — CT log fallback for when crt.sh is unavailable
  'api.certspotter.com',

  // whoisjson.com — domain WHOIS JSON (free, no auth)
  'whoisjson.com',

  // Robtex
  'freeapi.robtex.com',

  // abuse.ch (URLhaus, ThreatFox, MalwareBazaar)
  'urlhaus-api.abuse.ch',
  'threatfox-api.abuse.ch',
  'mb-api.abuse.ch',

  // abuse.ch blocklist downloads (Feodo + SSLBL, fetched by cron)
  'feodotracker.abuse.ch',
  'sslbl.abuse.ch',

  // NVD (NIST)
  'services.nvd.nist.gov',

  // CIRCL CVE Search
  'cve.circl.lu',

  // OSV.dev
  'api.osv.dev',

  // GrayHatWarfare
  'buckets.grayhatwarfare.com',

  // Wayback / Internet Archive CDX
  'web.archive.org',

  // Cloudflare DoH (used for domain → IP resolution)
  'cloudflare-dns.com',

  'challenges.cloudflare.com',
])

/**
 * RDAP registry hostnames discovered at runtime via the IANA bootstrap are
 * validated against this suffix allowlist.  Every legitimate RIR / ccTLD
 * RDAP endpoint ends with one of these TLD-ish suffixes.
 *
 * This prevents a poisoned IANA bootstrap cache from redirecting RDAP calls
 * to an attacker-controlled host.
 */
const DYNAMIC_RDAP_ALLOWED_SUFFIXES = [
  '.arin.net',
  '.ripe.net',
  '.apnic.net',
  '.lacnic.net',
  '.afrinic.net',
  '.verisign.com',
  '.identitydigital.services',
  '.registro.br',
  '.nic.fr',
  '.denic.de',
  '.dns.be',
  '.nic.uk',
  '.nominet.org.uk',
  '.registry.in',
  '.centralnic.com',
  '.donuts.co',
  '.afilias.info',
  '.afilias-srs.net',
  '.rdap.org',           // fallback aggregator used by some TLDs
]

// ─── Blocked host patterns ────────────────────────────────────────────────────

/**
 * Secondary guard — hostname substrings / prefixes that must never be
 * called regardless of allowlist state.  These cover:
 *   - Loopback:           localhost, 127.x.x.x
 *   - RFC-1918 private:   10.x, 172.16–31.x, 192.168.x
 *   - Link-local:         169.254.x (AWS/GCP/Azure metadata)
 *   - IPv6 special:       ::1, fc00::/7, fe80::/10
 *   - AWS metadata:       169.254.169.254, fd00:ec2::254
 *   - GCP metadata:       metadata.google.internal
 *   - Azure metadata:     169.254.169.254 (same IP, already covered)
 *   - Kubernetes svc:     kubernetes.default.svc
 *
 * Matching is case-insensitive and tests the full hostname string.
 * The same set is reused by validateSSRFResolved() for post-DNS checks.
 */
const BLOCKED_HOST_PATTERNS: ReadonlyArray<RegExp> = [
  /^localhost$/i,
  /^127\.\d+\.\d+\.\d+$/,
  /^10\.\d+\.\d+\.\d+$/,
  /^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+$/,
  /^192\.168\.\d+\.\d+$/,
  /^169\.254\.\d+\.\d+$/,
  /^::1$/,
  /^(fc|fd)[0-9a-fA-F]{2}:/,     // ULA IPv6
  /^fe80:/i,                       // link-local IPv6
  /^0\.0\.0\.0$/,
  /metadata\.google\.internal$/i,
  /kubernetes\.default\.svc/i,
  /\.internal$/i,                  // any .internal TLD
  /\.local$/i,                     // mDNS .local
]

// ─── SSRF error ───────────────────────────────────────────────────────────────

export class SSRFError extends Error {
  constructor(
    public readonly url: string,
    public readonly reason: string,
  ) {
    super(`SSRF blocked: ${reason} — ${url}`)
    this.name = 'SSRFError'
  }
}

// ─── SSRF checks ──────────────────────────────────────────────────────────────

/**
 * Validate a URL against the SSRF allowlist and blocked-host patterns.
 * Throws SSRFError on any violation; returns the parsed URL on success.
 *
 * Call this before every outbound fetch.  safeFetch() calls it automatically,
 * including on every redirect Location header.
 */
export function validateSSRF(rawUrl: string, allowRdapDynamic = false, options?: { allowArbitraryHost?: boolean }): URL {
  let parsed: URL
  try {
    parsed = new URL(rawUrl)
  } catch (err) {
    throw new SSRFError(rawUrl, `unparseable URL: ${err}`)
  }

  // 1. Scheme must be https or http (http is permitted for APIs that don't
  //    support TLS, e.g. Robtex free endpoint).  Everything else is banned.
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    throw new SSRFError(rawUrl, `disallowed scheme "${parsed.protocol}"`)
  }

  const host = parsed.hostname.toLowerCase()

  // 2. Blocked-host check — catches loopback, private ranges, metadata IPs.
  for (const pattern of BLOCKED_HOST_PATTERNS) {
    if (pattern.test(host)) {
      throw new SSRFError(rawUrl, `blocked host pattern "${host}"`)
    }
  }

  // 3. Allowlist check.
  if (ALLOWED_HOSTS.has(host)) return parsed

  // 4. Dynamic RDAP allowlist — covers IANA-bootstrapped registry hostnames.
  //    allowRdapDynamic must be explicitly opted in; it is never the default.
  if (allowRdapDynamic) {
    const ok = DYNAMIC_RDAP_ALLOWED_SUFFIXES.some(s => host.endsWith(s))
    if (ok) return parsed
    throw new SSRFError(rawUrl, `RDAP host "${host}" not in dynamic suffix allowlist`)
  }

  // 5. Operator-controlled egress (e.g. WEBHOOK_URL) — allowlist is bypassed
  //    but BLOCKED_HOST_PATTERNS are still enforced so private/metadata
  //    endpoints can never be reached.  Only set allowArbitraryHost=true for
  //    URLs that come from operator-controlled config (env vars), never from
  //    user-supplied input.
  if (options?.allowArbitraryHost) return parsed

  throw new SSRFError(rawUrl, `host "${host}" not in allowlist`)
}

/**
 * DNS rebinding guard — validate a raw IP string (not a URL) returned by a
 * DNS resolution step against BLOCKED_HOST_PATTERNS.
 *
 * Call this immediately after resolving a domain to an IP, before using that
 * IP in any further request.  Throws SSRFError if the resolved address falls
 * in a private/link-local/loopback range.
 */
export function validateSSRFResolved(ip: string): void {
  const normalized = ip.trim().toLowerCase()
  for (const pattern of BLOCKED_HOST_PATTERNS) {
    if (pattern.test(normalized)) {
      throw new SSRFError(ip, `resolved IP "${normalized}" matches blocked host pattern (DNS rebinding guard)`)
    }
  }
}

// ─── safeFetch ────────────────────────────────────────────────────────────────

/**
 * Drop-in fetch() replacement with SSRF validation baked in.
 *
 * Hardening over a raw fetch():
 *   • SSRF allowlist + blocked-host check on the initial URL.
 *   • Redirect interception: redirects are followed manually (up to
 *     MAX_REDIRECTS hops), with full SSRF re-validation on each Location
 *     header.  This prevents open-redirect chains that terminate on an
 *     internal endpoint.
 *   • Default timeout: if the caller does not supply an AbortSignal, a
 *     DEFAULT_TIMEOUT_MS signal is injected so no request can hang forever.
 *
 * Usage:
 *   import { safeFetch } from '../../lib/ssrf'
 *   const res = await safeFetch('https://internetdb.shodan.io/1.2.3.4', { signal })
 *
 * Options:
 *   allowRdapDynamic  — set true in rdap.ts for bootstrap-resolved hostnames
 *
 * Throws SSRFError (extends Error) before any network I/O when the URL is
 * rejected.  Callers should let this propagate so the source returns error()
 * and the circuit breaker records a failure.  Do NOT silently catch it —
 * an SSRFError is a security event and must appear in logs.
 */
export async function safeFetch(
  url: string,
  init?: RequestInit,
  options?: { allowRdapDynamic?: boolean; allowArbitraryHost?: boolean },
): Promise<Response> {
  const allowRdapDynamic = options?.allowRdapDynamic ?? false

  // Validate the initial URL — throws SSRFError on any violation.
  validateSSRF(url, allowRdapDynamic, options)

  // Inject a default timeout when the caller has not provided one.
  const signal: AbortSignal =
    (init?.signal as AbortSignal | null | undefined) ??
    AbortSignal.timeout(DEFAULT_TIMEOUT_MS)

  // Disable automatic redirect following so we can inspect each Location.
  let currentUrl = url
  let hopsLeft   = MAX_REDIRECTS

  while (true) {
    const res = await fetch(currentUrl, {
      ...init,
      signal,
      redirect: 'manual',
    })

    // Not a redirect — return the response directly.
    if (res.status < 300 || res.status >= 400) return res

    // Redirect: validate the Location before following it.
    const location = res.headers.get('location')
    if (!location) {
      throw new SSRFError(currentUrl, `redirect (${res.status}) with no Location header`)
    }

    // Resolve relative redirects against the current URL.
    const nextUrl = new URL(location, currentUrl).toString()

    if (hopsLeft <= 0) {
      throw new SSRFError(nextUrl, `too many redirects (limit ${MAX_REDIRECTS})`)
    }

    // Full SSRF re-validation on the redirect target.
    validateSSRF(nextUrl, allowRdapDynamic, options)

    currentUrl = nextUrl
    hopsLeft--
  }
}
