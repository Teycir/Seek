/**
 * Results page — SSR, calls runLookup() directly (no self-fetch).
 * Each layer is a collapsible card. Failed/skipped sources render
 * a subtle "unavailable" placeholder, never a broken layout.
 *
 * Next 15+: params is a Promise — must be awaited.
 */
import { notFound } from 'next/navigation'
import { getCloudflareContext } from '@opennextjs/cloudflare'
import { parseQuery } from '../../../lib/validate'
import { runLookup } from '../../../worker/lookup'
import type { Env, HostResult, SourceResult } from '../../../lib/types'
import { ExportButton } from '../../components/ExportButton'
import { CopyButton } from '../../components/CopyButton'
import { ShareButton } from '../../components/ShareButton'
import { SaveButton } from '../../components/SaveButton'
import { VulnsStream } from '../../components/VulnsStream'
import { RiskBadge } from '../../components/RiskBadge'
import { RefreshButton } from '../../components/RefreshButton'
import { getTargetByQuery } from '../../../lib/targets'
import { diffHostResults } from '../../../lib/diff'
import type { TargetDiff } from '../../../lib/diff'
import type { Metadata } from 'next'

// ─── Dynamic metadata ─────────────────────────────────────────────────────────

export async function generateMetadata({
  params,
}: {
  params: Promise<{ query: string }>
}): Promise<Metadata> {
  const { query } = await params
  const decoded = decodeURIComponent(query)
  const url = `https://seekyou.workers.dev/host/${query}`
  const description =
    `OSINT intelligence report for ${decoded} — geolocation, open ports, CVEs, ` +
    `threat feeds, certificate transparency, passive DNS, and BGP routing.`
  return {
    title: decoded,
    description,
    alternates: { canonical: url },
    openGraph: {
      title: `${decoded} — SeekYou`,
      description,
      url,
      type: 'article',
    },
    twitter: {
      card: 'summary',
      title: `${decoded} — SeekYou`,
      description,
    },
    // Result pages are live data — don't let search engines cache stale snapshots
    robots: { index: false, follow: false },
  }
}

// ─── Data fetching ────────────────────────────────────────────────────────────

type FetchError =
  | { kind: 'rate-limited'; resetInSeconds: number }
  | { kind: 'server-busy'; retryAfterSeconds: number }
  | { kind: 'kv-limit' }
  | { kind: 'invalid' }
  | { kind: 'internal' }

type FetchOutcome = { ok: true; result: HostResult } | { ok: false; error: FetchError }

async function fetchResult(rawQuery: string, forceRefresh = false): Promise<FetchOutcome> {
  try {
    const query = parseQuery(rawQuery)
    if (!query) return { ok: false, error: { kind: 'invalid' } }
    // Use async mode — sync mode throws when the context isn't yet set on the
    // global scope, which happens when Next.js renders this as a dynamic route
    // before the Worker request context has been injected.
    const { env, ctx } = await getCloudflareContext({ async: true })
    const result = await runLookup({ ...query, forceRefresh }, env as unknown as Env, ctx)
    return { ok: true, result }
  } catch (err: unknown) {
    // runLookup is an internal call and doesn't throw HTTP errors — but
    // preserve the shape so the page can show a generic fallback.
    console.error('[fetchResult] runLookup failed:', err)
    const msg = err instanceof Error ? err.message : String(err)
    if (msg.includes('KV put() limit exceeded')) {
      return { ok: false, error: { kind: 'kv-limit' } }
    }
    return { ok: false, error: { kind: 'internal' } }
  }
}

// ─── UI primitives ────────────────────────────────────────────────────────────

function Badge({
  label,
  variant = 'default',
}: {
  label: string
  variant?: 'default' | 'danger' | 'warn' | 'ok' | 'muted'
}) {
  const styles: Record<string, string> = {
    default: 'bg-neutral-800 text-neutral-300',
    danger:  'bg-red-900/60 text-red-300',
    warn:    'bg-amber-900/60 text-amber-300',
    ok:      'bg-green-900/60 text-green-300',
    muted:   'bg-neutral-800/40 text-neutral-500',
  }
  return (
    <span className={`inline-block rounded px-2 py-0.5 text-xs font-medium ${styles[variant]}`}>
      {label}
    </span>
  )
}

function SourceUnavailable({ source }: { source: string }) {
  return <p className="text-xs text-neutral-600 italic">{source} unavailable</p>
}

function Card({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <details
      className="rounded-xl border border-neutral-800 bg-neutral-900 overflow-hidden"
      open
    >
      <summary className="cursor-pointer select-none px-5 py-4 text-sm font-semibold
                          text-neutral-200 hover:text-white list-none flex items-center
                          justify-between">
        {title}
        <svg className="chevron w-4 h-4 text-neutral-600 shrink-0" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="2">
          <polyline points="4,6 8,10 12,6" />
        </svg>
      </summary>
      <div className="border-t border-neutral-800 px-5 py-4 text-sm text-neutral-300">
        {children}
      </div>
    </details>
  )
}

/** Copyable monospace value — renders value + copy button inline */
function Mono({ value }: { value: string }) {
  return (
    <span className="inline-flex items-center gap-1">
      <span className="font-mono">{value}</span>
      <CopyButton value={value} />
    </span>
  )
}

function sourceOk<T>(r: SourceResult<T>): r is SourceResult<T> & { data: T } {
  return (r.status === 'ok' || r.status === 'cached') && r.data !== null
}

/** Days until an ISO date (negative = already past) */
function daysUntil(isoDate: string): number {
  return Math.floor((new Date(isoDate).getTime() - Date.now()) / 86_400_000)
}

// ─── Changes banner ───────────────────────────────────────────────────────────

function ChangesSection({
  diff,
  checkedAt,
}: {
  diff: TargetDiff
  checkedAt: number | null
}) {
  if (!diff.hasChanges) return null

  const since = checkedAt
    ? new Date(checkedAt * 1000).toISOString().slice(0, 10)
    : 'last scan'

  const FEED_LABEL: Record<string, string> = {
    urlhaus: 'URLhaus', threatfox: 'ThreatFox',
    feodo: 'Feodo', sslbl: 'SSLBL',
  }

  return (
    <div className="rounded-xl border border-amber-700/40 bg-amber-950/15 px-5 py-4 space-y-3">
      <p className="text-xs font-semibold text-amber-400 uppercase tracking-widest">
        ⚡ Changes since {since}
      </p>

      <div className="space-y-1.5 text-xs font-mono">

        {diff.risk && Math.abs(diff.risk.delta) >= 5 && (
          <div className={`flex items-center gap-2 ${diff.risk.delta > 0 ? 'text-red-400' : 'text-green-400'}`}>
            <span>{diff.risk.delta > 0 ? '▲' : '▼'} Risk score</span>
            <span className="text-neutral-500">{diff.risk.prev} → {diff.risk.next}</span>
          </div>
        )}

        {diff.ports.map((p, i) => (
          <div key={i} className={`flex items-center gap-2 ${p.direction === 'opened' ? 'text-red-400' : 'text-green-400'}`}>
            <span>{p.direction === 'opened' ? '↑' : '↓'} Port {p.port}</span>
            <span className="text-neutral-600">{p.direction}</span>
          </div>
        ))}

        {diff.cves.map((c, i) => (
          <div key={i} className={`flex items-center gap-2 ${c.direction === 'appeared' ? 'text-red-400' : 'text-green-400'}`}>
            <span>{c.direction === 'appeared' ? '+' : '−'} {c.id}</span>
            {c.severity && <span className="text-neutral-500">{c.severity}{c.score !== undefined ? ` ${c.score}` : ''}</span>}
          </div>
        ))}

        {diff.threats.map((t, i) => (
          <div key={i} className={`flex items-center gap-2 ${t.direction === 'appeared' ? 'text-red-400' : 'text-green-400'}`}>
            <span>{t.direction === 'appeared' ? '+' : '−'} {FEED_LABEL[t.feed] ?? t.feed}</span>
            {t.detail && <span className="text-neutral-500">{t.detail}</span>}
          </div>
        ))}

        {diff.geo.map((g, i) => (
          <div key={i} className="flex items-center gap-2 text-amber-400">
            <span>~ {g.field}</span>
            <span className="text-neutral-500">{g.prev} → {g.next}</span>
          </div>
        ))}

        {diff.certExpiry.map((c, i) => (
          <div key={i} className={`flex items-center gap-2 ${c.daysLeft <= 0 ? 'text-red-400' : 'text-amber-400'}`}>
            <span>{c.daysLeft <= 0 ? '✕ Cert expired' : '! Cert expiring'}</span>
            <span className="text-neutral-500">{c.commonName}</span>
            <span>{c.daysLeft <= 0 ? `(${Math.abs(c.daysLeft)}d ago)` : `(${c.daysLeft}d)`}</span>
          </div>
        ))}

      </div>
    </div>
  )
}

// ─── Section renderers ────────────────────────────────────────────────────────

function OverviewSection({ result }: { result: HostResult }) {
  const geo = result.core.geo
  const idb = result.core.internetdb
  const bgp = result.core.bgp
  const isCDN = sourceOk(idb) && idb.data.tags.some(t =>
    ['cdn', 'cloud', 'proxy'].includes(t.toLowerCase()),
  )

  return (
    <Card title="Overview">
      {result.dnsResolutionFailed && (
        <p className="mb-3 text-xs text-amber-500 font-mono">
          DNS resolution failed — IP-based sources unavailable. Domain-only sources (RDAP, certificates, passive DNS) still ran.
        </p>
      )}
      <dl className="grid grid-cols-2 gap-x-8 gap-y-3 sm:grid-cols-3">
        {result.resolvedIP && (
          <div>
            <dt className="text-xs text-neutral-500 uppercase tracking-wide mb-0.5">
              {result.query.type === 'domain' ? 'Resolved IP' : 'IP'}
            </dt>
            <dd className="inline-flex items-center gap-1.5">
              <Mono value={result.resolvedIP} />
              {isCDN && <Badge label="CDN" variant="warn" />}
            </dd>
          </div>
        )}
        {result.resolvedDomain && (
          <div>
            <dt className="text-xs text-neutral-500 uppercase tracking-wide mb-0.5">Domain</dt>
            <dd><Mono value={result.resolvedDomain} /></dd>
          </div>
        )}
        {sourceOk(geo) && (
          <>
            <div>
              <dt className="text-xs text-neutral-500 uppercase tracking-wide mb-0.5">Location</dt>
              <dd className="inline-flex items-center gap-1">
                {geo.data.city}, {geo.data.country}
                <CopyButton value={`${geo.data.city}, ${geo.data.country}`} label="Copy location" />
              </dd>
            </div>
            <div>
              <dt className="text-xs text-neutral-500 uppercase tracking-wide mb-0.5">ISP / Org</dt>
              <dd className="inline-flex items-center gap-1">
                <span>{geo.data.org}</span>
                <CopyButton value={geo.data.org} label="Copy org" />
              </dd>
            </div>
            <div>
              <dt className="text-xs text-neutral-500 uppercase tracking-wide mb-0.5">Timezone</dt>
              <dd>{geo.data.timezone}</dd>
            </div>
            <div className="flex gap-1 flex-wrap pt-1">
              {geo.data.proxy   && <Badge label="Proxy"   variant="warn" />}
              {geo.data.hosting && <Badge label="Hosting" variant="warn" />}
              {geo.data.mobile  && <Badge label="Mobile"  />}
            </div>
          </>
        )}
        {sourceOk(bgp) && (
          <div>
            <dt className="text-xs text-neutral-500 uppercase tracking-wide mb-0.5">ASN</dt>
            <dd><Mono value={`AS${bgp.data.asn}`} /> <span className="text-neutral-500 text-xs">— {bgp.data.name}</span></dd>
          </div>
        )}
        {sourceOk(idb) && idb.data.tags.length > 0 && (
          <div className="col-span-full flex gap-1 flex-wrap">
            {idb.data.tags.map(t => <Badge key={t} label={t} />)}
          </div>
        )}
      </dl>
    </Card>
  )
}

function PortsSection({ result }: { result: HostResult }) {
  const idb = result.core.internetdb
  if (!sourceOk(idb) || idb.data.ports.length === 0) return null
  return (
    <Card title={`Open ports (${idb.data.ports.length})`}>
      <div className="flex flex-wrap gap-2">
        {idb.data.ports.map(p => (
          <span key={p} className="inline-flex items-center gap-0.5 font-mono rounded
                                   bg-neutral-800 px-2 py-1 text-xs">
            {p}
            <CopyButton value={String(p)} label={`Copy port ${p}`} />
          </span>
        ))}
      </div>
      {idb.data.cpes.length > 0 && (
        <div className="mt-4 space-y-1.5">
          <p className="text-xs text-neutral-500 uppercase tracking-wide">CPEs</p>
          {idb.data.cpes.map(c => (
            <div key={c} className="inline-flex items-center gap-1">
              <span className="font-mono text-xs text-neutral-400">{c}</span>
              <CopyButton value={c} label="Copy CPE" />
            </div>
          ))}
        </div>
      )}
    </Card>
  )
}

function CertsSection({ result }: { result: HostResult }) {
  const certs = result.core.certs
  if (!sourceOk(certs)) return <Card title="Certificates"><SourceUnavailable source="crt.sh" /></Card>
  return (
    <Card title={`Certificates (${certs.data.length})`}>
      <div className="space-y-2 max-h-80 overflow-y-auto">
        {certs.data.slice(0, 50).map(c => {
          const days = daysUntil(c.notAfter)
          const expiryClass =
            days < 0   ? 'text-red-400' :
            days <= 30 ? 'text-amber-400' :
                         'text-neutral-600'
          return (
            <div key={c.id} className="flex items-center justify-between text-xs
                                       border-b border-neutral-800 pb-1 gap-2">
              <div className="flex items-center gap-1 min-w-0">
                <span className="font-mono text-neutral-200 truncate">{c.commonName}</span>
                <CopyButton value={c.commonName} label="Copy domain" />
              </div>
              <span className={`shrink-0 font-mono ${expiryClass}`}>
                {days < 0 ? `expired ${Math.abs(days)}d ago` : `expires ${c.notAfter.slice(0, 10)}`}
              </span>
            </div>
          )
        })}
      </div>
    </Card>
  )
}

function DNSSection({ result }: { result: HostResult }) {
  const pdns = result.core.passivedns
  if (!sourceOk(pdns) || pdns.data.length === 0) return null
  return (
    <Card title={`DNS history (${pdns.data.length} records)`}>
      <div className="overflow-x-auto">
        <table className="w-full text-xs text-neutral-400">
          <thead>
            <tr className="text-neutral-500 uppercase text-left">
              <th className="pb-2 pr-4">Name</th>
              <th className="pb-2 pr-4">Type</th>
              <th className="pb-2 pr-4">Value</th>
              <th className="pb-2">Last seen</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-neutral-800">
            {pdns.data.slice(0, 30).map((r, i) => (
              <tr key={i}>
                <td className="py-1 pr-4">
                  <span className="inline-flex items-center gap-1 font-mono">
                    {r.rrname}<CopyButton value={r.rrname} />
                  </span>
                </td>
                <td className="py-1 pr-4">{r.rrtype}</td>
                <td className="py-1 pr-4">
                  <span className="inline-flex items-center gap-1 font-mono">
                    {r.rdata}<CopyButton value={r.rdata} />
                  </span>
                </td>
                <td className="py-1">{new Date(r.time_last * 1000).toISOString().slice(0, 10)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  )
}

function ThreatSection({ result }: { result: HostResult }) {
  const indicators = result.normalizedThreats
  const hasThreats = indicators.length > 0

  // Clean target — omit the card entirely so the page stays tight.
  // The card only appears when there are actual threat indicators to show.
  if (!hasThreats) return null

  const feedLabel: Record<string, string> = {
    urlhaus:       'URLhaus',
    threatfox:     'ThreatFox',
    feodo:         'Feodo',
    sslbl:         'SSLBL',
    malwarebazaar: 'MalwareBazaar',
  }

  const confidenceVariant = (c: number): 'danger' | 'warn' | 'ok' | 'muted' => {
    if (c >= 85) return 'danger'
    if (c >= 65) return 'warn'
    if (c >= 40) return 'ok'
    return 'muted'
  }

  return (
    <Card title={`Threat intelligence ⚠ (${indicators.length})`}>
      <div className="space-y-3">
        {indicators.map((ind, i) => (
            <div
              key={i}
              className="rounded-lg border border-neutral-800 bg-neutral-950 px-4 py-3 space-y-2"
            >
              {/* IOC + confidence */}
              <div className="flex items-start justify-between gap-3">
                <div className="flex items-center gap-1 min-w-0">
                  <span className="font-mono text-sm text-neutral-100 break-all">{ind.ioc}</span>
                  <CopyButton value={ind.ioc} label="Copy IOC" />
                </div>
                <Badge label={`${ind.confidence}%`} variant={confidenceVariant(ind.confidence)} />
              </div>

              {/* Type + threat */}
              <div className="flex flex-wrap gap-2 text-xs text-neutral-400">
                <span className="uppercase tracking-wide text-neutral-600">{ind.iocType}</span>
                <span className="text-neutral-700">·</span>
                <span>{ind.threatType.replace(/_/g, ' ')}</span>
                {ind.malwareFamilies.length > 0 && (
                  <>
                    <span className="text-neutral-700">·</span>
                    <span className="text-amber-400">{ind.malwareFamilies.join(', ')}</span>
                  </>
                )}
              </div>

              {/* Provenance badges */}
              <div className="flex flex-wrap gap-1">
                {ind.provenance.map(feed => (
                  <span
                    key={feed}
                    className="rounded bg-neutral-800 px-2 py-0.5 text-xs text-neutral-400
                               font-mono"
                  >
                    {feedLabel[feed] ?? feed}
                  </span>
                ))}
              </div>

              {/* Tags */}
              {ind.tags.length > 0 && (
                <div className="flex flex-wrap gap-1">
                  {ind.tags.map(t => (
                    <span key={t} className="rounded bg-neutral-800/60 px-2 py-0.5 text-xs
                                             text-neutral-500">
                      {t}
                    </span>
                  ))}
                </div>
              )}

              {/* Timestamps */}
              {(ind.firstSeen || ind.lastSeen) && (
                <p className="text-xs text-neutral-600 font-mono">
                  {ind.firstSeen && <>first {ind.firstSeen.slice(0, 10)}</>}
                  {ind.firstSeen && ind.lastSeen && ' → '}
                  {ind.lastSeen && <>last {ind.lastSeen.slice(0, 10)}</>}
                </p>
              )}

              {/* Reference links */}
              {Object.entries(ind.references).map(([feed, url]) => (
                <a
                  key={feed}
                  href={url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-block text-xs text-neutral-600 hover:text-neon-red
                             font-mono transition-colors mr-3"
                >
                  {feedLabel[feed] ?? feed} ↗
                </a>
              ))}
            </div>
          ))}
        </div>
    </Card>
  )
}

function SubdomainsSection({ result }: { result: HostResult }) {
  const certs = result.core.certs
  if (!sourceOk(certs) || certs.data.length === 0) return null

  // Only meaningful for domain queries
  const baseDomain =
    result.query.type === 'domain' ? result.query.normalised : result.resolvedDomain
  if (!baseDomain) return null

  // Extract unique subdomains from cert CNs and SANs (nameValue may be \n-separated)
  const seen = new Set<string>()
  for (const cert of certs.data) {
    const names = [
      cert.commonName,
      ...cert.nameValue.split('\n'),
    ]
    for (const raw of names) {
      const name = raw.trim().toLowerCase()
      // Must be a proper subdomain of the base, no wildcards
      if (
        name &&
        name !== baseDomain &&
        name.endsWith(`.${baseDomain}`) &&
        !name.includes('*')
      ) {
        seen.add(name)
      }
    }
  }

  if (seen.size === 0) return null
  const sorted = [...seen].sort()

  return (
    <Card title={`Subdomains (${sorted.length} discovered)`}>
      <div className="columns-2 sm:columns-3 gap-x-6 max-h-72 overflow-y-auto">
        {sorted.map(sub => (
          <div key={sub} className="flex items-center gap-1 break-inside-avoid py-0.5">
            <a
              href={`/host/${encodeURIComponent(sub)}`}
              className="font-mono text-xs text-neutral-300 hover:text-white truncate
                         transition-colors"
            >
              {sub.replace(`.${baseDomain}`, '')}
              <span className="text-neutral-600">.{baseDomain}</span>
            </a>
            <CopyButton value={sub} label="Copy subdomain" />
          </div>
        ))}
      </div>
      {certs.data.length >= 50 && (
        <p className="mt-3 text-xs text-neutral-600 italic">
          Showing subdomains from the first 50 certificates — there may be more.
        </p>
      )}
    </Card>
  )
}

function BucketsSection({ result }: { result: HostResult }) {
  const buckets = result.recon.buckets
  if (buckets.status === 'skipped' || !sourceOk(buckets) || buckets.data.length === 0) return null
  return (
    <Card title={`Exposed buckets (${buckets.data.length})`}>
      <div className="space-y-2">
        {buckets.data.map(b => (
          <div key={b.bucket} className="flex items-center justify-between text-xs">
            <span className="inline-flex items-center gap-1 font-mono text-neutral-200">
              {b.bucket}
              <CopyButton value={b.bucket} label="Copy bucket name" />
            </span>
            <div className="flex items-center gap-2">
              <Badge label={b.provider.toUpperCase()} />
              <a
                href={b.url}
                target="_blank"
                rel="noopener noreferrer"
                className="text-neutral-500 hover:text-white font-mono transition-colors"
              >
                ↗
              </a>
              <span className="text-neutral-500">{b.fileCount} files</span>
            </div>
          </div>
        ))}
      </div>
    </Card>
  )
}

function WaybackSection({ result }: { result: HostResult }) {
  const wb = result.recon.wayback
  if (wb.status === 'skipped' || !sourceOk(wb) || wb.data.length === 0) return null
  return (
    <Card title={`Web archive (${wb.data.length} snapshots)`}>
      <div className="space-y-1 max-h-60 overflow-y-auto">
        {wb.data.slice(0, 20).map((s, i) => (
          <div key={i} className="flex justify-between text-xs font-mono gap-2">
            <a
              href={`https://web.archive.org/web/${s.timestamp}/${s.url}`}
              target="_blank"
              rel="noopener noreferrer"
              className="text-neutral-400 hover:text-neon-red truncate max-w-xs transition-colors"
            >
              {s.url}
            </a>
            <span className="text-neutral-600 shrink-0">{s.timestamp.slice(0, 8)}</span>
          </div>
        ))}
      </div>
    </Card>
  )
}

function WhoisSection({ result }: { result: HostResult }) {
  const whois = result.core.whois
  if (whois.status === 'skipped') return null
  if (!sourceOk(whois)) return null
  const d = whois.data

  // Collect contact emails, deduped
  const emails = [...new Set([
    d.registrantEmail,
    d.adminEmail,
    d.techEmail,
    d.abuseEmail,
  ].filter(Boolean) as string[])]

  // Only render if WHOIS adds something beyond what RDAP already shows —
  // i.e. contact info, registrant name/org, or DNSSEC. Otherwise skip silently.
  const hasExtraData = d.registrant || d.registrantOrg || emails.length > 0 || d.dnssec || d.rawText
  if (!hasExtraData) return null

  return (
    <Card title="WHOIS">
      <dl className="grid grid-cols-2 gap-x-8 gap-y-3 sm:grid-cols-3">
        {d.registrant && (
          <div>
            <dt className="text-xs text-neutral-500 uppercase tracking-wide mb-0.5">Registrant</dt>
            <dd className="inline-flex items-center gap-1 text-sm">
              {d.registrant}
              <CopyButton value={d.registrant} />
            </dd>
          </div>
        )}
        {d.registrantOrg && (
          <div>
            <dt className="text-xs text-neutral-500 uppercase tracking-wide mb-0.5">Organisation</dt>
            <dd className="inline-flex items-center gap-1 text-sm">
              {d.registrantOrg}
              <CopyButton value={d.registrantOrg} />
            </dd>
          </div>
        )}
        {d.registrar && (
          <div>
            <dt className="text-xs text-neutral-500 uppercase tracking-wide mb-0.5">Registrar</dt>
            <dd className="inline-flex items-center gap-1 text-sm">
              {d.registrar}
              {d.registrarUrl ? (
                <a href={d.registrarUrl} target="_blank" rel="noopener noreferrer"
                   className="text-neutral-500 hover:text-white text-xs font-mono ml-1">↗</a>
              ) : null}
            </dd>
          </div>
        )}
        {d.dnssec && (
          <div>
            <dt className="text-xs text-neutral-500 uppercase tracking-wide mb-0.5">DNSSEC</dt>
            <dd>
              <Badge
                label={d.dnssec}
                variant={d.dnssec.toLowerCase().includes('signed') ? 'ok' : 'muted'}
              />
            </dd>
          </div>
        )}
        {emails.length > 0 && (
          <div className="col-span-full">
            <dt className="text-xs text-neutral-500 uppercase tracking-wide mb-1">Contact emails</dt>
            <dd className="flex flex-wrap gap-2">
              {emails.map(email => (
                <span key={email} className="inline-flex items-center gap-0.5 font-mono text-xs
                                             bg-neutral-800 rounded px-2 py-0.5">
                  {email}
                  <CopyButton value={email} />
                </span>
              ))}
            </dd>
          </div>
        )}
        {d.status && d.status.length > 0 && (
          <div className="col-span-full flex gap-1 flex-wrap">
            {d.status.map(s => (
              <Badge key={s} label={s.replace(/ /g, '\u00a0')} variant="muted" />
            ))}
          </div>
        )}
      </dl>
      {d.rawText && (
        <details className="mt-4">
          <summary className="cursor-pointer text-xs text-neutral-500 hover:text-neutral-300 select-none">
            Raw WHOIS text
          </summary>
          <pre className="mt-2 max-h-60 overflow-y-auto rounded bg-neutral-950 px-3 py-2
                          text-xs text-neutral-400 font-mono whitespace-pre-wrap break-all">
            {d.rawText}
          </pre>
        </details>
      )}
    </Card>
  )
}

function RegistrationSection({ result }: { result: HostResult }) {
  const rdap = result.core.rdap
  if (!sourceOk(rdap)) return null
  const d = rdap.data

  const isExpired = d.expires && new Date(d.expires) < new Date()
  const isExpiringSoon = d.expires && !isExpired &&
    (new Date(d.expires).getTime() - Date.now()) < 30 * 24 * 60 * 60 * 1000

  return (
    <Card title="Registration (RDAP)">
      <dl className="grid grid-cols-2 gap-x-8 gap-y-3 sm:grid-cols-3">
        {d.registrar && (
          <div>
            <dt className="text-xs text-neutral-500 uppercase tracking-wide mb-0.5">Registrar</dt>
            <dd className="inline-flex items-center gap-1 text-sm">
              {d.registrar}
              <CopyButton value={d.registrar} />
            </dd>
          </div>
        )}
        {d.created && (
          <div>
            <dt className="text-xs text-neutral-500 uppercase tracking-wide mb-0.5">Created</dt>
            <dd className="font-mono text-sm">{d.created.slice(0, 10)}</dd>
          </div>
        )}
        {d.expires && (
          <div>
            <dt className="text-xs text-neutral-500 uppercase tracking-wide mb-0.5">Expires</dt>
            <dd className="inline-flex items-center gap-2 font-mono text-sm">
              {d.expires.slice(0, 10)}
              {isExpired     && <Badge label="Expired"       variant="danger" />}
              {isExpiringSoon && <Badge label="Expiring soon" variant="warn"   />}
            </dd>
          </div>
        )}
        {d.updated && (
          <div>
            <dt className="text-xs text-neutral-500 uppercase tracking-wide mb-0.5">Updated</dt>
            <dd className="font-mono text-sm">{d.updated.slice(0, 10)}</dd>
          </div>
        )}
        {d.nameservers && d.nameservers.length > 0 && (
          <div className="col-span-full">
            <dt className="text-xs text-neutral-500 uppercase tracking-wide mb-1">Nameservers</dt>
            <dd className="flex flex-wrap gap-2">
              {d.nameservers.map(ns => (
                <span key={ns} className="inline-flex items-center gap-0.5 font-mono text-xs
                                          bg-neutral-800 rounded px-2 py-0.5">
                  {ns.toLowerCase()}
                  <CopyButton value={ns.toLowerCase()} />
                </span>
              ))}
            </dd>
          </div>
        )}
        {d.status && d.status.length > 0 && (
          <div className="col-span-full flex gap-1 flex-wrap">
            {d.status.map(s => (
              <Badge key={s} label={s.replace(/ /g, '\u00a0')} variant="muted" />
            ))}
          </div>
        )}
      </dl>
    </Card>
  )
}

function MetaBar({ result }: { result: HostResult }) {
  const { meta } = result
  return (
    <p className="text-xs text-neutral-600 text-right font-mono">
      {meta.sourcesQueried} sources · {meta.cacheHits} cached ·{' '}
      <span className={meta.sourcesFailed > 0 ? 'text-amber-500' : ''}>
        {meta.sourcesFailed} failed
      </span>
      {' '}· {meta.durationMs}ms
    </p>
  )
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export default async function HostPage({
  params,
  searchParams,
}: {
  params: Promise<{ query: string }>
  searchParams: Promise<{ refresh?: string; ts?: string }>
}) {
  const [{ query: rawQuery }, sp] = await Promise.all([params, searchParams])
  const forceRefresh = sp.refresh === '1'
  const tsToken      = sp.ts ?? undefined
  const outcome = await fetchResult(decodeURIComponent(rawQuery), forceRefresh)

  // ── Diff against saved snapshot (non-fatal) ─────────────────────────────────
  let diff:      TargetDiff | null = null
  let checkedAt: number | null     = null

  if (outcome.ok) {
    try {
      const { env } = await getCloudflareContext({ async: true })
      const saved = await getTargetByQuery(
        (env as unknown as Env).DB,
        outcome.result.query.normalised,
      )
      if (saved?.result_json) {
        const prev = JSON.parse(saved.result_json) as HostResult
        diff      = diffHostResults(prev, outcome.result)
        checkedAt = saved.checked_at
      }
    } catch (err) {
      // non-fatal — page renders fine without diff
      console.warn('[HostPage] diff fetch failed (non-fatal):', err)
    }
  }

  // ── Error screens ───────────────────────────────────────────────────────────
  if (!outcome.ok) {
    const { error } = outcome

    if (error.kind === 'invalid') notFound()

    if (error.kind === 'server-busy') {
      return (
        <main className="flex min-h-screen flex-col items-center justify-center bg-neutral-950 px-4">
          <div className="max-w-md w-full rounded-xl border border-amber-800/40 bg-amber-950/20 p-8 text-center space-y-4">
            <div className="text-3xl">⏳</div>
            <h1 className="text-lg font-semibold text-amber-300 font-mono">Server busy</h1>
            <p className="text-sm text-neutral-400">
              Too many lookups are running simultaneously right now.
              This protects the {15} upstream sources from being overwhelmed.
            </p>
            <p className="text-sm text-amber-400/80 font-mono">
              Retry in ~{error.retryAfterSeconds}s
            </p>
            <a
              href={`/host/${encodeURIComponent(rawQuery)}`}
              className="inline-block mt-2 rounded-lg border border-amber-700/50 px-5 py-2
                         text-sm font-mono text-amber-300 hover:bg-amber-900/30 transition-colors"
            >
              Try again
            </a>
            <div className="pt-2">
              <a href="/" className="text-xs text-neutral-600 hover:text-neutral-400 transition-colors">
                ← back to search
              </a>
            </div>
          </div>
        </main>
      )
    }

    if (error.kind === 'rate-limited') {
      const resetMins = Math.ceil(error.resetInSeconds / 60)
      return (
        <main className="flex min-h-screen flex-col items-center justify-center bg-neutral-950 px-4">
          <div className="max-w-md w-full rounded-xl border border-neon-red/30 bg-red-950/20 p-8 text-center space-y-4">
            <div className="text-3xl">🚦</div>
            <h1 className="text-lg font-semibold text-neon-red font-mono">Rate limit reached</h1>
            <p className="text-sm text-neutral-400">
              You&apos;ve used all 500 lookups for this hour.
              Your quota resets in approximately <span className="text-white font-mono">{resetMins} minute{resetMins !== 1 ? 's' : ''}</span>.
            </p>
            <p className="text-xs text-neutral-600 font-mono">
              window resets in {error.resetInSeconds}s
            </p>
            <div className="pt-2">
              <a href="/" className="text-xs text-neutral-600 hover:text-neutral-400 transition-colors">
                ← back to search
              </a>
            </div>
          </div>
        </main>
      )
    }

    // kv write limit — transient, resets at midnight UTC
    if (error.kind === 'kv-limit') {
      return (
        <main className="flex min-h-screen flex-col items-center justify-center bg-neutral-950 px-4">
          <div className="max-w-md w-full rounded-xl border border-amber-800/40 bg-amber-950/20 p-8 text-center space-y-4">
            <div className="text-3xl">⏳</div>
            <h1 className="text-lg font-semibold text-amber-300 font-mono">Daily limit reached</h1>
            <p className="text-sm text-neutral-400">
              The service has hit its Cloudflare KV write quota for today. This resets automatically at midnight UTC.
            </p>
            <p className="text-sm text-neutral-400">
              IP lookups still work — if you know the IP address of{' '}
              <span className="font-mono text-neutral-200">{decodeURIComponent(rawQuery)}</span>,
              you can look it up directly instead.
            </p>
            <div className="pt-2">
              <a href="/" className="text-xs text-neutral-600 hover:text-neutral-400 transition-colors">
                ← back to search
              </a>
            </div>
          </div>
        </main>
      )
    }

    // internal error — generic fallback (don't 404, it might be transient)
    return (
      <main className="flex min-h-screen flex-col items-center justify-center bg-neutral-950 px-4">
        <div className="max-w-md w-full rounded-xl border border-neutral-800 bg-neutral-900 p-8 text-center space-y-4">
          <div className="text-3xl">⚡</div>
          <h1 className="text-lg font-semibold text-neutral-200 font-mono">Lookup failed</h1>
          <p className="text-sm text-neutral-400">
            An unexpected error occurred. This is usually transient — retry in a moment.
          </p>
          <a
            href={`/host/${encodeURIComponent(rawQuery)}`}
            className="inline-block mt-2 rounded-lg border border-neutral-700 px-5 py-2
                       text-sm font-mono text-neutral-300 hover:bg-neutral-800 transition-colors"
          >
            Retry
          </a>
          <div className="pt-2">
            <a href="/" className="text-xs text-neutral-600 hover:text-neutral-400 transition-colors">
              ← back to search
            </a>
          </div>
        </div>
      </main>
    )
  }

  const { result } = outcome

  return (
    <main className="min-h-screen bg-neutral-950 px-4 pt-14 pb-10 sm:pt-10">
      <div className="mx-auto max-w-3xl space-y-4">

        {/* Header */}
        <div className="flex items-start justify-between gap-4">
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <h1 className="font-mono text-xl font-semibold text-white truncate">
                {result.query.normalised}
              </h1>
              <CopyButton value={result.query.normalised} label="Copy query" className="text-sm" />
            </div>
            <div className="flex items-center gap-3 mt-1">
              <p className="text-xs text-neutral-500 uppercase tracking-wide">{result.query.type}</p>
              <RiskBadge risk={result.riskScore} />
            </div>
          </div>
          <div className="flex items-center gap-3 shrink-0 flex-wrap justify-end">
            <SaveButton query={result.query.normalised} />
            <ShareButton query={result.query.normalised} />
            <ExportButton
              resultJson={JSON.stringify(result, null, 2)}
              filename={`seekyou-${result.query.normalised}.json`}
            />
            <RefreshButton query={result.query.normalised} />
            <a href="/" className="text-sm text-neutral-500 hover:text-white transition-colors">
              ← back
            </a>
          </div>
        </div>

        {diff && <ChangesSection diff={diff} checkedAt={checkedAt} />}

        <OverviewSection result={result} />
        <RegistrationSection result={result} />
        <WhoisSection result={result} />
        <PortsSection result={result} />
        {/* VulnsStream fetches CVE details client-side so NVD latency doesn't
            block the initial paint — geo/ports/threats all SSR above this. */}
        <VulnsStream
          cveIds={result.core.internetdb.data?.vulns ?? []}
          query={result.query.normalised}
          refresh={forceRefresh}
          {...(tsToken != null && { tsToken })}
        />
        <ThreatSection result={result} />
        <CertsSection result={result} />
        <SubdomainsSection result={result} />
        <DNSSection result={result} />
        <BucketsSection result={result} />
        <WaybackSection result={result} />
        <MetaBar result={result} />
      </div>
    </main>
  )
}
