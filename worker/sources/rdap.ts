/**
 * RDAP — registration data for IPs and domains.
 *
 * Uses IANA bootstrap to route to the correct RDAP registry per IP block /
 * domain TLD. Bootstrap responses are themselves cached for 24 hours.
 *
 * IP:     ARIN → RIPE → APNIC → LACNIC → AFRINIC fallback chain
 * Domain: TLD-specific registry via IANA dns.json bootstrap
 * Auth:   none | Limits: unlimited | TTL: 24 hours
 */
import type { LookupQuery, RDAPContact, RDAPResult, SourceResult } from '../../lib/types'
import { cacheGet, cachePut, CacheKey, TTL } from '../../lib/cache'
import { ok, error, skipped, safeJson } from '../../lib/results'
import { safeFetch } from '../../lib/ssrf'

const SOURCE = 'rdap'

// ─── Bootstrap ───────────────────────────────────────────────────────────────

interface BootstrapEntry {
  services: [string[], string[]][]
}

async function getRDAPBaseForDomain(
  tld: string,
  db: D1Database,
): Promise<string | null> {
  let boot = await cacheGet<BootstrapEntry>(db, CacheKey.rdapBootDNS())
  if (!boot) {
    try {
      const res = await safeFetch('https://data.iana.org/rdap/dns.json', {
        signal: AbortSignal.timeout(8000),
      })
      if (!res.ok) return null
      boot = await safeJson<BootstrapEntry>(
        res,
        (v): v is BootstrapEntry =>
          typeof v === 'object' && v !== null && Array.isArray((v as BootstrapEntry).services),
        'rdap-dns-bootstrap',
      )
      await cachePut(db, CacheKey.rdapBootDNS(), boot, TTL.RDAP)
    } catch (err) {
      console.error('[rdap] getRDAPBaseForDomain bootstrap fetch failed:', err)
      return null
    }
  }
  for (const [tlds, urls] of boot.services) {
    if (tlds.includes(tld) && urls[0]) return urls[0]
  }
  return null
}

async function getRDAPBaseForIP(
  ip: string,
  db: D1Database,
): Promise<string> {
  // Choose bootstrap file based on address family
  const isIPv6 = ip.includes(':')
  const bootstrapUrl = isIPv6
    ? 'https://data.iana.org/rdap/ipv6.json'
    : 'https://data.iana.org/rdap/ipv4.json'
  const cacheKey = isIPv6 ? `${CacheKey.rdapBootIP()}:v6` : CacheKey.rdapBootIP()
  const defaultBase = isIPv6
    ? 'https://rdap.db.ripe.net/'          // RIPE is the most common IPv6 RIR
    : 'https://rdap.arin.net/registry/'

  let boot = await cacheGet<BootstrapEntry>(db, cacheKey)
  if (!boot) {
    try {
      const res = await safeFetch(bootstrapUrl, {
        signal: AbortSignal.timeout(8000),
      })
      if (res.ok) {
        boot = await safeJson<BootstrapEntry>(
          res,
          (v): v is BootstrapEntry =>
            typeof v === 'object' && v !== null && Array.isArray((v as BootstrapEntry).services),
          'rdap-ip-bootstrap',
        )
        await cachePut(db, cacheKey, boot, TTL.RDAP)
      }
    } catch (err) {
      console.error('[rdap] getRDAPBaseForIP bootstrap fetch failed:', err)
      // Fall through to default
    }
  }

  // Convert a dotted-decimal IP to a 32-bit unsigned integer
  function ipToInt(addr: string): number {
    return addr.split('.').reduce((acc, o) => ((acc << 8) | parseInt(o, 10)) >>> 0, 0) >>> 0
  }

  // Parse a CIDR like "1.2.3.0/24" and check if the given ipInt falls within it
  function cidrContains(cidr: string, ipInt: number): boolean {
    const [network, bitsStr] = cidr.split('/')
    if (!network || !bitsStr) return false
    const bits = parseInt(bitsStr, 10)
    if (isNaN(bits) || bits < 0 || bits > 32) return false
    const mask = bits === 0 ? 0 : (~((1 << (32 - bits)) - 1)) >>> 0
    const netInt = ipToInt(network)
    return (ipInt & mask) === (netInt & mask)
  }

  if (boot) {
    const ipInt = ipToInt(ip)
    for (const [ranges, urls] of boot.services) {
      for (const cidr of ranges) {
        if (cidrContains(cidr, ipInt) && urls[0]) return urls[0]
      }
    }
  }
  return defaultBase
}

// ─── Normalisers ─────────────────────────────────────────────────────────────

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function parseContacts(entities: any[]): RDAPContact[] {
  if (!Array.isArray(entities)) return []
  return entities.map(e => {
    const vcard = e.vcardArray?.[1] ?? []
    const email = vcard.find((v: string[]) => v[0] === 'email')?.[3] as string | undefined
    const org   = vcard.find((v: string[]) => v[0] === 'org')?.[3] as string | undefined
    return {
      role: (e.roles?.[0] ?? 'unknown') as string,
      ...(email !== undefined && { email }),
      ...(org !== undefined && { org }),
    }
  })
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function normaliseIP(json: any): RDAPResult {
  const cidrBlock = json.cidr0_cidrs?.[0]
  // cidr0_cidrs entries use v4prefix for IPv4 and v6prefix for IPv6
  const cidrPrefix = cidrBlock?.v4prefix ?? cidrBlock?.v6prefix
  return {
    ip:          json.startAddress,
    ...(cidrBlock && cidrPrefix !== undefined && { cidr: `${cidrPrefix}/${cidrBlock.length}` }),
    ...(json.name && { networkName: json.name }),
    ...(json.country && { country: json.country }),
    contacts:    parseContacts(json.entities ?? []),
    ...(json.status && { status: json.status }),
  }
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function normaliseDomain(json: any): RDAPResult {
  const events: { eventAction: string; eventDate: string }[] = json.events ?? []
  const getEvent = (action: string) =>
    events.find(e => e.eventAction === action)?.eventDate

  const registrar = json.entities?.find((e: { roles: string[] }) =>
    e.roles?.includes('registrar'))?.vcardArray?.[1]
    ?.find((v: string[]) => v[0] === 'fn')?.[3] as string | undefined

  const created = getEvent('registration')
  const expires = getEvent('expiration')
  const updated = getEvent('last changed')

  return {
    domain: json.ldhName ?? json.unicodeName,
    ...(registrar !== undefined && { registrar }),
    ...(created !== undefined && { created }),
    ...(expires !== undefined && { expires }),
    ...(updated !== undefined && { updated }),
    nameservers: (json.nameservers ?? []).map(
                   (ns: { ldhName: string }) => ns.ldhName),
    status:      json.status,
    contacts:    parseContacts(json.entities ?? []),
  }
}

// ─── Main fetch ──────────────────────────────────────────────────────────────

export async function fetchRDAP(
  query: LookupQuery,
  db: D1Database,
): Promise<SourceResult<RDAPResult>> {
  if (query.type === 'asn') return skipped(SOURCE)

  const cacheKey = query.type === 'ip'
    ? CacheKey.rdapIP(query.normalised)
    : CacheKey.rdapDomain(query.normalised)

  const cached = await cacheGet<RDAPResult>(db, cacheKey, query.forceRefresh)
  if (cached) return ok(SOURCE, cached, true)

  try {
    let url: string

    if (query.type === 'ip') {
      const base = await getRDAPBaseForIP(query.normalised, db)
      url = `${base}ip/${query.normalised}`
    } else {
      const tld = query.normalised.split('.').pop() ?? ''
      const base = await getRDAPBaseForDomain(tld, db)
        ?? 'https://rdap.verisign.com/com/v1/'
      url = `${base}domain/${query.normalised}`
    }

    const res = await safeFetch(url, { 
      signal: AbortSignal.timeout(8000) 
    }, { 
      allowRdapDynamic: true 
    })

    if (!res.ok) {
      console.error(`[${SOURCE}] HTTP ${res.status} for ${query.normalised}`)
      return error(SOURCE, `HTTP ${res.status}`)
    }

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const json = await safeJson<any>(
      res,
      (v): v is Record<string, unknown> => typeof v === 'object' && v !== null,
      SOURCE,
    )
    const data = query.type === 'ip' ? normaliseIP(json) : normaliseDomain(json)

    await cachePut(db, cacheKey, data, TTL.RDAP)
    return ok(SOURCE, data)
  } catch (err) {
    console.error(`[${SOURCE}] fetch failed for ${query.normalised}`, err)
    return error(SOURCE, String(err))
  }
}
