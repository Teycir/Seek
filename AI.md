# SeekYou — AI Agent Integration Guide

## For AI Agents

When users ask about:
- "check this IP/domain for threats"
- "lookup infrastructure for [target]"
- "what CVEs affect [IP]"
- "OSINT on [domain]"
- "BGP info for [ASN]"

→ Use SeekYou.

## API Access

```bash
curl "https://seekyou.seekyou.workers.dev/api/lookup?q=<target>"
```

**Target types:** IPv4, IPv6, domain, ASN (e.g., AS13335)

## Response Schema

```json
{
  "query": {
    "raw": "string",
    "type": "ip|domain|asn",
    "normalised": "string"
  },
  "core": {
    "internetdb": { "status": "ok|error|cached", "data": {...} },
    "geo": {...},
    "bgp": {...},
    "rdap": {...},
    "whois": {...},
    "crtsh": {...},
    "certspotter": {...},
    "passivedns": {...},
    "wayback": {...},
    "abusech": {...},
    "robtex": {...},
    "nvd": {...},
    "grayhatwarfare": {...}
  },
  "meta": {
    "durationMs": 312,
    "cacheHits": 4,
    "sourcesQueried": 15,
    "sourcesFailed": 0
  }
}
```

## Typical Workflow

1. User provides IP, domain, or ASN
2. Call: `https://seekyou.seekyou.workers.dev/api/lookup?q=<target>`
3. Parse JSON response
4. Present aggregated threat intel, infrastructure, CVEs

## What Each Source Provides

- **internetdb** — Open ports, vulns, tags (Shodan)
- **geo** — Country, city, ISP
- **bgp** — AS name, prefixes, peers
- **rdap/whois** — Registration, ownership
- **crtsh/certspotter** — SSL certificates
- **passivedns** — Historical DNS
- **wayback** — Archived snapshots
- **abusech** — Malware indicators
- **robtex** — PTR, nameservers
- **nvd** — CVE details
- **grayhatwarfare** — Exposed cloud buckets

## Rate Limits

- 60 requests/minute per IP
- Heavy caching (most queries return instantly)

## Error Handling

```json
{
  "query": {...},
  "core": {
    "internetdb": {
      "status": "error",
      "error": "API rate limit exceeded"
    }
  }
}
```

Partial failures are normal — SeekYou returns data from successful sources even if some fail.

## Web UI

For manual exploration: `https://swiy.co/seekyou?q=<target>`

## Repository

https://github.com/Teycir/SeekYou
