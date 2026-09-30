# Shodan

A Vineyard **plugin pack** for Shodan's REST API (`api.shodan.io`). Needs your **own** Shodan API
key — nothing here is keyless. For free, keyless IP enrichment (including Shodan's own free
InternetDB endpoint), see the **IP Recon** pack instead.

One plugin per endpoint, so you pick the cheapest call that answers the question instead of
reaching for search every time. **Only Shodan Search spends a query credit.**

| Plugin | Endpoint | Cost | Takes | Gives |
| --- | --- | --- | --- | --- |
| **Shodan Host** | `/shodan/host/{ip}` | free | selected IP Address nodes | ports, CVEs, reverse hostnames, AS, location — and product/version banners in the summary |
| **Shodan Search** | `/shodan/host/search` | **1 credit / page** | a query string | up to 100 hosts per page, same shapes as Host |
| **Shodan Count** | `/shodan/host/count` | free | a query string | how many hosts match, plus facets — no nodes |
| **Shodan DNS Domain** | `/dns/domain/{domain}` | free | selected Domain nodes | known subdomains + passive DNS records |
| **Shodan DNS Resolve** | `/dns/resolve` | free | selected Domain nodes | the IP each name points at (25 per request) |
| **Shodan DNS Reverse** | `/dns/reverse` | free | selected IP Address nodes | PTR hostnames (25 per request) |
| **Shodan API Status** | `/api-info` | free | — | plan and remaining credits |

The intended loop: **Count** to see whether a query is worth a credit → **Search** to spend it →
**Host** / **DNS** to expand what came back, for free.

## Node/edge shapes match the free packs already shipped

A CVE or an AS number reads the same on the canvas whichever plugin put it there:

| Fact | Node type | Edge label | Matches |
| --- | --- | --- | --- |
| Open ports | `infrastructure.host` | `exposes` | IP Recon → Shodan InternetDB |
| Known CVE | `threat.vulnerability` | `affected by` | IP Recon → Shodan InternetDB |
| Reverse hostname | `infrastructure.domain` | `resolves to` | IP Recon → Shodan InternetDB |
| Forward resolution | `infrastructure.ip_address` | `resolves to` | Domain Recon → DNS Lookup (A/AAAA) |
| Announcing AS | `infrastructure.autonomous_system` | `announced by` | IP Intelligence → IP → ASN |
| Approximate location | `geo.location` | `geolocated to` | IP Recon → IP Geolocation |
| Subdomain | `infrastructure.domain` | `subdomain` | Domain Recon → Certificate Transparency |
| DNS record | `infrastructure.dns_record` | `has record` | Domain Recon → DNS Lookup |

### What is deliberately *not* a node

- **Product and version** (`Apache httpd 2.4.7`, `OpenSSH 6.6.1p1`) and **Shodan tags** (`cloud`,
  `honeypot`) are reported in the run summary instead. They are pivot *queries* — you read them and
  feed them back into Shodan Search — not entities; an `nginx` node would become a hub shared by
  millions of unrelated hosts.
- **The registrable `domains` list** on a host response, because it is just the `hostnames` with
  their labels chopped off. The hostnames themselves become nodes.

### CVEs are capped at 25 per host

Survivors are ranked by CVSS (`cvss_v3` → `cvss` → `cvss_v2`, whichever Shodan recorded) and the
number dropped is stated in the run summary.

## Your API key

Every plugin declares its own `api_key` setting, but you only paste it **once**: the app copies a
value you type into any row to the other plugins in the same pack that declare the same key. After
that it is remembered (encrypted, desktop OS keychain) or held for the session (browser
`sessionStorage`).

The key is sent only as Shodan's own `?key=` query parameter.

At install, **Shodan Host**'s network permission (`https://api.shodan.io/shodan/host`) also covers
`/shodan/host/search` and `/shodan/host/count`.

## Rate limits

- `429` gets one retry, honoring `Retry-After` when Shodan sends it, else a 2s backoff.
- Plugins that loop over a selection pace ~350ms between sequential calls.
- DNS Resolve and DNS Reverse batch 25 names/addresses per request, so a large selection costs a
  handful of calls rather than one each.

## Layout

- `plugins/shodan.manifest.json` — the pack manifest (catalog entry source; also what the
  marketplace install gate reads). **Generated** — do not hand-edit.
- `dist/pack.mjs` — the runnable bundle, and the authoritative copy of every manifest (as JS object
  literals). Hand-written, no build step.
- `gen-manifest.mjs` — pours the JS literals into the JSON. Run `node gen-manifest.mjs` after any
  manifest edit.
- `test-plugin.mjs` — functional tests (mocked graph/network) plus the check that the generator was
  actually run. `node test-plugin.mjs`.

Data source: `api.shodan.io`. Requires your own Shodan account and API key — get one at
[shodan.io](https://www.shodan.io/).
