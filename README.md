# Shodan

A Vineyard **plugin pack** for Shodan's paid REST API (`api.shodan.io`). Needs your **own** Shodan
API key — nothing here is keyless. For free, keyless IP enrichment (including Shodan's own free
InternetDB endpoint), see the **IP Recon** pack instead.

Three plugins:

- **Shodan Search** — runs a free-text host-search query (`org:"Example Corp"`,
  `hostname:example.com`, `product:nginx port:443`, …) and materializes up to 100 matching hosts:
  an **IP Address** node per host, with its exposing **Host** (`exposes`), announcing
  **Autonomous System** (`announced by`), approximate **Location** (`geolocated to`), known
  **Vulnerability** nodes (`affected by`) and reverse **Domain** nodes (`resolves to`). Ignores the
  canvas selection and runs once per invocation — costs exactly **1 query credit** per run,
  regardless of how much it selects or creates.
- **Shodan DNS** — reads a selected **Domain**'s passively-observed DNS history: known subdomains
  become **Domain** nodes (`subdomain`), and the underlying records (A/AAAA/MX/NS/TXT/CAA/…) become
  **DNS Record** nodes (`has record`). This is Shodan's own cache, not a live query — it can show
  records a live DNS-over-HTTPS lookup no longer sees, and miss ones that changed since Shodan's
  last crawl. **Free** — does not spend a query credit.
- **Shodan API Status** — checks the configured key's plan and remaining query/scan credits. Run
  this before a search you are not sure you can afford. **Free**, touches nothing on the canvas.

## Node/edge shapes match the free packs already shipped

Rather than invent a parallel model for the same facts, this pack reuses the exact node types and
edge labels the free packs already established, so a CVE or an AS number reads the same on the
canvas whichever plugin put it there:

| Fact                  | Node type                            | Edge label      | Matches                                            |
| ---------------------- | ------------------------------------- | ---------------- | --------------------------------------------------- |
| Open ports              | `infrastructure.host`                 | `exposes`         | IP Recon → Shodan InternetDB                        |
| Known CVE                | `threat.vulnerability`                | `affected by`     | IP Recon → Shodan InternetDB                        |
| Reverse hostname          | `infrastructure.domain`               | `resolves to`     | IP Recon → Shodan InternetDB                        |
| Announcing AS             | `infrastructure.autonomous_system`    | `announced by`    | IP Intelligence → IP → ASN                           |
| Approximate location       | `geo.location`                        | `geolocated to`   | IP Recon → IP Geolocation                            |
| Subdomain                 | `infrastructure.domain`               | `subdomain`       | Domain Recon → Certificate Transparency               |
| DNS record                | `infrastructure.dns_record`           | `has record`      | Domain Recon → DNS Lookup (per-record-type plugins)    |

## Your API key

Each of the three plugins declares its own `api_key` setting (Settings ➜ paste your
`api.shodan.io` key), because Vineyard's config store is keyed per **plugin**, not per pack — there
is no cross-plugin sharing to lean on. Paste it once per row; after that it is remembered
(encrypted, desktop OS keychain) or held for the session (browser `sessionStorage`). The key is
sent only as Shodan's own `?key=` query parameter — Shodan's REST API has no header-auth option —
and never leaves this pack's own declared endpoints.

## Rate limits and cost

- `/shodan/host/search` costs **1 query credit** per call. This pack calls it exactly once per run.
- `/dns/domain/{domain}` and `/api-info` are **free** and do not spend a credit (measured against a
  live `dev`-plan key).
- A `429` gets one retry (honoring `Retry-After` when Shodan sends it, else a 2s backoff); the DNS
  plugin also paces ~350ms between sequential domain lookups in a batch.

## Layout

- `plugins/shodan.manifest.json` — the pack manifest (catalog entry source; also what the
  marketplace install gate reads).
- `dist/pack.mjs` — the runnable bundle. Hand-written (no build step), matching the Telegram pack's
  layout — the plugin manifests are duplicated here as JS object literals rather than imported from
  the JSON, because dynamic `import()` of a JSON module needs import-attribute syntax whose support
  is still inconsistent across engines; `test-plugin.mjs` pins the two copies against each other.
- `test-plugin.mjs` — functional tests (mocked graph/network) plus the manifest-drift check. Run
  with `node test-plugin.mjs`.

Data source: `api.shodan.io`. Requires your own Shodan account and API key — get one at
[shodan.io](https://www.shodan.io/).
