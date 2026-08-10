// Shodan — the paid REST API (api.shodan.io), not the free InternetDB endpoint the IP Recon pack
// already covers keylessly. Three plugins:
//   1. shodan_search      — free-text host search (org:"X", hostname:example.com, product:nginx …).
//                            Costs 1 query credit per run. Selection-independent: runs once.
//   2. shodan_dns         — a selected Domain's known subdomains + passively-observed DNS records.
//                            Free (no credit spent). Shodan's own historical cache, not a live query.
//   3. shodan_api_status  — plan + remaining query/scan credits for the configured key. Free.
//
// Every request carries the analyst's OWN key as `?key=` (Shodan's REST API has no header-auth
// option), read from ctx.config.api_key — never hardcoded, never logged. `scopes.config` is
// declared on EACH plugin, not once on the pack: config is stored per PLUGIN identifier (see
// plugin-config.ts), so there is no pack-level sharing mechanism to reuse here. The analyst pastes
// the key into Settings on each of the three rows once; after that it is remembered (desktop OS
// keychain) or held for the session (browser).
//
// Node/edge shapes deliberately MIRROR the free packs already shipped, rather than inventing a
// parallel model for the same facts: IP → Host ("exposes"), IP → Vulnerability ("affected by"),
// IP → Domain ("resolves to") match run.vineyard.pluginpacks.ip_recon's Shodan InternetDB plugin;
// IP → Autonomous System ("announced by") matches the IP Intelligence pack's IP → ASN plugin;
// IP → Location ("geolocated to") matches its IP Geolocation plugin; Domain → Domain ("subdomain")
// matches Domain Recon's Certificate Transparency plugin; Domain → DNS Record ("has record")
// matches Domain Recon's per-record-type DNS Lookup plugins. A CVE or an AS number reads the same
// whichever plugin put it on the canvas.

const API = "https://api.shodan.io";

// ---- shared: key, fetch, pacing ------------------------------------------------------------

function apiKey(ctx) {
  const v = ctx.config && ctx.config.api_key;
  return typeof v === "string" ? v.trim() : "";
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * GET one Shodan endpoint with the key attached, one 429 retry, and a uniform result shape.
 *
 * Returns { ok, status, body, error } rather than throwing: every caller needs to tell "no data
 * for this input" (a clean 4xx with a JSON `error`) from "the request itself failed" (network,
 * abort, an HTML error page from a layer in front of the API — measured: a bad key's 401 is HTML,
 * not JSON, so `error` there is the caller's own message rather than a parsed body).
 */
async function shodanGet(ctx, path, params) {
  const url = new URL(path, API);
  for (const [k, v] of Object.entries(params || {})) if (v != null && v !== "") url.searchParams.set(k, v);
  url.searchParams.set("key", apiKey(ctx));

  for (let attempt = 0; attempt < 2; attempt++) {
    if (ctx.signal && ctx.signal.aborted) return { ok: false, status: 0, error: "cancelled" };
    let res;
    try {
      res = await ctx.net.fetch(url.toString(), { method: "GET" });
    } catch (e) {
      return { ok: false, status: 0, error: String((e && e.message) || e) };
    }
    if (res.status === 429 && attempt === 0) {
      const retryAfter = Number(res.headers && res.headers["retry-after"]);
      await sleep(Number.isFinite(retryAfter) && retryAfter > 0 ? retryAfter * 1000 : 2000);
      continue;
    }
    if (res.status === 401) return { ok: false, status: 401, error: "unauthorized" };
    let body = null;
    try {
      body = await res.json();
    } catch {
      /* non-JSON body (an HTML error page from a layer in front of the API) — body stays null */
    }
    if (!res.ok) return { ok: false, status: res.status, body, error: (body && body.error) || `HTTP ${res.status}` };
    return { ok: true, status: res.status, body };
  }
  return { ok: false, status: 429, error: "rate limited" };
}

/** The one message every plugin gives for a key problem, so it reads the same everywhere. */
function keyMessage(r) {
  if (r.status === 401) return "Shodan rejected this key. Check the API key in Settings below.";
  return `Shodan request failed: ${r.error || `HTTP ${r.status}`}`;
}

// ---- shared: node/edge shaping (mirrors the free packs — see file header) -------------------

const isDomain = (n) => n.type === "infrastructure.domain";
const domainOf = (n) => String((n.data && n.data.domain_name) || (n.data && n.data.value) || "").trim().toLowerCase();
const ipVersion = (ip) => (String(ip).includes(":") ? "ipv6" : "ipv4");
const cc2 = (s) => {
  const v = String(s || "").toUpperCase();
  return /^[A-Z]{2}$/.test(v) ? v : undefined;
};
const CVE_RE = /^CVE-\d{4}-\d{4,}$/i;
const ASN_RE = /^AS(\d+)$/i;

/** Aggregate Shodan search matches by IP — a query can return several rows for one host (one per
 *  scanned port), and mergeNodeData does not UNION array-ish fields across separate createNode
 *  calls, it overwrites, so aggregating here is what stops a second port's write from erasing the
 *  first port's. */
function aggregateMatches(matches) {
  const byIp = new Map();
  for (const m of matches || []) {
    const ip = m.ip_str;
    if (!ip) continue;
    let a = byIp.get(ip);
    if (!a) {
      a = { ip, ports: new Set(), cves: new Set(), hostnames: new Set(), org: "", isp: "", asn: "", os: "", location: null };
      byIp.set(ip, a);
    }
    if (m.port) a.ports.add(m.port);
    for (const cve of Object.keys(m.vulns || {})) if (CVE_RE.test(cve)) a.cves.add(cve.toUpperCase());
    for (const h of m.hostnames || []) if (h) a.hostnames.add(String(h).trim().toLowerCase());
    if (!a.org && m.org) a.org = m.org;
    if (!a.isp && m.isp) a.isp = m.isp;
    if (!a.asn && m.asn) a.asn = m.asn;
    if (!a.os && m.os) a.os = m.os;
    if (!a.location && m.location) a.location = m.location;
  }
  return [...byIp.values()];
}

/** Write one aggregated IP and everything hanging off it. Returns which node kinds it produced. */
async function writeIp(ctx, agg, asNodeByAsn) {
  const made = { ip: false, host: false, as: false, domains: 0, vulns: 0, geo: false };

  const asnMatch = ASN_RE.exec(agg.asn || "");
  const ipNode = await ctx.graph.createNode({
    type: "infrastructure.ip_address",
    data: {
      ip_address: agg.ip,
      version: ipVersion(agg.ip),
      ...(cc2(agg.location && agg.location.country_code) ? { country_code: cc2(agg.location.country_code) } : {}),
      ...(agg.org || agg.isp ? { organization: agg.org || agg.isp } : {}),
      ...(agg.asn ? { asn: agg.asn.toUpperCase() } : {}),
    },
  });
  made.ip = true;
  const ipId = String(ipNode.id);

  if (agg.ports.size) {
    const hostNode = await ctx.graph.createNode({
      type: "infrastructure.host",
      data: {
        hostname: agg.ip,
        open_ports: [...agg.ports].sort((a, b) => a - b).join(", "),
        ...(agg.os ? { operating_system: agg.os } : {}),
      },
    });
    await ctx.graph.createEdge({ from: ipId, to: String(hostNode.id), label: "exposes" });
    made.host = true;
  }

  if (asnMatch) {
    const asn = Number(asnMatch[1]);
    let asId = asNodeByAsn.get(asn);
    if (!asId) {
      const asNode = await ctx.graph.createNode({
        type: "infrastructure.autonomous_system",
        data: {
          autonomous_system_number: asn,
          ...(cc2(agg.location && agg.location.country_code) ? { country_code: cc2(agg.location.country_code) } : {}),
        },
      });
      asId = String(asNode.id);
      asNodeByAsn.set(asn, asId);
    }
    await ctx.graph.createEdge({ from: ipId, to: asId, label: "announced by" });
    made.as = true;
  }

  for (const cve of agg.cves) {
    const vNode = await ctx.graph.createNode({ type: "threat.vulnerability", data: { cve_id: cve } });
    await ctx.graph.createEdge({ from: ipId, to: String(vNode.id), label: "affected by" });
    made.vulns++;
  }

  for (const h of agg.hostnames) {
    const dNode = await ctx.graph.createNode({ type: "infrastructure.domain", data: { domain_name: h } });
    await ctx.graph.createEdge({ from: ipId, to: String(dNode.id), label: "resolves to" });
    made.domains++;
  }

  if (agg.location && (agg.location.city || agg.location.country_name || Number.isFinite(agg.location.latitude))) {
    const loc = agg.location;
    const cc = cc2(loc.country_code);
    const name = [loc.city, cc || loc.country_name].filter(Boolean).join(", ") || loc.country_name || agg.ip;
    const locNode = await ctx.graph.createNode({
      type: "geo.location",
      data: {
        name,
        ...(Number.isFinite(loc.latitude) ? { latitude: Number(loc.latitude) } : {}),
        ...(Number.isFinite(loc.longitude) ? { longitude: Number(loc.longitude) } : {}),
        ...(loc.city ? { city: String(loc.city) } : {}),
        ...(loc.region_code ? { region: String(loc.region_code) } : {}),
        ...(loc.country_name ? { country: String(loc.country_name) } : {}),
      },
    });
    await ctx.graph.createEdge({ from: ipId, to: String(locNode.id), label: "geolocated to" });
    made.geo = true;
  }

  return made;
}

// ---- plugin: Shodan Search -------------------------------------------------------------------

const searchPlugin = {
  manifest: {
    identifier: "run.vineyard.plugins.shodan_search",
    content_type: "vineyard:plugin",
    name: "Shodan Search",
    version: "1.0.0",
    description:
      'Runs a free-text Shodan query (host search syntax, e.g. org:"Example Corp", hostname:example.com, product:nginx port:443) and materializes up to 100 matching hosts: an IP Address node per host (with its exposing Host, announcing AS, approximate Location, known CVEs and reverse hostnames), reusing the same shapes/edge labels as the free IP Recon pack\'s Shodan InternetDB plugin. Costs exactly 1 Shodan query credit per run, regardless of how many nodes are selected — this plugin ignores the selection and runs once. Needs your own api.shodan.io key in Settings below.',
    icon: "search",
    author: { name: "VINEYARD", url: "https://github.com/Vineyard-Intelligence" },
    license: "Apache-2.0",
    platforms: { primary: "web", web: { runtime: "sandbox-js", entry: "inline" } },
    params: {
      type: "object",
      properties: {
        query: {
          type: "string",
          title: "Query",
          minLength: 1,
          description:
            'Shodan search syntax. Examples: org:"Example Corp" · hostname:example.com · product:nginx port:443 · ssl.cert.subject.cn:example.com',
        },
      },
      required: ["query"],
    },
    io: {
      consumes: [],
      produces: [
        { typepack: "run.vineyard.typepacks.infrastructure", category: "infrastructure", name: "ip_address" },
        { typepack: "run.vineyard.typepacks.infrastructure", category: "infrastructure", name: "host" },
        { typepack: "run.vineyard.typepacks.infrastructure", category: "infrastructure", name: "autonomous_system" },
        { typepack: "run.vineyard.typepacks.infrastructure", category: "infrastructure", name: "domain" },
        { typepack: "run.vineyard.typepacks.threat", category: "threat", name: "vulnerability" },
        { typepack: "run.vineyard.typepacks.geo", category: "geo", name: "location" },
      ],
    },
    scopes: {
      graph: ["node:create", "edge:create"],
      network: [
        {
          endpoint: "https://api.shodan.io/shodan/host/search",
          methods: ["GET"],
          purpose: "Run the query against Shodan's host search index.",
        },
      ],
      config: [{ key: "api_key", label: "Shodan API Key", type: "string", secret: true, optional: false }],
    },
    lifecycle: { persistence: "opt-in", controls: ["progress", "cancel"], progress: "determinate" },
  },
  async run(ctx) {
    const key = apiKey(ctx);
    if (!key) return { summary: "No Shodan API key configured — add one in Settings below.", counts: { ips: 0 } };
    const query = String((ctx.params && ctx.params.query) || "").trim();
    if (!query) return { summary: "Enter a Shodan search query first.", counts: { ips: 0 } };

    const r = await shodanGet(ctx, "/shodan/host/search", { query });
    if (!r.ok) return { summary: keyMessage(r), counts: { ips: 0 } };
    const total = Number(r.body && r.body.total) || 0;
    const matches = (r.body && r.body.matches) || [];
    if (!matches.length) return { summary: `0 results for "${query}" (${total} total match Shodan's index)`, counts: { ips: 0 } };

    const aggregated = aggregateMatches(matches);
    const asNodeByAsn = new Map();
    const totals = { ip: 0, host: 0, as: 0, domains: 0, vulns: 0, geo: 0 };
    for (let i = 0; i < aggregated.length; i++) {
      if (ctx.signal && ctx.signal.aborted) break;
      ctx.progress &&
        ctx.progress.set &&
        ctx.progress.set({ percent: Math.round(((i + 1) / aggregated.length) * 100), message: aggregated[i].ip });
      const made = await writeIp(ctx, aggregated[i], asNodeByAsn);
      if (made.ip) totals.ip++;
      if (made.host) totals.host++;
      if (made.as) totals.as++;
      if (made.geo) totals.geo++;
      totals.domains += made.domains;
      totals.vulns += made.vulns;
    }
    const more = total > matches.length ? ` — ${total - matches.length} more match this query in Shodan's index` : "";
    return {
      summary: `"${query}": ${totals.ip} host(s), ${totals.host} exposing ports, ${totals.as} AS(es), ${totals.vulns} CVE(s), ${totals.geo} geolocated${more}`,
      counts: { ips: totals.ip, hosts: totals.host, autonomous_systems: totals.as, vulnerabilities: totals.vulns, locations: totals.geo },
    };
  },
};

// ---- plugin: Shodan DNS ------------------------------------------------------------------------

const MAX_SUBDOMAINS = 150; // matches the free Certificate Transparency plugin's per-domain cap
const MAX_RECORDS = 300;
const DNS_PACE_MS = 350; // courteous spacing between sequential /dns/domain calls in a batch

const dnsPlugin = {
  manifest: {
    identifier: "run.vineyard.plugins.shodan_dns",
    content_type: "vineyard:plugin",
    name: "Shodan DNS",
    version: "1.0.0",
    description:
      'Reads each selected Domain\'s passively-observed DNS history from Shodan: known subdomains become Domain nodes ("subdomain" — same edge label as the free Certificate Transparency plugin, so both read the same way on the canvas), and the underlying A/AAAA/MX/NS/TXT/CAA/… records become DNS Record nodes ("has record" — matching the free DNS Lookup plugins\' shape). This is Shodan\'s own cache, not a live query — it can show records the live DNS-over-HTTPS lookups no longer see, and miss ones that changed after Shodan\'s last crawl. Free — does not spend a query credit. Needs your own api.shodan.io key in Settings below.',
    icon: "waypoints",
    author: { name: "VINEYARD", url: "https://github.com/Vineyard-Intelligence" },
    license: "Apache-2.0",
    platforms: { primary: "web", web: { runtime: "sandbox-js", entry: "inline" } },
    io: {
      consumes: [{ typepack: "run.vineyard.typepacks.infrastructure", category: "infrastructure", name: "domain" }],
      produces: [
        { typepack: "run.vineyard.typepacks.infrastructure", category: "infrastructure", name: "domain" },
        { typepack: "run.vineyard.typepacks.infrastructure", category: "infrastructure", name: "dns_record" },
      ],
    },
    scopes: {
      graph: ["node:read", "node:create", "edge:create"],
      network: [
        {
          endpoint: "https://api.shodan.io/dns/domain",
          methods: ["GET"],
          purpose: "Fetch a domain's known subdomains and passively-observed DNS records.",
        },
      ],
      config: [{ key: "api_key", label: "Shodan API Key", type: "string", secret: true, optional: false }],
    },
    lifecycle: { persistence: "opt-in", controls: ["progress", "cancel"], progress: "determinate" },
  },
  async run(ctx) {
    const key = apiKey(ctx);
    if (!key) return { summary: "No Shodan API key configured — add one in Settings below.", counts: { subdomains: 0, dns_records: 0 } };
    const ids = ctx.input.selection;
    if (!ids.length) return { summary: "Select one or more Domain nodes first", counts: { subdomains: 0, dns_records: 0 } };

    let subdomains = 0;
    let records = 0;
    let truncatedSubs = 0;
    let truncatedRecs = 0;
    let failed = 0;
    for (let i = 0; i < ids.length; i++) {
      if (ctx.signal && ctx.signal.aborted) break;
      const node = await ctx.graph.get(ids[i]);
      if (!node || !isDomain(node)) continue;
      const domain = domainOf(node);
      if (!domain) continue;
      ctx.progress &&
        ctx.progress.set &&
        ctx.progress.set({ percent: Math.round(((i + 1) / ids.length) * 100), message: `Shodan DNS: ${domain}` });
      if (i > 0) await sleep(DNS_PACE_MS);

      const r = await shodanGet(ctx, `/dns/domain/${encodeURIComponent(domain)}`, {});
      if (!r.ok) {
        failed++;
        continue;
      }
      const body = r.body || {};

      // Subdomain nodes first, so the record loop below can edge a record to the exact name it
      // belongs to (the apex node passed in, or one of these) rather than always to the apex.
      const nodeByName = new Map([[domain, ids[i]]]);
      const subs = Array.isArray(body.subdomains) ? body.subdomains : [];
      if (subs.length > MAX_SUBDOMAINS) truncatedSubs += subs.length - MAX_SUBDOMAINS;
      for (const sub of subs.slice(0, MAX_SUBDOMAINS)) {
        if (ctx.signal && ctx.signal.aborted) break;
        const name = sub ? `${sub}.${domain}` : domain;
        if (nodeByName.has(name)) continue;
        const subNode = await ctx.graph.createNode({ type: "infrastructure.domain", data: { domain_name: name } });
        await ctx.graph.createEdge({ from: ids[i], to: String(subNode.id), label: "subdomain" });
        nodeByName.set(name, String(subNode.id));
        subdomains++;
      }

      const data = Array.isArray(body.data) ? body.data : [];
      if (data.length > MAX_RECORDS) truncatedRecs += data.length - MAX_RECORDS;
      for (const rec of data.slice(0, MAX_RECORDS)) {
        if (ctx.signal && ctx.signal.aborted) break;
        const name = rec.subdomain ? `${rec.subdomain}.${domain}` : domain;
        const ownerId = nodeByName.get(name) || ids[i]; // a record for a name the subdomain list omitted still anchors to the apex
        const recNode = await ctx.graph.createNode({
          type: "infrastructure.dns_record",
          data: {
            record_name: name,
            record_value: String(rec.value == null ? "" : rec.value),
            record_type: String(rec.type || "").toUpperCase(),
            ...(rec.options && Number.isFinite(rec.options.ttl) ? { ttl: Number(rec.options.ttl) } : {}),
          },
        });
        await ctx.graph.createEdge({ from: ownerId, to: String(recNode.id), label: "has record" });
        records++;
      }
    }
    const notes = [
      truncatedSubs ? `${truncatedSubs} subdomain(s) omitted by the ${MAX_SUBDOMAINS}/domain cap` : "",
      truncatedRecs ? `${truncatedRecs} record(s) omitted by the ${MAX_RECORDS}/domain cap` : "",
      failed ? `${failed} domain(s) failed` : "",
    ].filter(Boolean);
    return {
      summary: `${subdomains} subdomain(s), ${records} DNS record(s) from ${ids.length - failed}/${ids.length} domain(s)${notes.length ? ` (${notes.join("; ")})` : ""}`,
      counts: { subdomains, dns_records: records, failed },
    };
  },
};

// ---- plugin: Shodan API Status -----------------------------------------------------------------

const statusPlugin = {
  manifest: {
    identifier: "run.vineyard.plugins.shodan_api_status",
    content_type: "vineyard:plugin",
    name: "Shodan API Status",
    version: "1.0.0",
    description:
      "Checks the configured key against api.shodan.io/api-info and reports the plan and remaining query/scan credits — free, does not spend a credit. Run this before a search you are unsure you can afford. Does not touch the graph. Needs your own api.shodan.io key in Settings below.",
    icon: "gauge",
    author: { name: "VINEYARD", url: "https://github.com/Vineyard-Intelligence" },
    license: "Apache-2.0",
    platforms: { primary: "web", web: { runtime: "sandbox-js", entry: "inline" } },
    io: { consumes: [], produces: [] },
    scopes: {
      network: [
        {
          endpoint: "https://api.shodan.io/api-info",
          methods: ["GET"],
          purpose: "Check the configured key's plan and remaining credits.",
        },
      ],
      config: [{ key: "api_key", label: "Shodan API Key", type: "string", secret: true, optional: false }],
    },
    lifecycle: { persistence: "ephemeral", controls: ["cancel"] },
  },
  async run(ctx) {
    const key = apiKey(ctx);
    if (!key) return { summary: "No Shodan API key configured — add one in Settings below.", counts: {} };
    const r = await shodanGet(ctx, "/api-info", {});
    if (!r.ok) return { summary: keyMessage(r), counts: {} };
    const b = r.body || {};
    return {
      summary: `Plan: ${b.plan || "unknown"} · ${b.query_credits ?? "?"} query credit(s), ${b.scan_credits ?? "?"} scan credit(s), ${b.monitored_ips ?? 0} monitored IP(s) remaining`,
      counts: {
        query_credits: Number.isFinite(b.query_credits) ? b.query_credits : undefined,
        scan_credits: Number.isFinite(b.scan_credits) ? b.scan_credits : undefined,
      },
    };
  },
};

// ---- pack --------------------------------------------------------------------------------------
// The manifest below is data, not derived — it has to equal plugins/shodan.manifest.json's pack-
// level fields by hand. A relative import of that JSON file would resolve at runtime (this module
// loads over HTTP from jsDelivr, so `../plugins/…` is a real, fetchable sibling URL there) but
// dynamic `import()` of JSON needs import-attribute syntax whose support is still inconsistent
// across engines — a SyntaxError there fails the whole pack rather than one plugin. Every other
// pack in this catalog inlines its manifest as a literal for the same reason (see
// pluginpack-telegram/dist/pack.mjs); check-shodan-pack.mjs pins this copy against the JSON file
// so the two cannot drift silently.
export default {
  manifest: {
    identifier: "run.vineyard.pluginpacks.shodan",
    content_type: "vineyard:pluginpack",
    name: "Shodan",
    version: "1.0.0",
    description:
      "Shodan's paid REST API: free-text host search, passive subdomain/DNS discovery, and a key/credit status check. Needs your own api.shodan.io key — nothing here is keyless.",
    author: { name: "VINEYARD", url: "https://github.com/Vineyard-Intelligence" },
    license: "Apache-2.0",
    icon: "radar",
    platforms: { primary: "web", web: { runtime: "sandbox-js", entry: "dist/pack.mjs" } },
  },
  plugins: [searchPlugin, dnsPlugin, statusPlugin],
};
