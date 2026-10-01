// Shodan — the paid REST API (api.shodan.io), not the free InternetDB endpoint the IP Recon pack
// already covers keylessly. Seven plugins, split one-per-endpoint so a human (or the agent) picks
// the cheapest call that answers the question instead of reaching for search every time:
//
//   1. shodan_host        — /shodan/host/{ip}      everything Shodan knows about ONE ip.   FREE
//   2. shodan_search      — /shodan/host/search    free-text query over the whole index.   1 CREDIT
//   3. shodan_count       — /shodan/host/count     how many hosts a query matches, + facets. FREE
//   4. shodan_dns_domain  — /dns/domain/{domain}   subdomains + passive DNS history.        FREE
//   5. shodan_dns_resolve — /dns/resolve           forward: hostname -> ip, batched.        FREE
//   6. shodan_dns_reverse — /dns/reverse           reverse: ip -> hostnames, batched.       FREE
//   7. shodan_api_status  — /api-info              plan + remaining credits.                FREE
//
// Credit costs above are MEASURED against a live `dev` key (before/after /api-info), not read off
// the docs: only /shodan/host/search moves the counter. That asymmetry is the whole reason these
// are separate plugins — shodan_count answers "is this query worth a credit?" for free, and
// shodan_host enriches a known IP for free, so the one paid call is a deliberate choice.
//
// Every request carries the analyst's OWN key as `?key=` (Shodan's REST API has no header-auth
// option), read from ctx.config.api_key — never hardcoded, never logged. `scopes.config` is
// declared on EACH plugin, not once on the pack: config is stored per PLUGIN identifier (see
// plugin-config.ts), so there is no pack-level sharing to lean on inside the manifest grammar. The
// app fans a typed value out to the pack's other members, so the key is pasted once, not seven
// times.
//
// Node/edge shapes deliberately MIRROR the free packs already shipped, rather than inventing a
// parallel model for the same facts: IP → Host ("exposes"), IP → Vulnerability ("affected by"),
// IP → Domain ("resolves to") match run.vineyard.pluginpacks.ip_recon's Shodan InternetDB plugin;
// Domain → IP ("resolves to") matches Domain Recon's A/AAAA lookups; IP → Autonomous System
// ("announced by") matches the IP Intelligence pack; IP → Location ("geolocated to") matches IP
// Recon's IP Geolocation plugin; Domain → Domain ("subdomain") matches Domain Recon's Certificate
// Transparency plugin; Domain → DNS Record ("has record") matches its DNS Lookup plugins. A CVE or
// an AS number reads the same whichever plugin put it on the canvas.
//
// WHAT IS DELIBERATELY *NOT* A NODE: Shodan's per-service `product`/`version` (Apache httpd 2.4.7,
// OpenSSH 6.6.1) and its `tags` (cloud, honeypot). Those are pivot *queries*, not entities — a
// "nginx" node would collide across millions of unrelated hosts and collapse the graph into a hub.
// They go in the run summary instead, where they are read and fed back into shodan_search.

const API = "https://api.shodan.io";

// Measured: 25 names in one ?hostnames= is fine. Kept well under any URL-length cliff, and small
// enough that one failed batch loses little.
const RESOLVE_BATCH = 25;
const MAX_SUBDOMAINS = 150; // matches the free Certificate Transparency plugin's per-domain cap
const MAX_RECORDS = 300;
const MAX_CVES = 25; // per IP — see the note in writeIp
const PACE_MS = 350; // courteous spacing between sequential calls in a batch

// ---- shared: key, fetch, pacing ------------------------------------------------------------

function apiKey(ctx) {
  const v = ctx.config && ctx.config.api_key;
  return typeof v === "string" ? v.trim() : "";
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const chunk = (arr, n) => {
  const out = [];
  for (let i = 0; i < arr.length; i += n) out.push(arr.slice(i, i + n));
  return out;
};

/**
 * GET one Shodan endpoint with the key attached, one 429 retry, and a uniform result shape.
 *
 * Returns { ok, status, body, error } rather than throwing: every caller needs to tell "no data
 * for this input" (a clean 4xx with a JSON `error` — measured: `{"error":"No information available
 * for that IP."}` at 404 is the normal answer for a quiet host, not a failure) from "the request
 * itself failed" (network, abort, an HTML error page from a layer in front of the API — measured:
 * a bad key's 401 is HTML, not JSON, so `.json()` there throws and `body` stays null).
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

/** A 401 ends the whole run, in the plugins that loop over a selection.
 *
 *  Those four folded every !ok into a per-item `failed` counter, so a typo'd key over a 30-node
 *  selection read as "0 found, 30 failed" — indistinguishable from "Shodan has no data on these",
 *  which is the wrong thing to go and investigate. A rejected key is not a per-item outcome: it
 *  will reject the other twenty-nine too. */
const isBadKey = (r) => r.status === 401;

const NO_KEY = "No Shodan API key configured — add one in Settings below.";

// ---- shared: node/edge shaping (mirrors the free packs — see file header) -------------------

const isDomain = (n) => n.type === "infrastructure.domain";
const domainOf = (n) => String((n.data && n.data.domain_name) || (n.data && n.data.value) || "").trim().toLowerCase();
const isIp = (n) => n.type === "infrastructure.ip_address";
const ipOf = (n) => String((n.data && n.data.ip_address) || (n.data && n.data.value) || "").trim();
const ipVersion = (ip) => (String(ip).includes(":") ? "ipv6" : "ipv4");
const cc2 = (s) => {
  const v = String(s || "").toUpperCase();
  return /^[A-Z]{2}$/.test(v) ? v : undefined;
};
const CVE_RE = /^CVE-\d{4}-\d{4,}$/i;
const ASN_RE = /^AS(\d+)$/i;

/** Whichever CVSS base score a Shodan vuln detail happens to carry. Measured: a record can have
 *  `cvss_v2` and `cvss_version: 2.0` with no plain `cvss` at all, so reading one field name only
 *  scores half the findings and mis-ranks the rest. */
function cvssOf(detail) {
  for (const k of ["cvss_v3", "cvss", "cvss_v2"]) {
    // The raw value first, and a blank one SKIPS to the next key. `Number(detail && detail[k])`
    // reads null as 0 — finite — so a bare CVE id with no detail at all scored 0.0, which is the
    // CVSS "None" band: the graph would assert that Log4Shell is harmless, and rank it last so the
    // MAX_CVES cap dropped it as "lower-CVSS". Same trap one level down when a record carries
    // cvss:null alongside a real cvss_v2.
    const raw = detail && detail[k];
    if (raw === null || raw === undefined || raw === "") continue;
    const n = Number(raw);
    if (Number.isFinite(n)) return n;
  }
  return undefined;
}

/** Shodan spells `vulns` two ways and both reach this pack: an OBJECT keyed by CVE (with a detail
 *  carrying the score) on a /host/search match and inside each /shodan/host/{ip} service, a flat
 *  ARRAY of bare ids at the top level of /shodan/host/{ip}. Measured on both. Non-CVE keys appear
 *  too, so everything is filtered rather than trusted.
 *
 *  Fills `into` as CVE -> score-or-undefined. A score once found is never downgraded to undefined
 *  by a later bare mention of the same id. */
function collectVulns(vulns, into) {
  const entries = Array.isArray(vulns) ? vulns.map((c) => [c, null]) : Object.entries(vulns || {});
  for (const [cve, detail] of entries) {
    if (!CVE_RE.test(cve)) continue;
    const id = String(cve).toUpperCase();
    const score = cvssOf(detail);
    if (!into.has(id) || (score !== undefined && into.get(id) === undefined)) into.set(id, score);
  }
}

const emptyAgg = (ip) => ({
  ip,
  ports: new Set(),
  cves: new Map(), // CVE id -> CVSS base score, or undefined when Shodan gave none
  hostnames: new Set(),
  org: "",
  isp: "",
  asn: "",
  os: "",
  location: null,
});

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
      a = emptyAgg(ip);
      byIp.set(ip, a);
    }
    if (m.port) a.ports.add(m.port);
    collectVulns(m.vulns, a.cves);
    for (const h of m.hostnames || []) if (h) a.hostnames.add(String(h).trim().toLowerCase());
    if (!a.org && m.org) a.org = m.org;
    if (!a.isp && m.isp) a.isp = m.isp;
    if (!a.asn && m.asn) a.asn = m.asn;
    if (!a.os && m.os) a.os = m.os;
    if (!a.location && m.location) a.location = m.location;
  }
  return [...byIp.values()];
}

/** The same aggregate shape from /shodan/host/{ip}, which reports the SAME facts in a different
 *  layout: ports/vulns/hostnames are already unioned across services at the top level, and the
 *  geo fields are flat there rather than nested under `location` as they are on a search match. */
function aggregateHost(body) {
  const b = body || {};
  const a = emptyAgg(String(b.ip_str || ""));
  for (const p of b.ports || []) if (p) a.ports.add(p);
  // Per-service first: those detail objects carry the CVSS scores that rank the cap below. The
  // top-level list is bare ids and only fills in anything the services did not mention.
  for (const svc of b.data || []) collectVulns(svc && svc.vulns, a.cves);
  collectVulns(b.vulns, a.cves);
  for (const h of b.hostnames || []) if (h) a.hostnames.add(String(h).trim().toLowerCase());
  a.org = b.org || "";
  a.isp = b.isp || "";
  a.asn = b.asn || "";
  a.os = b.os || "";
  a.location = {
    city: b.city,
    region_code: b.region_code,
    country_code: b.country_code,
    country_name: b.country_name,
    latitude: b.latitude,
    longitude: b.longitude,
  };
  return a;
}

/** Write one aggregated IP and everything hanging off it. Returns which node kinds it produced.
 *  `ipId` pins the IP to a node that already exists (the selected one) instead of creating a
 *  second; identity would merge them anyway, but reusing the selection keeps the edges attached to
 *  what the analyst is looking at. */
async function writeIp(ctx, agg, asNodeByAsn, existingIpId) {
  const made = { ip: false, host: false, as: false, domains: 0, vulns: 0, cvesOmitted: 0, geo: false };
  const loc = agg.location || {};
  const country = cc2(loc.country_code);
  const firstHostname = [...agg.hostnames][0];

  let ipId = existingIpId ? String(existingIpId) : "";
  const ipData = {
    ip_address: agg.ip,
    version: ipVersion(agg.ip),
    ...(country ? { country_code: country } : {}),
    ...(agg.org || agg.isp ? { organization: agg.org || agg.isp } : {}),
    ...(agg.asn ? { asn: String(agg.asn).toUpperCase() } : {}),
    ...(firstHostname ? { reverse_dns: firstHostname } : {}),
  };
  if (ipId) {
    // Delta, not a snapshot: updateNode merges what it is given, so handing it only the fields
    // this run actually established is what stops a blank from clobbering another plugin's value.
    if (ctx.graph.updateNode) await ctx.graph.updateNode(ipId, ipData);
  } else {
    const ipNode = await ctx.graph.createNode({ type: "infrastructure.ip_address", data: ipData });
    ipId = String(ipNode.id);
    made.ip = true;
  }

  if (agg.ports.size) {
    const hostNode = await ctx.graph.createNode({
      type: "infrastructure.host",
      data: {
        hostname: agg.ip,
        open_ports: [...agg.ports].sort((a, b) => a - b).join(", "),
        ...(agg.os ? { operating_system: agg.os } : {}),
        ...(agg.org || agg.isp ? { hosting_provider: agg.org || agg.isp } : {}),
      },
    });
    await ctx.graph.createEdge({ from: ipId, to: String(hostNode.id), label: "exposes" });
    made.host = true;
  }

  const asnMatch = ASN_RE.exec(agg.asn || "");
  if (asnMatch) {
    const asn = Number(asnMatch[1]);
    let asId = asNodeByAsn.get(asn);
    if (!asId) {
      // ASN ONLY. The typepack declares autonomous_system.country_code as "country of
      // registration", and Shodan gives no such thing — `country` here is where THIS IP geolocates.
      // Writing it would be wrong on its own terms and destructive besides: the AS node's identity
      // is the ASN alone, mergeNodeData overwrites with any non-blank incoming value, and the
      // IP-to-ASN pack fills the same field from the RIR. One Cloudflare IP in Seoul would rewrite
      // AS13335's registered country from US to KR.
      const asNode = await ctx.graph.createNode({
        type: "infrastructure.autonomous_system",
        data: { autonomous_system_number: asn },
      });
      asId = String(asNode.id);
      asNodeByAsn.set(asn, asId);
      made.as = true; // set HERE, not below: 40 IPs on one ASN are one AS node, not forty.
    }
    await ctx.graph.createEdge({ from: ipId, to: asId, label: "announced by" });
  }

  // Capped, highest CVSS first. Measured: one ordinary old Apache host carries 119 CVEs, so an
  // uncapped page of 100 search results is >10,000 vulnerability nodes and edges — a graph nobody
  // can read, for a pack whose job is pivoting. What the cap drops is COUNTED and reported by the
  // caller rather than silently vanishing, and the survivors are the ones worth looking at.
  const ranked = [...agg.cves.entries()].sort((x, y) => (y[1] ?? -1) - (x[1] ?? -1));
  made.cvesOmitted = Math.max(0, ranked.length - MAX_CVES);
  for (const [cve, cvss] of ranked.slice(0, MAX_CVES)) {
    const vNode = await ctx.graph.createNode({
      type: "threat.vulnerability",
      data: { cve_id: cve, ...(cvss === undefined ? {} : { cvss_score: cvss }) },
    });
    await ctx.graph.createEdge({ from: ipId, to: String(vNode.id), label: "affected by" });
    made.vulns++;
  }

  for (const h of agg.hostnames) {
    const dNode = await ctx.graph.createNode({ type: "infrastructure.domain", data: { domain_name: h } });
    await ctx.graph.createEdge({ from: ipId, to: String(dNode.id), label: "resolves to" });
    made.domains++;
  }

  // A city or a region, or no node. Falling back to the bare country produced a "US" node pinned
  // at one host's coordinates that every US host in the run then merged into — a hub carrying no
  // fact. The country is already on the IP node, so declining loses nothing. The city||region
  // fallback and the label shape match the free IP Geolocation plugin exactly, so when both run
  // they agree instead of forking the same place into two nodes.
  const place = loc.city || loc.region_code;
  if (place) {
    const name = [place, country || loc.country_name].filter(Boolean).join(", ");
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

/** Shared manifest boilerplate — every plugin here is the same author, license and platform, and
 *  every one needs the analyst's own key. */
const AUTHOR = { name: "VINEYARD", url: "https://github.com/Vineyard-Intelligence" };
// `entry` is the PACK's module, repeated on every member — NOT "inline". Measured the hard way:
// "inline" means "a plugin bundled into the app", nothing is bundled any more, and registry.ts's
// isRemoteRunnable() drops such a member on the floor. A pack that declares it installs fine,
// shows nothing in the run dialog, and gives no diagnostic. Every other pack in the catalog says
// dist/pack.mjs here; test-plugin.mjs now refuses to let this one drift back.
const PACK_ENTRY = "dist/pack.mjs";
const WEB = { primary: "web", web: { runtime: "sandbox-js", entry: PACK_ENTRY } };
const KEY_CONFIG = [{ key: "api_key", label: "Shodan API Key", type: "string", secret: true, optional: false }];
const T_INFRA = "run.vineyard.typepacks.infrastructure";
const io = (t, category, name) => ({ typepack: t, category, name });

// ---- plugin: Shodan Host ---------------------------------------------------------------------

const hostPlugin = {
  manifest: {
    identifier: "run.vineyard.plugins.shodan_host",
    content_type: "vineyard:plugin",
    name: "Shodan Host",
    version: "2.0.2",
    description:
      "Looks up each selected IP Address in Shodan and creates its Host with open ports (\"exposes\"), CVEs as Vulnerability nodes (\"affected by\", up to 25 per IP, highest CVSS first), reverse hostnames as Domain nodes (\"resolves to\"), its Autonomous System (\"announced by\") and Location (\"geolocated to\"); fills the IP's country_code, organization, asn and reverse_dns. Product/version banners and Shodan tags are listed in the run summary, not added as nodes. Does not spend a query credit; needs a Shodan API key.",
    icon: "server",
    author: AUTHOR,
    license: "Apache-2.0",
    platforms: WEB,
    io: {
      consumes: [io(T_INFRA, "infrastructure", "ip_address")],
      produces: [
        io(T_INFRA, "infrastructure", "host"),
        io(T_INFRA, "infrastructure", "autonomous_system"),
        io(T_INFRA, "infrastructure", "domain"),
        io("run.vineyard.typepacks.threat", "threat", "vulnerability"),
        io("run.vineyard.typepacks.geo", "geo", "location"),
      ],
    },
    scopes: {
      graph: ["node:read", "node:create", "node:update", "edge:create"],
      network: [
        {
          endpoint: "https://api.shodan.io/shodan/host",
          methods: ["GET"],
          // The IP is a PATH parameter, and the scope grammar has no wildcard — the narrowest
          // expressible scope is this prefix, which by segment-boundary matching also covers
          // /shodan/host/search and /shodan/host/count. The install gate shows this endpoint.
          purpose: "Look up each selected IP address's host details on Shodan.",
        },
      ],
      config: KEY_CONFIG,
    },
    lifecycle: { persistence: "opt-in", controls: ["progress", "cancel"], progress: "determinate" },
  },
  async run(ctx) {
    if (!apiKey(ctx)) return { summary: NO_KEY, counts: { hosts: 0 } };
    const ids = ctx.input.selection;
    if (!ids.length) return { summary: "Select one or more IP Address nodes first", counts: { hosts: 0 } };

    const asNodeByAsn = new Map();
    const totals = { hosts: 0, ports: 0, vulns: 0, omitted: 0, domains: 0, as: 0, geo: 0 };
    const products = new Set();
    const tags = new Set();
    let unknown = 0;
    let failed = 0;
    let looked = 0;

    for (let i = 0; i < ids.length; i++) {
      if (ctx.signal && ctx.signal.aborted) break;
      const node = await ctx.graph.get(ids[i]);
      if (!node || !isIp(node)) continue;
      const ip = ipOf(node);
      if (!ip) continue;
      looked++;
      ctx.progress &&
        ctx.progress.set &&
        ctx.progress.set({ percent: Math.round(((i + 1) / ids.length) * 100), message: `Shodan host: ${ip}` });
      if (looked > 1) await sleep(PACE_MS);

      const r = await shodanGet(ctx, `/shodan/host/${encodeURIComponent(ip)}`, {});
      if (isBadKey(r)) return { summary: keyMessage(r), counts: {} };
      if (!r.ok) {
        // 404 is the routine answer for an IP Shodan has never scanned — not an error to report as
        // one, or every quiet host in a selection reads as a broken key.
        if (r.status === 404) unknown++;
        else failed++;
        continue;
      }
      const body = r.body || {};
      for (const t of body.tags || []) if (t) tags.add(String(t));
      for (const s of body.data || []) {
        if (s && s.product) products.add(s.version ? `${s.product} ${s.version}` : String(s.product));
      }

      const agg = aggregateHost(body);
      if (!agg.ip) agg.ip = ip; // an unusual body without ip_str still belongs to the IP we asked about
      const made = await writeIp(ctx, agg, asNodeByAsn, ids[i]);
      totals.hosts++;
      totals.ports += agg.ports.size;
      totals.vulns += made.vulns;
      totals.omitted += made.cvesOmitted;
      totals.domains += made.domains;
      if (made.as) totals.as++;
      if (made.geo) totals.geo++;
    }

    const notes = [
      unknown ? `${unknown} IP(s) unknown to Shodan` : "",
      failed ? `${failed} lookup(s) failed` : "",
      totals.omitted ? `${totals.omitted} lower-CVSS CVE(s) omitted by the ${MAX_CVES}/host cap` : "",
      products.size ? `running ${[...products].slice(0, 8).join(", ")}` : "",
      tags.size ? `tags: ${[...tags].join(", ")}` : "",
    ].filter(Boolean);
    return {
      summary: `${totals.hosts} host(s): ${totals.ports} open port(s), ${totals.vulns} CVE(s), ${totals.domains} hostname(s), ${totals.as} AS(es)${notes.length ? ` — ${notes.join("; ")}` : ""}`,
      counts: {
        hosts: totals.hosts,
        open_ports: totals.ports,
        vulnerabilities: totals.vulns,
        domains: totals.domains,
        unknown,
        failed,
      },
    };
  },
};

// ---- plugin: Shodan Search --------------------------------------------------------------------

const searchPlugin = {
  manifest: {
    identifier: "run.vineyard.plugins.shodan_search",
    content_type: "vineyard:plugin",
    name: "Shodan Search",
    version: "2.0.2",
    description:
      "Runs a Shodan host search from a query in the Run dialog (no selection) and creates up to 100 matching IP Address nodes per page, each with its Host (\"exposes\"), CVEs as Vulnerability nodes (\"affected by\", up to 25 per IP), hostnames as Domain nodes (\"resolves to\"), Autonomous System (\"announced by\") and Location (\"geolocated to\"). Spends 1 query credit when the query uses a filter or for any page after the first; needs a Shodan API key.",
    icon: "search",
    author: AUTHOR,
    license: "Apache-2.0",
    platforms: WEB,
    params: {
      type: "object",
      properties: {
        query: {
          type: "string",
          title: "Query",
          minLength: 1,
          description: 'Shodan search query, e.g. org:"Example Corp", hostname:example.com or product:nginx port:443.',
        },
        page: {
          type: "integer",
          title: "Page",
          minimum: 1,
          default: 1,
          description: "Results page to fetch, 100 results per page (default 1). Each page is a separate search and can spend a query credit.",
        },
      },
      required: ["query"],
    },
    io: {
      consumes: [],
      produces: [
        io(T_INFRA, "infrastructure", "ip_address"),
        io(T_INFRA, "infrastructure", "host"),
        io(T_INFRA, "infrastructure", "autonomous_system"),
        io(T_INFRA, "infrastructure", "domain"),
        io("run.vineyard.typepacks.threat", "threat", "vulnerability"),
        io("run.vineyard.typepacks.geo", "geo", "location"),
      ],
    },
    scopes: {
      graph: ["node:create", "edge:create"],
      network: [
        {
          endpoint: "https://api.shodan.io/shodan/host/search",
          methods: ["GET"],
          purpose: "Search Shodan for hosts matching the query.",
        },
      ],
      config: KEY_CONFIG,
    },
    lifecycle: { persistence: "opt-in", controls: ["progress", "cancel"], progress: "determinate" },
  },
  async run(ctx) {
    if (!apiKey(ctx)) return { summary: NO_KEY, counts: { ips: 0 } };
    const query = String((ctx.params && ctx.params.query) || "").trim();
    if (!query) return { summary: "Enter a Shodan search query first.", counts: { ips: 0 } };
    const pageRaw = Number((ctx.params && ctx.params.page) || 1);
    const page = Number.isFinite(pageRaw) && pageRaw >= 1 ? Math.floor(pageRaw) : 1;

    const r = await shodanGet(ctx, "/shodan/host/search", { query, ...(page > 1 ? { page } : {}) });
    if (!r.ok) return { summary: keyMessage(r), counts: { ips: 0 } };
    const total = Number(r.body && r.body.total) || 0;
    const matches = (r.body && r.body.matches) || [];
    if (!matches.length) return { summary: `0 results for "${query}" (${total} total match Shodan's index)`, counts: { ips: 0 } };

    const aggregated = aggregateMatches(matches);
    const asNodeByAsn = new Map();
    const totals = { ip: 0, host: 0, as: 0, domains: 0, vulns: 0, omitted: 0, geo: 0 };
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
      totals.omitted += made.cvesOmitted;
    }
    const capped = totals.omitted ? `, ${totals.omitted} lower-CVSS CVE(s) omitted by the ${MAX_CVES}/host cap` : "";
    const seen = page * 100;
    const more = total > seen ? ` — ${total - seen} more match this query (raise Page for the next 100, 1 credit each)` : "";
    return {
      summary: `"${query}" p${page}: ${totals.ip} host(s), ${totals.host} exposing ports, ${totals.as} AS(es), ${totals.vulns} CVE(s), ${totals.geo} geolocated${capped}${more}`,
      counts: { ips: totals.ip, hosts: totals.host, autonomous_systems: totals.as, vulnerabilities: totals.vulns, locations: totals.geo },
    };
  },
};

// ---- plugin: Shodan Count ---------------------------------------------------------------------

const countPlugin = {
  manifest: {
    identifier: "run.vineyard.plugins.shodan_count",
    content_type: "vineyard:plugin",
    name: "Shodan Count",
    version: "2.0.2",
    description:
      "Counts the hosts matching a Shodan search query from the Run dialog (no selection) and reports the total and facet breakdowns (default: country, org, port, product) in the run summary; creates no nodes. Does not spend a query credit; needs a Shodan API key.",
    icon: "chart-bar",
    author: AUTHOR,
    license: "Apache-2.0",
    platforms: WEB,
    params: {
      type: "object",
      properties: {
        query: {
          type: "string",
          title: "Query",
          minLength: 1,
          description: 'Shodan search query, e.g. org:"Example Corp" or product:nginx country:KR.',
        },
        facets: {
          type: "string",
          title: "Facets",
          default: "country:5,org:5,port:5,product:5",
          description: "Comma-separated facet:count pairs; country:5,org:5,port:5,product:5 if not given. An empty string returns the total only.",
        },
      },
      required: ["query"],
    },
    io: { consumes: [], produces: [] },
    scopes: {
      network: [
        {
          endpoint: "https://api.shodan.io/shodan/host/count",
          methods: ["GET"],
          purpose: "Count the hosts matching a query on Shodan.",
        },
      ],
      config: KEY_CONFIG,
    },
    lifecycle: { persistence: "ephemeral", controls: ["cancel"] },
  },
  async run(ctx) {
    if (!apiKey(ctx)) return { summary: NO_KEY, counts: {} };
    const query = String((ctx.params && ctx.params.query) || "").trim();
    if (!query) return { summary: "Enter a Shodan search query first.", counts: {} };
    const facets = String((ctx.params && ctx.params.facets) ?? "country:5,org:5,port:5,product:5").trim();

    const r = await shodanGet(ctx, "/shodan/host/count", { query, facets });
    if (!r.ok) return { summary: keyMessage(r), counts: {} };
    const total = Number(r.body && r.body.total) || 0;
    const facetOut = (r.body && r.body.facets) || {};
    // A query with no hits still returns every facet as an empty list; printing those is pure
    // noise on the one result that most needs to read clearly ("0 host(s) match").
    const lines = Object.keys(facetOut)
      .filter((k) => (facetOut[k] || []).length)
      .map((k) => `${k}: ${facetOut[k].map((f) => `${f.value} (${f.count})`).join(", ")}`);
    return {
      summary: `${total.toLocaleString("en-US")} host(s) match "${query}"${lines.length ? ` · ${lines.join(" · ")}` : ""}`,
      counts: { total },
      data: { total, facets: facetOut },
    };
  },
};

// ---- plugin: Shodan DNS Domain -----------------------------------------------------------------

const dnsDomainPlugin = {
  manifest: {
    identifier: "run.vineyard.plugins.shodan_dns_domain",
    content_type: "vineyard:plugin",
    name: "Shodan DNS Domain",
    version: "2.0.1",
    description:
      "Fetches Shodan's passively observed DNS data for each selected Domain: subdomains become Domain nodes (\"subdomain\", up to 150 per domain) and DNS records become DNS Record nodes (\"has record\", up to 300 per domain). Does not spend a query credit; needs a Shodan API key.",
    icon: "waypoints",
    author: AUTHOR,
    license: "Apache-2.0",
    platforms: WEB,
    io: {
      consumes: [io(T_INFRA, "infrastructure", "domain")],
      produces: [io(T_INFRA, "infrastructure", "domain"), io(T_INFRA, "infrastructure", "dns_record")],
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
      config: KEY_CONFIG,
    },
    lifecycle: { persistence: "opt-in", controls: ["progress", "cancel"], progress: "determinate" },
  },
  async run(ctx) {
    if (!apiKey(ctx)) return { summary: NO_KEY, counts: { subdomains: 0, dns_records: 0 } };
    const ids = ctx.input.selection;
    if (!ids.length) return { summary: "Select one or more Domain nodes first", counts: { subdomains: 0, dns_records: 0 } };

    let subdomains = 0;
    let records = 0;
    let truncatedSubs = 0;
    let truncatedRecs = 0;
    let failed = 0;
    let looked = 0;
    for (let i = 0; i < ids.length; i++) {
      if (ctx.signal && ctx.signal.aborted) break;
      const node = await ctx.graph.get(ids[i]);
      if (!node || !isDomain(node)) continue;
      const domain = domainOf(node);
      if (!domain) continue;
      looked++;
      ctx.progress &&
        ctx.progress.set &&
        ctx.progress.set({ percent: Math.round(((i + 1) / ids.length) * 100), message: `Shodan DNS: ${domain}` });
      if (looked > 1) await sleep(PACE_MS);

      const r = await shodanGet(ctx, `/dns/domain/${encodeURIComponent(domain)}`, {});
      if (isBadKey(r)) return { summary: keyMessage(r), counts: {} };
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
        // "*" is a wildcard RULE, not a host, and infrastructure.domain's own regex rejects the
        // character — createNode THROWS on it, killing the run and everything staged with it.
        // Measured against the live API: nmap.org's very first subdomain is "*". Stripping the
        // wildcard prefix is what the free Certificate Transparency plugin does with the same
        // input, so the two agree; a bare "*" collapses to the apex and is skipped as a duplicate.
        const label = String(sub == null ? "" : sub).replace(/^\*\.?/, "").trim();
        const name = label ? `${label}.${domain}` : domain;
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
        const recLabel = String(rec.subdomain == null ? "" : rec.subdomain).replace(/^\*\.?/, "").trim();
        const name = recLabel ? `${recLabel}.${domain}` : domain;
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
      summary: `${subdomains} subdomain(s), ${records} DNS record(s) from ${looked - failed}/${ids.length} domain(s)${notes.length ? ` (${notes.join("; ")})` : ""}`,
      counts: { subdomains, dns_records: records, failed },
    };
  },
};

// ---- plugin: Shodan DNS Resolve ----------------------------------------------------------------

const dnsResolvePlugin = {
  manifest: {
    identifier: "run.vineyard.plugins.shodan_dns_resolve",
    content_type: "vineyard:plugin",
    name: "Shodan DNS Resolve",
    version: "2.0.1",
    description:
      "Resolves each selected Domain to its IP address through Shodan, creating an IP Address node with a \"resolves to\" edge from the domain. Does not spend a query credit; needs a Shodan API key.",
    icon: "arrow-right",
    author: AUTHOR,
    license: "Apache-2.0",
    platforms: WEB,
    io: {
      consumes: [io(T_INFRA, "infrastructure", "domain")],
      produces: [io(T_INFRA, "infrastructure", "ip_address")],
    },
    scopes: {
      graph: ["node:read", "node:create", "edge:create"],
      network: [
        {
          endpoint: "https://api.shodan.io/dns/resolve",
          methods: ["GET"],
          purpose: "Resolve hostnames to IP addresses.",
        },
      ],
      config: KEY_CONFIG,
    },
    lifecycle: { persistence: "opt-in", controls: ["progress", "cancel"], progress: "determinate" },
  },
  async run(ctx) {
    if (!apiKey(ctx)) return { summary: NO_KEY, counts: { ips: 0 } };
    const ids = ctx.input.selection;
    if (!ids.length) return { summary: "Select one or more Domain nodes first", counts: { ips: 0 } };

    // Collect first, request in batches — one call per 25 names instead of one per name.
    const idByName = new Map();
    for (const id of ids) {
      const node = await ctx.graph.get(id);
      if (!node || !isDomain(node)) continue;
      const d = domainOf(node);
      if (d && !idByName.has(d)) idByName.set(d, id);
    }
    const names = [...idByName.keys()];
    if (!names.length) return { summary: "No Domain nodes in the selection", counts: { ips: 0 } };

    const batches = chunk(names, RESOLVE_BATCH);
    let ips = 0;
    let unresolved = 0;
    let failed = 0;
    let sent = 0; // requests actually made, not the batch count planned
    for (let b = 0; b < batches.length; b++) {
      if (ctx.signal && ctx.signal.aborted) break;
      ctx.progress &&
        ctx.progress.set &&
        ctx.progress.set({ percent: Math.round(((b + 1) / batches.length) * 100), message: `Resolving ${batches[b].length} name(s)` });
      if (b > 0) await sleep(PACE_MS);
      const r = await shodanGet(ctx, "/dns/resolve", { hostnames: batches[b].join(",") });
      if (isBadKey(r)) return { summary: keyMessage(r), counts: {} };
      if (!r.ok) {
        // A cancel is not the API failing — reporting it as one sends the analyst looking for a
        // network problem they caused themselves by clicking stop.
        if (r.error !== "cancelled") failed += batches[b].length;
        continue;
      }
      sent++;
      const body = r.body || {};
      for (const name of batches[b]) {
        const ip = body[name];
        // A name Shodan cannot resolve comes back as an explicit null, not a missing key.
        if (!ip || typeof ip !== "string") {
          unresolved++;
          continue;
        }
        const ipNode = await ctx.graph.createNode({
          type: "infrastructure.ip_address",
          data: { ip_address: ip, version: ipVersion(ip) },
        });
        await ctx.graph.createEdge({ from: idByName.get(name), to: String(ipNode.id), label: "resolves to" });
        ips++;
      }
    }
    const notes = [unresolved ? `${unresolved} did not resolve` : "", failed ? `${failed} failed` : ""].filter(Boolean);
    return {
      summary: `${ips} IP(s) from ${names.length} name(s) in ${sent} request(s)${notes.length ? ` (${notes.join("; ")})` : ""}`,
      counts: { ips, unresolved, failed },
    };
  },
};

// ---- plugin: Shodan DNS Reverse ----------------------------------------------------------------

const dnsReversePlugin = {
  manifest: {
    identifier: "run.vineyard.plugins.shodan_dns_reverse",
    content_type: "vineyard:plugin",
    name: "Shodan DNS Reverse",
    version: "2.0.1",
    description:
      "Looks up the PTR hostnames of each selected IP Address through Shodan, creating a Domain node per hostname with a \"resolves to\" edge from the IP, and writes the first hostname to the IP's reverse_dns. Does not spend a query credit; needs a Shodan API key.",
    icon: "arrow-left",
    author: AUTHOR,
    license: "Apache-2.0",
    platforms: WEB,
    io: {
      consumes: [io(T_INFRA, "infrastructure", "ip_address")],
      produces: [io(T_INFRA, "infrastructure", "domain")],
    },
    scopes: {
      graph: ["node:read", "node:create", "node:update", "edge:create"],
      network: [
        {
          endpoint: "https://api.shodan.io/dns/reverse",
          methods: ["GET"],
          purpose: "Look up the PTR hostnames for IP addresses.",
        },
      ],
      config: KEY_CONFIG,
    },
    lifecycle: { persistence: "opt-in", controls: ["progress", "cancel"], progress: "determinate" },
  },
  async run(ctx) {
    if (!apiKey(ctx)) return { summary: NO_KEY, counts: { domains: 0 } };
    const ids = ctx.input.selection;
    if (!ids.length) return { summary: "Select one or more IP Address nodes first", counts: { domains: 0 } };

    const idByIp = new Map();
    for (const id of ids) {
      const node = await ctx.graph.get(id);
      if (!node || !isIp(node)) continue;
      const ip = ipOf(node);
      if (ip && !idByIp.has(ip)) idByIp.set(ip, id);
    }
    const addrs = [...idByIp.keys()];
    if (!addrs.length) return { summary: "No IP Address nodes in the selection", counts: { domains: 0 } };

    const batches = chunk(addrs, RESOLVE_BATCH);
    let domains = 0;
    let none = 0;
    let failed = 0;
    let sent = 0; // requests actually made, not the batch count planned
    for (let b = 0; b < batches.length; b++) {
      if (ctx.signal && ctx.signal.aborted) break;
      ctx.progress &&
        ctx.progress.set &&
        ctx.progress.set({ percent: Math.round(((b + 1) / batches.length) * 100), message: `Reversing ${batches[b].length} address(es)` });
      if (b > 0) await sleep(PACE_MS);
      const r = await shodanGet(ctx, "/dns/reverse", { ips: batches[b].join(",") });
      if (isBadKey(r)) return { summary: keyMessage(r), counts: {} };
      if (!r.ok) {
        if (r.error !== "cancelled") failed += batches[b].length;
        continue;
      }
      sent++;
      const body = r.body || {};
      for (const ip of batches[b]) {
        const names = body[ip];
        // An address with no PTR comes back as an explicit null, not a missing key.
        if (!Array.isArray(names) || !names.length) {
          none++;
          continue;
        }
        const ipId = idByIp.get(ip);
        let first = "";
        for (const raw of names) {
          const name = String(raw || "").trim().toLowerCase();
          if (!name) continue;
          if (!first) first = name;
          const dNode = await ctx.graph.createNode({ type: "infrastructure.domain", data: { domain_name: name } });
          await ctx.graph.createEdge({ from: ipId, to: String(dNode.id), label: "resolves to" });
          domains++;
        }
        // Delta write: only the one field this run established. See writeIp's note.
        if (first && ctx.graph.updateNode) await ctx.graph.updateNode(ipId, { reverse_dns: first });
      }
    }
    const notes = [none ? `${none} had no PTR` : "", failed ? `${failed} failed` : ""].filter(Boolean);
    return {
      summary: `${domains} hostname(s) from ${addrs.length} address(es) in ${sent} request(s)${notes.length ? ` (${notes.join("; ")})` : ""}`,
      counts: { domains, no_ptr: none, failed },
    };
  },
};

// ---- plugin: Shodan API Status -----------------------------------------------------------------

const statusPlugin = {
  manifest: {
    identifier: "run.vineyard.plugins.shodan_api_status",
    content_type: "vineyard:plugin",
    name: "Shodan API Status",
    version: "2.0.1",
    description:
      "Reports the configured Shodan key's plan and remaining query and scan credits in the run summary; runs without a selection and creates no nodes. Does not spend a credit; needs a Shodan API key.",
    icon: "gauge",
    author: AUTHOR,
    license: "Apache-2.0",
    platforms: WEB,
    io: { consumes: [], produces: [] },
    scopes: {
      network: [
        {
          endpoint: "https://api.shodan.io/api-info",
          methods: ["GET"],
          purpose: "Check the configured key's plan and remaining credits.",
        },
      ],
      config: KEY_CONFIG,
    },
    lifecycle: { persistence: "ephemeral", controls: ["cancel"] },
  },
  async run(ctx) {
    if (!apiKey(ctx)) return { summary: NO_KEY, counts: {} };
    const r = await shodanGet(ctx, "/api-info", {});
    if (!r.ok) return { summary: keyMessage(r), counts: {} };
    const b = r.body || {};
    return {
      summary: `Plan: ${b.plan || "unknown"} · ${b.query_credits ?? "?"} query credit(s), ${b.scan_credits ?? "?"} scan credit(s), ${b.monitored_ips ?? 0} monitored IP(s)`,
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
// pluginpack-telegram/dist/pack.mjs); test-plugin.mjs pins this copy against the JSON file so the
// two cannot drift silently.
export default {
  manifest: {
    identifier: "run.vineyard.pluginpacks.shodan",
    content_type: "vineyard:pluginpack",
    name: "Shodan",
    version: "2.0.2",
    description:
      "Shodan REST API lookups: IP host details, host search and result counts, passive DNS, forward and reverse DNS, and API credit status. Needs your own Shodan API key; only Shodan Search spends query credits.",
    author: AUTHOR,
    license: "Apache-2.0",
    icon: "radar",
    platforms: { primary: "web", web: { runtime: "sandbox-js", entry: PACK_ENTRY } },
  },
  plugins: [hostPlugin, searchPlugin, countPlugin, dnsDomainPlugin, dnsResolvePlugin, dnsReversePlugin, statusPlugin],
};
