// Functional test harness for pluginpack-shodan/dist/pack.mjs (3 plugins).
// Run: node test-plugin.mjs   (or: jsc -m test-plugin.mjs)
import { readFileSync } from "node:fs";
import pack from "./dist/pack.mjs";

// Same dual-runtime shim as pluginpack-telegram/test-plugin.mjs — see its header for why both
// halves are needed rather than just picking one.
const say = typeof console !== "undefined" ? (m) => console.log(m) : print;
const die = () => (typeof process !== "undefined" ? process.exit(1) : quit(1));
if (typeof console === "undefined") {
  globalThis.console = { log: print, warn: print, error: print, info: print, debug: print };
}

const [searchPlugin, dnsPlugin, statusPlugin] = pack.plugins;
const ok = [];
const fail = [];
function check(name, cond) {
  (cond ? ok : fail).push(name);
}

function makeGraph(nodeById) {
  const createdNodes = [];
  const createdEdges = [];
  return {
    createdNodes,
    createdEdges,
    async get(id) {
      return nodeById[id] || null;
    },
    async createNode(draft) {
      const node = { id: `n${createdNodes.length + 1}`, type: draft.type, data: draft.data };
      createdNodes.push(node);
      return node;
    },
    async createEdge(edge) {
      createdEdges.push(edge);
    },
  };
}

// respond(url) -> { ok, status, body } | { status, html } for a non-JSON error page.
function makeNet(respond) {
  const calls = [];
  return {
    calls,
    async fetch(url, init) {
      calls.push(url);
      const r = respond(new URL(url));
      const headers = {};
      return {
        ok: r.status >= 200 && r.status < 300,
        status: r.status,
        headers,
        async text() {
          return r.html ?? JSON.stringify(r.body ?? {});
        },
        async json() {
          if (r.html) throw new SyntaxError("not JSON");
          return r.body ?? {};
        },
      };
    },
  };
}

// ---------------------------------------------------------------- search: no key configured
{
  const ctx = { config: {}, params: { query: "org:test" }, input: { selection: [] }, graph: makeGraph({}) };
  const r = await searchPlugin.run(ctx);
  check("search refuses with no key, before any network call", /No Shodan API key/.test(r.summary));
}

// ---------------------------------------------------------------- search: no query
{
  const ctx = { config: { api_key: "k" }, params: {}, input: { selection: [] }, graph: makeGraph({}) };
  const r = await searchPlugin.run(ctx);
  check("search refuses with no query", /Enter a Shodan search query/.test(r.summary));
}

// ---------------------------------------------------------------- search: rejected key (401, HTML body)
{
  const net = makeNet(() => ({ status: 401, html: "<html>401 Unauthorized</html>" }));
  const ctx = { config: { api_key: "bad" }, params: { query: "org:test" }, input: { selection: [] }, net, graph: makeGraph({}) };
  const r = await searchPlugin.run(ctx);
  check("search: 401 with an HTML body does not throw", /Shodan rejected this key/.test(r.summary));
}

// ---------------------------------------------------------------- search: happy path, two ports on one IP
{
  const matches = [
    {
      ip_str: "1.2.3.4",
      port: 80,
      org: "Example Org",
      asn: "AS64500",
      location: { city: "Springfield", country_code: "US", country_name: "United States", latitude: 1, longitude: 2 },
      hostnames: ["web.example.test"],
      vulns: { "CVE-2021-1234": {}, "not-a-cve": {} },
    },
    { ip_str: "1.2.3.4", port: 443, isp: "Example ISP", os: "Linux" }, // second row, SAME ip, must aggregate not overwrite
    { ip_str: "5.6.7.8", port: 22 }, // a second, unrelated host
  ];
  const net = makeNet((url) => {
    check("search hits /shodan/host/search", url.pathname === "/shodan/host/search");
    check("search sends the key", url.searchParams.get("key") === "k");
    check("search sends the query", url.searchParams.get("query") === "org:test");
    return { status: 200, body: { matches, total: 3 } };
  });
  const graph = makeGraph({});
  const ctx = { config: { api_key: "k" }, params: { query: "org:test" }, input: { selection: [] }, net, graph, signal: { aborted: false } };
  const r = await searchPlugin.run(ctx);

  check("search: exactly 1 network call regardless of match count", net.calls.length === 1);
  check("search: 2 IP nodes (aggregated, not one per port row)", graph.createdNodes.filter((n) => n.type === "infrastructure.ip_address").length === 2);
  const host = graph.createdNodes.find((n) => n.type === "infrastructure.host" && n.data.hostname === "1.2.3.4");
  check("search: ports from BOTH rows of the same IP are on one Host node", host && host.data.open_ports === "80, 443");
  check("search: the second row's `os` survived aggregation onto the first row's host", host && host.data.operating_system === "Linux");
  const asNode = graph.createdNodes.find((n) => n.type === "infrastructure.autonomous_system");
  check("search: AS number parsed from 'AS64500'", asNode && asNode.data.autonomous_system_number === 64500);
  const vulnIds = graph.createdNodes.filter((n) => n.type === "threat.vulnerability").map((n) => n.data.cve_id);
  check("search: a real CVE became a node", vulnIds.includes("CVE-2021-1234"));
  check("search: a vulns key that is not CVE-shaped did not", !vulnIds.includes("NOT-A-CVE") && vulnIds.length === 1);
  const geo = graph.createdNodes.find((n) => n.type === "geo.location");
  check("search: location became a node", geo && geo.data.city === "Springfield");
  check(
    "search: IP -> Host edge label matches the free InternetDB plugin",
    graph.createdEdges.some((e) => e.label === "exposes"),
  );
  check(
    "search: IP -> AS edge label matches the IP Intelligence plugin",
    graph.createdEdges.some((e) => e.label === "announced by"),
  );
  check("search: summary names the query", r.summary.includes("org:test"));
}

// ---------------------------------------------------------------- search: zero matches
{
  const net = makeNet(() => ({ status: 200, body: { matches: [], total: 0 } }));
  const graph = makeGraph({});
  const ctx = { config: { api_key: "k" }, params: { query: "org:nobody" }, input: { selection: [] }, net, graph, signal: { aborted: false } };
  const r = await searchPlugin.run(ctx);
  check("search: zero matches creates nothing", graph.createdNodes.length === 0);
  check("search: zero matches says so plainly", /0 results/.test(r.summary));
}

// ---------------------------------------------------------------- dns: subdomains + records, correct owners
{
  const domainNode = { id: "d1", type: "infrastructure.domain", data: { domain_name: "example.test" } };
  const body = {
    subdomains: ["www", "api"],
    data: [
      { subdomain: "", type: "A", value: "1.2.3.4", options: { ttl: 300 } },
      { subdomain: "www", type: "CNAME", value: "example.test", options: { ttl: 300 } },
      { subdomain: "unlisted", type: "A", value: "9.9.9.9" }, // a record for a name NOT in `subdomains`
    ],
  };
  const net = makeNet((url) => {
    check("dns hits /dns/domain/<domain>", url.pathname === "/dns/domain/example.test");
    return { status: 200, body };
  });
  const graph = makeGraph({ d1: domainNode });
  const ctx = { config: { api_key: "k" }, input: { selection: ["d1"] }, net, graph, signal: { aborted: false } };
  const r = await dnsPlugin.run(ctx);

  const subs = graph.createdNodes.filter((n) => n.type === "infrastructure.domain").map((n) => n.data.domain_name);
  check("dns: subdomains composed as <sub>.<domain>", subs.includes("www.example.test") && subs.includes("api.example.test"));
  check(
    "dns: subdomain edge label matches the free CT-log plugin",
    graph.createdEdges.filter((e) => e.label === "subdomain").length === 2,
  );
  const records = graph.createdNodes.filter((n) => n.type === "infrastructure.dns_record");
  check("dns: apex A record uses the domain itself as record_name", records.some((n) => n.data.record_name === "example.test" && n.data.record_type === "A"));
  check("dns: record edge label matches the free DNS Lookup plugins", graph.createdEdges.some((e) => e.label === "has record"));
  const wwwRecordEdge = graph.createdEdges.find(
    (e) => e.to === records.find((n) => n.data.record_name === "www.example.test").id,
  );
  const wwwNodeId = graph.createdNodes.find((n) => n.data.domain_name === "www.example.test").id;
  check("dns: a record for a listed subdomain edges from THAT subdomain, not the apex", wwwRecordEdge.from === wwwNodeId);
  const unlistedRecordEdge = graph.createdEdges.find(
    (e) => e.to === records.find((n) => n.data.record_name === "unlisted.example.test").id,
  );
  check("dns: a record for an UNLISTED name falls back to the apex node", unlistedRecordEdge.from === "d1");
  check("dns: ttl carried through when present", records.find((n) => n.data.record_type === "A" && n.data.record_name === "example.test").data.ttl === 300);
  check("dns: no ttl field when Shodan gave none", !("ttl" in records.find((n) => n.data.record_name === "unlisted.example.test").data));
}

// ---------------------------------------------------------------- dns: non-domain / no selection are no-ops
{
  const other = { id: "x1", type: "identity.handle", data: { handle: "nobody" } };
  const graph = makeGraph({ x1: other });
  const net = makeNet(() => {
    throw new Error("must not be called for a non-domain node");
  });
  const ctx = { config: { api_key: "k" }, input: { selection: ["x1"] }, net, graph, signal: { aborted: false } };
  const r = await dnsPlugin.run(ctx);
  check("dns: a non-domain selected node triggers no request and creates nothing", graph.createdNodes.length === 0);
}

// ---------------------------------------------------------------- api status
{
  const net = makeNet((url) => {
    check("status hits /api-info", url.pathname === "/api-info");
    return { status: 200, body: { plan: "dev", query_credits: 97, scan_credits: 100, monitored_ips: 0 } };
  });
  const graph = makeGraph({});
  const ctx = { config: { api_key: "k" }, net, graph };
  const r = await statusPlugin.run(ctx);
  check("status: no graph scope means no graph calls happen", graph.createdNodes.length === 0);
  check("status: reports the plan and credits", /dev/.test(r.summary) && /97/.test(r.summary));
  check("status: counts carry the raw numbers for the caller", r.counts.query_credits === 97);
}

// ---------------------------------------------------------------- manifest: JS literal vs. JSON stay in sync
// See pluginpack-telegram/test-plugin.mjs for why this exists: the JS copy in dist/pack.mjs is
// hand-maintained (dynamic `import()` of JSON has inconsistent engine support — see the comment
// above `export default` in dist/pack.mjs), so nothing else catches the two drifting apart.
{
  const json = JSON.parse(readFileSync(new URL("./plugins/shodan.manifest.json", import.meta.url)));
  const stable = (v) =>
    JSON.stringify(v, (_k, x) =>
      x && typeof x === "object" && !Array.isArray(x) ? Object.fromEntries(Object.keys(x).sort().map((k) => [k, x[k]])) : x,
    );

  check("manifest: pack version agrees", json.version === pack.manifest.version);
  check("manifest: pack identifier agrees", json.identifier === pack.manifest.identifier);
  check("manifest: member count agrees", json.plugins.length === pack.plugins.length);
  for (let i = 0; i < json.plugins.length; i++) {
    const a = json.plugins[i];
    const b = pack.plugins[i].manifest;
    check(`${a.identifier}: identifiers agree`, a.identifier === b.identifier);
    check(`${a.identifier}: io agrees`, stable(a.io) === stable(b.io));
    check(`${a.identifier}: scopes agree`, stable(a.scopes) === stable(b.scopes));
    check(`${a.identifier}: params agree`, stable(a.params) === stable(b.params));
    // The one fact the marketplace card shows before anyone reads a word of prose: every plugin
    // here needs the analyst's own key, on every copy of the manifest.
    check(`${a.identifier}: declares a secret config key`, (a.scopes.config || []).some((c) => c.secret));
  }
}

say(`PASS ${ok.length} / ${ok.length + fail.length}`);

if (fail.length) {
  say("FAILED:\n" + fail.map((f) => `  - ${f}`).join("\n"));
  die();
}
