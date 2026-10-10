// Functional test harness for pluginpack-shodan/dist/pack.mjs (7 plugins).
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

const [hostPlugin, searchPlugin, countPlugin, dnsDomainPlugin, dnsResolvePlugin, dnsReversePlugin, statusPlugin] =
  pack.plugins;
const ok = [];
const fail = [];
function check(name, cond) {
  (cond ? ok : fail).push(name);
}

function makeGraph(nodeById) {
  const createdNodes = [];
  const createdEdges = [];
  const updates = [];
  return {
    createdNodes,
    createdEdges,
    updates,
    async get(id) {
      return nodeById[id] || null;
    },
    async createNode(draft) {
      const node = { id: `n${createdNodes.length + 1}`, type: draft.type, data: draft.data };
      createdNodes.push(node);
      return node;
    },
    async updateNode(id, data) {
      updates.push({ id, data });
    },
    async createEdge(edge) {
      createdEdges.push(edge);
    },
  };
}

// respond(url) -> { status, body } | { status, html } for a non-JSON error page.
function makeNet(respond) {
  const calls = [];
  return {
    calls,
    async fetch(url) {
      calls.push(url);
      const r = respond(new URL(url));
      return {
        ok: r.status >= 200 && r.status < 300,
        status: r.status,
        headers: {},
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

const RUN = { signal: { aborted: false } };
const KEY = { api_key: "k" };

// ================================================================ every plugin refuses with no key
{
  for (const p of pack.plugins) {
    const net = makeNet(() => {
      throw new Error("must not reach the network without a key");
    });
    const ctx = { config: {}, params: { query: "x" }, input: { selection: ["a"] }, net, graph: makeGraph({}), ...RUN };
    const r = await p.run(ctx);
    check(`${p.manifest.identifier}: refuses with no key, before any network call`, /No Shodan API key/.test(r.summary));
  }
}

// ================================================================ shodan_host
{
  // Measured shape of /shodan/host/{ip}: flat geo at the top level (NOT nested in `location` like a
  // search match), `vulns` a flat ARRAY of ids (NOT an object), ports already unioned across data[].
  const body = {
    ip_str: "45.33.32.156",
    ports: [80, 22],
    vulns: ["CVE-2021-1234", "not-a-cve"],
    hostnames: ["scanme.nmap.org", "extra.example.test"],
    domains: ["nmap.org"],
    tags: ["cloud"],
    asn: "AS63949",
    org: "Akamai",
    isp: "Akamai Technologies",
    os: "Ubuntu",
    city: "Fremont",
    region_code: "CA",
    country_code: "US",
    country_name: "United States",
    latitude: 37.5,
    longitude: -121.9,
    data: [
      { port: 22, product: "OpenSSH", version: "6.6.1p1" },
      { port: 80, product: "Apache httpd", version: "2.4.7" },
    ],
  };
  const ipNode = { id: "ip1", type: "infrastructure.ip_address", data: { ip_address: "45.33.32.156" } };
  const net = makeNet((url) => {
    check("host: hits /shodan/host/<ip>", url.pathname === "/shodan/host/45.33.32.156");
    return { status: 200, body };
  });
  const graph = makeGraph({ ip1: ipNode });
  const r = await hostPlugin.run({ config: KEY, input: { selection: ["ip1"] }, net, graph, ...RUN });

  check("host: enriches the SELECTED ip node instead of creating a second", graph.updates.length === 1 && graph.updates[0].id === "ip1");
  check("host: no new ip_address node was created", !graph.createdNodes.some((n) => n.type === "infrastructure.ip_address"));
  const upd = (graph.updates[0] || {}).data || {}; // a failed update assertion above must not crash the rest
  check("host: asn written back onto the ip node as the integer the type pack declares", upd.asn === 63949);
  check("host: organization written back", upd.organization === "Akamai");
  check("host: reverse_dns takes the first hostname", upd.reverse_dns === "scanme.nmap.org");
  const h = graph.createdNodes.find((n) => n.type === "infrastructure.host");
  check("host: open ports sorted onto one Host node", h && h.data.open_ports === "22, 80");
  check("host: os carried through", h && h.data.operating_system === "Ubuntu");
  const vulns = graph.createdNodes.filter((n) => n.type === "threat.vulnerability").map((n) => n.data.cve_id);
  check("host: vulns given as a flat ARRAY are read (the /host/{ip} spelling)", vulns.includes("CVE-2021-1234"));
  check("host: a non-CVE entry in vulns is dropped", vulns.length === 1);
  const geo = graph.createdNodes.find((n) => n.type === "geo.location");
  check("host: FLAT top-level geo fields become a Location (not nested under `location`)", geo && geo.data.city === "Fremont" && geo.data.latitude === 37.5);
  const as = graph.createdNodes.find((n) => n.type === "infrastructure.autonomous_system");
  check("host: AS number parsed from 'AS63949'", as && as.data.autonomous_system_number === 63949);
  const domains = graph.createdNodes.filter((n) => n.type === "infrastructure.domain").map((n) => n.data.domain_name);
  check("host: every reverse hostname becomes a Domain", domains.length === 2 && domains.includes("scanme.nmap.org"));
  check("host: the registrable `domains` list is NOT also nodeified (it is derived from hostnames)", !domains.includes("nmap.org"));
  check("host: product/version reported in the summary, not as nodes", /OpenSSH 6\.6\.1p1/.test(r.summary) && !graph.createdNodes.some((n) => n.type === "infrastructure.technologies"));
  check("host: tags reported in the summary", /tags: cloud/.test(r.summary));
}
{
  // 404 is Shodan's normal answer for an IP it has never scanned. It must not read as a failure.
  const net = makeNet(() => ({ status: 404, body: { error: "No information available for that IP." } }));
  const graph = makeGraph({ ip1: { id: "ip1", type: "infrastructure.ip_address", data: { ip_address: "192.0.2.1" } } });
  const r = await hostPlugin.run({ config: KEY, input: { selection: ["ip1"] }, net, graph, ...RUN });
  check("host: an IP Shodan has never seen counts as unknown, not failed", r.counts.unknown === 1 && r.counts.failed === 0);
  check("host: nothing is written for an unknown IP", graph.createdNodes.length === 0 && graph.updates.length === 0);
}
{
  const net = makeNet(() => {
    throw new Error("must not be called for a non-IP node");
  });
  const graph = makeGraph({ d1: { id: "d1", type: "infrastructure.domain", data: { domain_name: "example.test" } } });
  await hostPlugin.run({ config: KEY, input: { selection: ["d1"] }, net, graph, ...RUN });
  check("host: a selected non-IP node triggers no request", net.calls.length === 0 && graph.createdNodes.length === 0);
}
{
  // A rejected key must SAY it was rejected. Folding it into a per-item "failed" counter made a
  // typo'd key indistinguishable from "Shodan has no data on these", over the whole selection.
  const nodes = {};
  const selection = [];
  for (let i = 0; i < 4; i++) {
    nodes[`ip${i}`] = { id: `ip${i}`, type: "infrastructure.ip_address", data: { ip_address: `1.2.3.${i}` } };
    selection.push(`ip${i}`);
  }
  for (const [name, plugin, sel] of [
    ["host", hostPlugin, selection],
    ["dns_reverse", dnsReversePlugin, selection],
  ]) {
    const net = makeNet(() => ({ status: 401, html: "<html>401 Unauthorized</html>" }));
    const r = await plugin.run({ config: KEY, input: { selection: sel }, net, graph: makeGraph(nodes), ...RUN });
    check(`${name}: a 401 with an HTML body does not throw`, typeof r.summary === "string");
    check(`${name}: a rejected key says so instead of counting 4 mystery failures`, /rejected this key/.test(r.summary));
    check(`${name}: a rejected key stops the run instead of retrying every selected node`, net.calls.length === 1);
  }
  const dnodes = { d1: { id: "d1", type: "infrastructure.domain", data: { domain_name: "a.test" } }, d2: { id: "d2", type: "infrastructure.domain", data: { domain_name: "b.test" } } };
  for (const [name, plugin] of [["dns_domain", dnsDomainPlugin], ["dns_resolve", dnsResolvePlugin]]) {
    const net = makeNet(() => ({ status: 401, html: "<html>401</html>" }));
    const r = await plugin.run({ config: KEY, input: { selection: ["d1", "d2"] }, net, graph: makeGraph(dnodes), ...RUN });
    check(`${name}: a rejected key says so`, /rejected this key/.test(r.summary));
    check(`${name}: a rejected key stops the run`, net.calls.length === 1);
  }
}

{
  // The cap that keeps a page of results readable. Ranked by CVSS so what survives is the part
  // worth looking at, and what is dropped is COUNTED — a silent truncation reads as "this host has
  // 25 CVEs", which is a different and false claim.
  const many = {};
  for (let i = 0; i < 40; i++) many[`CVE-2020-${1000 + i}`] = { cvss_v2: i / 10 }; // 0.0 … 3.9
  many["CVE-2019-9999"] = { cvss_v3: 9.8 }; // the one that matters, mentioned last
  const body = { ip_str: "1.2.3.4", ports: [80], data: [{ port: 80, vulns: many }], vulns: Object.keys(many) };
  const net = makeNet(() => ({ status: 200, body }));
  const graph = makeGraph({ ip1: { id: "ip1", type: "infrastructure.ip_address", data: { ip_address: "1.2.3.4" } } });
  const r = await hostPlugin.run({ config: KEY, input: { selection: ["ip1"] }, net, graph, ...RUN });
  const vulns = graph.createdNodes.filter((n) => n.type === "threat.vulnerability");
  check("host: CVEs are capped per host", vulns.length === 25);
  check("host: the cap keeps the HIGHEST CVSS, not the first 25 seen", vulns[0].data.cve_id === "CVE-2019-9999");
  check("host: cvss_v3 is read when there is no plain `cvss` field", vulns[0].data.cvss_score === 9.8);
  check("host: cvss_v2 is read as a fallback", vulns[1].data.cvss_score === 3.9);
  check("host: what the cap dropped is reported, not silently vanished", /16 lower-CVSS CVE\(s\) omitted/.test(r.summary));
  check("host: a score found in a service detail is not lost to the bare top-level id list", vulns.every((n) => n.data.cvss_score !== undefined));
}

{
  // Every defect the adversarial review confirmed, pinned as the input that produced it.
  const net = makeNet(() => ({
    status: 200,
    body: {
      ip_str: "1.2.3.4",
      ports: [443],
      // The measured flat-ARRAY spelling: bare ids, NO detail object anywhere.
      vulns: ["CVE-2021-44228"],
      asn: "AS13335",
      country_code: "KR",
      country_name: "South Korea",
      latitude: 37.5,
      longitude: 127,
      data: [{ port: 443 }],
    },
  }));
  const graph = makeGraph({ ip1: { id: "ip1", type: "infrastructure.ip_address", data: { ip_address: "1.2.3.4" } } });
  await hostPlugin.run({ config: KEY, input: { selection: ["ip1"] }, net, graph, ...RUN });

  const v = graph.createdNodes.find((n) => n.type === "threat.vulnerability");
  // Number(null) is 0 and 0 is FINITE, so a bare id used to score 0.0 — the CVSS "None" band. The
  // graph would have asserted that Log4Shell is harmless, and ranked it last for the MAX_CVES cap.
  check("cvss: a bare CVE id with no detail carries NO score, rather than 0", v && !("cvss_score" in v.data));
  const as = graph.createdNodes.find((n) => n.type === "infrastructure.autonomous_system");
  // autonomous_system.country_code is declared "country of registration"; Shodan gives the country
  // THIS IP geolocates in. The AS node's identity is the ASN alone, so writing it would let one
  // Cloudflare IP in Seoul rewrite AS13335's registered country for every pack that reads it.
  check("as: the IP's geolocated country is NOT stamped on the shared AS node", as && !("country_code" in as.data));
  // No city and no region: the label would fall back to a bare "KR", a country-sized hub pinned at
  // one host's coordinates that every KR host in the run then merges into.
  check("geo: no location node when there is no city or region to name it", !graph.createdNodes.some((n) => n.type === "geo.location"));
}
{
  // One ASN across many IPs is ONE node, and the summary must count nodes, not IPs.
  const matches = [
    { ip_str: "1.1.1.1", port: 80, asn: "AS13335" },
    { ip_str: "1.0.0.1", port: 80, asn: "AS13335" },
  ];
  const net = makeNet(() => ({ status: 200, body: { matches, total: 2 } }));
  const graph = makeGraph({});
  const r = await searchPlugin.run({ config: KEY, params: { query: "q" }, input: { selection: [] }, net, graph, ...RUN });
  check("as: two IPs on one ASN produce ONE AS node", graph.createdNodes.filter((n) => n.type === "infrastructure.autonomous_system").length === 1);
  check("as: ...and the summary says 1 AS, not 2", r.counts.autonomous_systems === 1);
  check("as: both IPs still edge to it", graph.createdEdges.filter((e) => e.label === "announced by").length === 2);
}
{
  // Measured live: nmap.org's FIRST subdomain from /dns/domain is "*". infrastructure.domain's
  // regex has no "*", so createNode THROWS on it and takes the whole run down with everything
  // already staged. The free CT-log plugin strips the wildcard prefix; match it.
  const net = makeNet(() => ({
    status: 200,
    body: { subdomains: ["*", "www"], data: [{ subdomain: "*", type: "A", value: "1.2.3.4" }] },
  }));
  const graph = makeGraph({ d1: { id: "d1", type: "infrastructure.domain", data: { domain_name: "nmap.org" } } });
  await dnsDomainPlugin.run({ config: KEY, input: { selection: ["d1"] }, net, graph, ...RUN });
  const names = graph.createdNodes.filter((n) => n.type === "infrastructure.domain").map((n) => n.data.domain_name);
  check('dns_domain: a "*" wildcard never becomes a domain node', !names.some((n) => n.includes("*")));
  check("dns_domain: it collapses to the apex and is skipped, leaving the real subdomain", names.join() === "www.nmap.org");
  const rec = graph.createdNodes.find((n) => n.type === "infrastructure.dns_record");
  check("dns_domain: a wildcard record anchors to the apex under the apex's own name", rec.data.record_name === "nmap.org");
}

// ================================================================ shodan_search
{
  const matches = [
    {
      ip_str: "1.2.3.4",
      port: 80,
      org: "Example Org",
      asn: "AS64500",
      location: { city: "Springfield", country_code: "US", country_name: "United States", latitude: 1, longitude: 2 },
      hostnames: ["web.example.test"],
      vulns: { "CVE-2021-1234": {}, "not-a-cve": {} }, // the OBJECT spelling, only on search matches
    },
    { ip_str: "1.2.3.4", port: 443, isp: "Example ISP", os: "Linux" }, // second row, SAME ip, must aggregate not overwrite
    { ip_str: "5.6.7.8", port: 22 },
  ];
  const net = makeNet((url) => {
    check("search: hits /shodan/host/search", url.pathname === "/shodan/host/search");
    check("search: sends the key", url.searchParams.get("key") === "k");
    check("search: sends the query", url.searchParams.get("query") === "org:test");
    check("search: page 1 is not sent as a parameter", !url.searchParams.has("page"));
    return { status: 200, body: { matches, total: 3 } };
  });
  const graph = makeGraph({});
  const r = await searchPlugin.run({ config: KEY, params: { query: "org:test" }, input: { selection: [] }, net, graph, ...RUN });

  check("search: exactly 1 network call regardless of match count", net.calls.length === 1);
  check("search: 2 IP nodes (aggregated, not one per port row)", graph.createdNodes.filter((n) => n.type === "infrastructure.ip_address").length === 2);
  const host = graph.createdNodes.find((n) => n.type === "infrastructure.host" && n.data.hostname === "1.2.3.4");
  check("search: ports from BOTH rows of the same IP land on one Host node", host && host.data.open_ports === "80, 443");
  check("search: the second row's `os` survived aggregation", host && host.data.operating_system === "Linux");
  const asNode = graph.createdNodes.find((n) => n.type === "infrastructure.autonomous_system");
  check("search: AS number parsed from 'AS64500'", asNode && asNode.data.autonomous_system_number === 64500);
  const vulnIds = graph.createdNodes.filter((n) => n.type === "threat.vulnerability").map((n) => n.data.cve_id);
  check("search: vulns given as an OBJECT are read (the /host/search spelling)", vulnIds.length === 1 && vulnIds[0] === "CVE-2021-1234");
  const geo = graph.createdNodes.find((n) => n.type === "geo.location");
  check("search: NESTED location becomes a Location node", geo && geo.data.city === "Springfield");
  check("search: IP -> Host edge label matches the free InternetDB plugin", graph.createdEdges.some((e) => e.label === "exposes"));
  check("search: IP -> AS edge label matches the IP Intelligence plugin", graph.createdEdges.some((e) => e.label === "announced by"));
  check("search: summary names the query", r.summary.includes("org:test"));
}
{
  const net = makeNet((url) => {
    check("search: page 2 is passed through", url.searchParams.get("page") === "2");
    return { status: 200, body: { matches: [{ ip_str: "9.9.9.9", port: 53 }], total: 250 } };
  });
  const r = await searchPlugin.run({ config: KEY, params: { query: "q", page: 2 }, input: { selection: [] }, net, graph: makeGraph({}), ...RUN });
  check("search: 'more results' counts the pages already taken", /50 more match/.test(r.summary));
}
{
  const net = makeNet(() => ({ status: 200, body: { matches: [], total: 0 } }));
  const graph = makeGraph({});
  const r = await searchPlugin.run({ config: KEY, params: { query: "org:nobody" }, input: { selection: [] }, net, graph, ...RUN });
  check("search: zero matches creates nothing", graph.createdNodes.length === 0);
  check("search: zero matches says so plainly", /0 results/.test(r.summary));
}
{
  const r = await searchPlugin.run({ config: KEY, params: {}, input: { selection: [] }, graph: makeGraph({}), ...RUN });
  check("search: refuses with no query", /Enter a Shodan search query/.test(r.summary));
}

// ================================================================ fingerprints a service presents
// Field shapes from Shodan's banner schema and Datapedia samples (datapedia.shodan.io, 2026-10): the
// ssl.cert serial is a JSON number (the sample's is 1.908545518767334e+38), validity is ASN.1 time,
// ssh.key is base64 wrapped at 76 columns, ssh.fingerprint is MD5. The SHA-256 below was computed
// with `ssh-keygen -lf` from that same sample key (SHA256:ROQFvPThGrW4RuWLoL9tq9I9zJ42fK4XywyRtbOz/EQ).
const SAMPLE_SSH_KEY =
  "AAAAB3NzaC1yc2EAAAADAQABAAABAQCsj2bNKTBSpIYDEGk9KxsGh3mySTRgMtXL583qmBpzeQ+j\nqCMRgBqB98u3z++J1sKlXHWfM9dyhSevkMwSbhoR8XIq/U0tCNyokEi/ueaBMCvbcTHhO7FcwzY9\n2WK4Yt0aGROY5qX2UKSeOvuP4D6TPqKF1onrSzH9bx9XUf2lEdWT/ia1NEKjunUqu1xOB/StKDHM\noX4/OKyIzuS0q/T1zOATthvasJFoPrAjkohTyaDUz2LN5JoH839hViyEG82yB+MjcFV5MU3N1l1Q\nL3cVUCh93xSaua1N85qivl+siMkPGbO5xR/En4iEY6K2XPASUEMaieWVNTRCtJ4S8H+9\n";
const SAMPLE_SSH_SHA256 = "44e405bcf4e11ab5b846e58ba0bf6dabd23dcc9e367cae17cb0c91b5b3b3fc44";
const GITLAB_CERT = {
  sig_alg: "sha256WithRSAEncryption",
  issued: "20171123000000Z",
  expires: "20190121235959Z",
  version: 2,
  fingerprint: { sha256: "0B1E768B492663D9D236C40DE17BE1A379A2E3146C2AA8890E613FB3095A0D92", sha1: "e19d2258e5f9f5aa35e4c9be2f60c0a34c08492e" },
  serial: 1.908545518767334e38,
  issuer: { C: "GB", ST: "Greater Manchester", CN: "COMODO RSA Domain Validation Secure Server CA", O: "COMODO CA Limited", L: "Salford" },
  subject: { OU: "PositiveSSL", CN: "gitlab.com" },
  extensions: [{ data: "0\\x1c\\x82\\ngitlab.com\\x82\\x0ewww.gitlab.com", name: "subjectAltName" }],
};
const DEVICE_CERT = {
  issued: "20200101000000Z",
  expires: "20300101000000Z",
  fingerprint: { sha256: "c".repeat(64) },
  serial: 4660,
  issuer: { CN: "FortiGate" },
  subject: { CN: "FortiGate" },
};
{
  const body = {
    ip_str: "198.51.100.7",
    ports: [22, 443, 2222, 8443],
    tags: ["cloud", "self-signed"],
    data: [
      { port: 22, product: "OpenSSH", version: "6.6.1p1", ssh: { fingerprint: "b6:03:0e:39:97:9e:d0:e7:24:ce:a3:77:3e:01:42:09", key: SAMPLE_SSH_KEY, type: "ssh-rsa" } },
      { port: 2222, ssh: { key: "not a key blob!", fingerprint: "00:11" } },
      {
        port: 443,
        product: "nginx",
        ssl: { cert: GITLAB_CERT, jarm: "29D29D00029D29D00041D41D00041D2AA5CE6A70DE7BA95AEF77A77B00A0AF" },
        http: { title: " The only single product for the complete DevOps lifecycle - GitLab | GitLab ", favicon: { hash: 516963061, location: "https://about.gitlab.com:443/ico/favicon.ico" } },
      },
      { port: 8443, ssl: { cert: DEVICE_CERT, jarm: "00000000000000000000000000000000000000000000000000000000000000" }, http: { favicon: { hash: -235701012 } } },
      { port: 8444, ssl: { cert: GITLAB_CERT } }, // the same certificate on a second port
      { port: 9000 }, // a service with none of these fields
    ],
  };
  const net = makeNet(() => ({ status: 200, body }));
  const graph = makeGraph({ ip1: { id: "ip1", type: "infrastructure.ip_address", data: { ip_address: "198.51.100.7" } } });
  const r = await hostPlugin.run({ config: KEY, input: { selection: ["ip1"] }, net, graph, ...RUN });
  const of = (t) => graph.createdNodes.filter((n) => n.type === t);
  const edgesTo = (label) => graph.createdEdges.filter((e) => e.label === label && e.from === "ip1");

  const certs = of("infrastructure.certificate");
  const gitlab = certs.find((n) => n.data.subject_common_name === "gitlab.com");
  const device = certs.find((n) => n.data.subject_common_name === "FortiGate");
  check("fp: one certificate node per distinct fingerprint, not per port", certs.length === 2);
  check("fp: certificate identity is the lowercased SHA-256", gitlab && gitlab.data.fingerprint_sha256 === GITLAB_CERT.fingerprint.sha256.toLowerCase());
  check("fp: issuer reads 'O — CN', as VirusTotal writes it", gitlab && gitlab.data.issuer === "COMODO CA Limited — COMODO RSA Domain Validation Secure Server CA");
  check("fp: ASN.1 validity becomes ISO datetimes", gitlab && gitlab.data.not_before === "2017-11-23T00:00:00Z" && gitlab.data.not_after === "2019-01-21T23:59:59Z");
  // A 128-bit serial arrives as a rounded float; written, it would clobber the exact one VT/Censys wrote.
  check("fp: a serial that lost precision in JSON is left out, not rounded", gitlab && !("serial_number" in gitlab.data));
  check("fp: a serial that survived parsing is written in hex", device && device.data.serial_number === "1234");
  check("fp: IP -> certificate edges labelled like Censys Host Lookup", edgesTo("presents certificate").length === 2);

  const favs = of("web.favicon_hash");
  check("fp: favicon hashes keep Shodan's signed MMH3 as Web Recon writes it", favs.map((n) => n.data.hash_value).sort().join() === "-235701012,516963061" && favs.every((n) => n.data.hash_algorithm === "mmh3"));
  check("fp: IP -> favicon edges labelled like Web Recon", edgesTo("has favicon").length === 2);

  const keys = of("infrastructure.ssh_host_key");
  check("fp: SSH host key is SHA-256 of the decoded blob (ssh-keygen's value), not the MD5 fingerprint", keys.length === 1 && keys[0].data.fingerprint_sha256 === SAMPLE_SSH_SHA256);
  check("fp: key type read from the blob", keys[0] && keys[0].data.key_type === "ssh-rsa");
  check("fp: a value that is not a key blob is skipped", !graph.createdNodes.some((n) => /:/.test(String(n.data.fingerprint_sha256 || ""))));
  check("fp: IP -> host key edge labelled like Censys Host Lookup", edgesTo("presents host key").length === 1);

  const upd = (graph.updates[0] || {}).data || {};
  check("fp: Shodan tags written onto the IP", upd.shodan_tags === "cloud, self-signed");
  check("fp: products written per port", upd.shodan_products === "22: OpenSSH 6.6.1p1; 443: nginx");
  check("fp: HTTP title written per port, trimmed", upd.shodan_http_title === "443: The only single product for the complete DevOps lifecycle - GitLab | GitLab");
  check("fp: JARM written per port, and an all-zero JARM (no handshake) is not", upd.shodan_jarm === "443: 29d29d00029d29d00041d41d00041d2aa5ce6a70de7ba95aef77a77b00a0af");
  check("fp: no JARM, tag or product node", !graph.createdNodes.some((n) => /jarm|tag|technolog/.test(n.type)));
  check("fp: summary and counts name what was presented", /2 certificate\(s\), 2 favicon hash\(es\), 1 SSH host key\(s\)/.test(r.summary) && r.counts.certificates === 2 && r.counts.ssh_host_keys === 1);
}
{
  // Search: one row per service, the same certificate on two IPs. Each IP gets its own edge to it;
  // the host merges the two createNode calls into one node by fingerprint.
  const matches = [
    { ip_str: "203.0.113.1", port: 443, tags: ["cdn"], ssl: { cert: GITLAB_CERT, jarm: "2ad2ad0002ad2ad22c42d42d000000faabb8fd156aa8b4d8a37853e1063261" }, http: { title: "Panel", favicon: { hash: 81586312 } } },
    { ip_str: "203.0.113.1", port: 22, ssh: { key: SAMPLE_SSH_KEY } },
    { ip_str: "203.0.113.2", port: 8443, ssl: { cert: GITLAB_CERT } },
  ];
  const net = makeNet(() => ({ status: 200, body: { matches, total: 3 } }));
  const graph = makeGraph({});
  const r = await searchPlugin.run({ config: KEY, params: { query: "ssl.cert.fingerprint:x" }, input: { selection: [] }, net, graph, ...RUN });
  const ips = graph.createdNodes.filter((n) => n.type === "infrastructure.ip_address");
  const ip1 = ips.find((n) => n.data.ip_address === "203.0.113.1");
  const ip2 = ips.find((n) => n.data.ip_address === "203.0.113.2");
  const certIds = new Set(graph.createdNodes.filter((n) => n.type === "infrastructure.certificate" && n.data.fingerprint_sha256 === GITLAB_CERT.fingerprint.sha256.toLowerCase()).map((n) => n.id));
  const certEdges = graph.createdEdges.filter((e) => e.label === "presents certificate" && certIds.has(e.to));
  check("search fp: both IPs present the shared certificate", ip1 && ip2 && certEdges.some((e) => e.from === ip1.id) && certEdges.some((e) => e.from === ip2.id));
  check("search fp: rows of one IP aggregate their favicon and SSH key onto it", graph.createdEdges.some((e) => e.from === ip1?.id && e.label === "has favicon") && graph.createdEdges.some((e) => e.from === ip1?.id && e.label === "presents host key"));
  check("search fp: tags, title and JARM ride on the created IP (search has no node:update)", ip1 && ip1.data.shodan_tags === "cdn" && ip1.data.shodan_http_title === "443: Panel" && /^443: 2ad2ad/.test(ip1.data.shodan_jarm));
  check("search fp: an IP with no such fields gets no empty shodan_* keys", ip2 && !Object.keys(ip2.data).some((k) => k.startsWith("shodan_")));
  check("search fp: counts name what was presented", r.counts.certificates === 2 && r.counts.favicon_hashes === 1 && r.counts.ssh_host_keys === 1);
}
{
  // A host answering on every port: the per-port properties are capped and say how many were left out.
  const data = Array.from({ length: 30 }, (_, i) => ({ port: 1000 + i, product: "tcpwrapped" }));
  const net = makeNet(() => ({ status: 200, body: { ip_str: "192.0.2.9", ports: data.map((d) => d.port), data } }));
  const graph = makeGraph({ ip1: { id: "ip1", type: "infrastructure.ip_address", data: { ip_address: "192.0.2.9" } } });
  await hostPlugin.run({ config: KEY, input: { selection: ["ip1"] }, net, graph, ...RUN });
  const products = (graph.updates[0] || {}).data?.shodan_products || "";
  check("fp: per-port properties are capped at 25 entries, the rest counted", products.split("; ").length === 25 && / \(\+5 more\)$/.test(products));
}

// ================================================================ shodan_count
{
  const net = makeNet((url) => {
    check("count: hits /shodan/host/count", url.pathname === "/shodan/host/count");
    check("count: sends the default facets", url.searchParams.get("facets") === "country:5,org:5,port:5,product:5");
    return { status: 200, body: { total: 820499, matches: [], facets: { port: [{ count: 137818, value: 80 }] } } };
  });
  const graph = makeGraph({});
  const r = await countPlugin.run({ config: KEY, params: { query: "product:nginx" }, input: { selection: [] }, net, graph, ...RUN });
  check("count: writes nothing to the graph", graph.createdNodes.length === 0 && graph.createdEdges.length === 0);
  check("count: reports the total", /820,499 host\(s\)/.test(r.summary));
  check("count: reports facet values", /port: 80 \(137818\)/.test(r.summary));
  check("count: total is machine-readable in counts", r.counts.total === 820499);
}
{
  const net = makeNet((url) => {
    check("count: an explicitly blank facets string is not sent", !url.searchParams.has("facets"));
    return { status: 200, body: { total: 3 } };
  });
  await countPlugin.run({ config: KEY, params: { query: "q", facets: "" }, input: { selection: [] }, net, graph: makeGraph({}), ...RUN });
}

// ================================================================ shodan_dns_domain
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
    check("dns_domain: hits /dns/domain/<domain>", url.pathname === "/dns/domain/example.test");
    return { status: 200, body };
  });
  const graph = makeGraph({ d1: domainNode });
  await dnsDomainPlugin.run({ config: KEY, input: { selection: ["d1"] }, net, graph, ...RUN });

  const subs = graph.createdNodes.filter((n) => n.type === "infrastructure.domain").map((n) => n.data.domain_name);
  check("dns_domain: subdomains composed as <sub>.<domain>", subs.includes("www.example.test") && subs.includes("api.example.test"));
  check("dns_domain: subdomain edge label matches the free CT-log plugin", graph.createdEdges.filter((e) => e.label === "subdomain").length === 2);
  const records = graph.createdNodes.filter((n) => n.type === "infrastructure.dns_record");
  check("dns_domain: apex A record uses the domain itself as record_name", records.some((n) => n.data.record_name === "example.test" && n.data.record_type === "A"));
  check("dns_domain: record edge label matches the free DNS Lookup plugins", graph.createdEdges.some((e) => e.label === "has record"));
  const wwwRecordEdge = graph.createdEdges.find((e) => e.to === records.find((n) => n.data.record_name === "www.example.test").id);
  const wwwNodeId = graph.createdNodes.find((n) => n.data.domain_name === "www.example.test").id;
  check("dns_domain: a record for a listed subdomain edges from THAT subdomain, not the apex", wwwRecordEdge.from === wwwNodeId);
  const unlistedRecordEdge = graph.createdEdges.find((e) => e.to === records.find((n) => n.data.record_name === "unlisted.example.test").id);
  check("dns_domain: a record for an UNLISTED name falls back to the apex node", unlistedRecordEdge.from === "d1");
  check("dns_domain: ttl carried through when present", records.find((n) => n.data.record_type === "A" && n.data.record_name === "example.test").data.ttl === 300);
  check("dns_domain: no ttl field when Shodan gave none", !("ttl" in records.find((n) => n.data.record_name === "unlisted.example.test").data));
}
{
  const graph = makeGraph({ x1: { id: "x1", type: "identity.handle", data: { handle: "nobody" } } });
  const net = makeNet(() => {
    throw new Error("must not be called for a non-domain node");
  });
  await dnsDomainPlugin.run({ config: KEY, input: { selection: ["x1"] }, net, graph, ...RUN });
  check("dns_domain: a non-domain selected node triggers no request and creates nothing", graph.createdNodes.length === 0);
}

// ================================================================ shodan_dns_resolve
{
  // 30 domains -> two batched calls, not thirty. Measured: Shodan takes 25 names in one ?hostnames=.
  const nodeById = {};
  const selection = [];
  for (let i = 0; i < 30; i++) {
    nodeById[`d${i}`] = { id: `d${i}`, type: "infrastructure.domain", data: { domain_name: `h${i}.example.test` } };
    selection.push(`d${i}`);
  }
  const net = makeNet((url) => {
    check("dns_resolve: hits /dns/resolve", url.pathname === "/dns/resolve");
    const names = url.searchParams.get("hostnames").split(",");
    check("dns_resolve: no batch exceeds 25 names", names.length <= 25);
    const body = {};
    // h0 resolves, h1 comes back as an explicit null (Shodan's answer for "no A record").
    for (const n of names) body[n] = n === "h1.example.test" ? null : `10.0.0.${names.indexOf(n)}`;
    return { status: 200, body };
  });
  const graph = makeGraph(nodeById);
  const r = await dnsResolvePlugin.run({ config: KEY, input: { selection }, net, graph, ...RUN });
  check("dns_resolve: 30 names cost 2 requests, not 30", net.calls.length === 2);
  check("dns_resolve: an explicit null counts as unresolved, not as an IP", r.counts.unresolved === 1 && r.counts.ips === 29);
  const e = graph.createdEdges[0];
  check("dns_resolve: edge runs domain -> ip (matching the free A-record lookup)", e.from === "d0" && e.label === "resolves to");
  check("dns_resolve: creates ip_address nodes with a version", graph.createdNodes.every((n) => n.type === "infrastructure.ip_address" && n.data.version === "ipv4"));
}
{
  const graph = makeGraph({ ip1: { id: "ip1", type: "infrastructure.ip_address", data: { ip_address: "1.2.3.4" } } });
  const net = makeNet(() => {
    throw new Error("must not be called with no domain in the selection");
  });
  const r = await dnsResolvePlugin.run({ config: KEY, input: { selection: ["ip1"] }, net, graph, ...RUN });
  check("dns_resolve: an all-IP selection makes no request", net.calls.length === 0 && /No Domain nodes/.test(r.summary));
}

// ================================================================ shodan_dns_reverse
{
  const nodeById = {
    a: { id: "a", type: "infrastructure.ip_address", data: { ip_address: "8.8.8.8" } },
    b: { id: "b", type: "infrastructure.ip_address", data: { ip_address: "192.0.2.1" } },
  };
  const net = makeNet((url) => {
    check("dns_reverse: hits /dns/reverse", url.pathname === "/dns/reverse");
    check("dns_reverse: sends both addresses in one call", url.searchParams.get("ips") === "8.8.8.8,192.0.2.1");
    // 192.0.2.1 comes back as an explicit null — Shodan's answer for "no PTR".
    return { status: 200, body: { "8.8.8.8": ["dns.google", "DNS.GOOGLE."], "192.0.2.1": null } };
  });
  const graph = makeGraph(nodeById);
  const r = await dnsReversePlugin.run({ config: KEY, input: { selection: ["a", "b"] }, net, graph, ...RUN });
  check("dns_reverse: one request for the whole selection", net.calls.length === 1);
  check("dns_reverse: an explicit null counts as no-PTR, not as a failure", r.counts.no_ptr === 1 && r.counts.failed === 0);
  check("dns_reverse: every PTR name becomes a Domain node, lowercased", graph.createdNodes.map((n) => n.data.domain_name).join("|") === "dns.google|dns.google.");
  check("dns_reverse: edge runs ip -> domain (matching the free InternetDB plugin)", graph.createdEdges[0].from === "a" && graph.createdEdges[0].label === "resolves to");
  check("dns_reverse: reverse_dns written back as a DELTA — that field alone", graph.updates.length === 1 && JSON.stringify(graph.updates[0]) === '{"id":"a","data":{"reverse_dns":"dns.google"}}');
}

// ================================================================ shodan_api_status
{
  const net = makeNet((url) => {
    check("status: hits /api-info", url.pathname === "/api-info");
    return { status: 200, body: { plan: "dev", query_credits: 97, scan_credits: 100, monitored_ips: 0 } };
  });
  const graph = makeGraph({});
  const r = await statusPlugin.run({ config: KEY, net, graph, ...RUN });
  check("status: no graph scope means no graph calls happen", graph.createdNodes.length === 0);
  check("status: reports the plan and credits", /dev/.test(r.summary) && /97/.test(r.summary));
  check("status: counts carry the raw numbers for the caller", r.counts.query_credits === 97);
}

// ================================================================ manifest: JS literal vs. JSON
// gen-manifest.mjs pours the JS literals into the JSON, so these agree by construction — this is
// the check that the generator was actually RUN after the last edit.
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
    check(`${a.identifier}: JSON copy is identical to the JS one`, stable(a) === stable(b));
    // The one fact the marketplace card shows before anyone reads a word of prose: every plugin
    // here needs the analyst's own key, on every copy of the manifest.
    check(`${a.identifier}: declares a secret config key`, (a.scopes.config || []).some((c) => c.secret));
    // The defect that made 1.0.0 install cleanly and list NOTHING: a member declaring
    // entry:"inline" is not remote-runnable, and registry.ts drops it without a word.
    check(`${a.identifier}: web entry is the pack module, not "inline"`, a.platforms.web.entry === json.platforms.web.entry && a.platforms.web.entry !== "inline");
    // Every plugin that writes to the graph must say so, or the run silently no-ops on createNode.
    const writes = (a.io.produces || []).length > 0;
    check(`${a.identifier}: graph scope matches whether it produces nodes`, writes === !!(a.scopes.graph || []).includes("node:create"));
  }
}

say(`PASS ${ok.length} / ${ok.length + fail.length}`);

if (fail.length) {
  say("FAILED:\n" + fail.map((f) => `  - ${f}`).join("\n"));
  die();
}
