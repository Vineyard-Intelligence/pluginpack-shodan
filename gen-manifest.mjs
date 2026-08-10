// Regenerates plugins/shodan.manifest.json from the JS literals in dist/pack.mjs.
//
// The two copies have to agree (test-plugin.mjs fails the build if they drift) and the pack is
// hand-written with no bundler, so the only question is which copy is authoritative. It is the JS
// one — that is what actually runs — and this pours it into the JSON the catalog reads.
//
// Run after any manifest edit:  node gen-manifest.mjs
import { writeFileSync } from "node:fs";
import pack from "./dist/pack.mjs";

const doc = { ...pack.manifest, plugins: pack.plugins.map((p) => p.manifest) };
writeFileSync(new URL("./plugins/shodan.manifest.json", import.meta.url), JSON.stringify(doc, null, 2) + "\n");
console.log(`wrote plugins/shodan.manifest.json — ${doc.plugins.length} plugins`);
