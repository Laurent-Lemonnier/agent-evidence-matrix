// Adapter: the canonicalize() function of xkumakichi/xaip-protocol docs/spec/test-vectors/check.mjs behind the
// a2a-jcs-v01 verifier contract (agent-evidence-vectors docs/reference/corpus-readers.md):
//   <verifier> rfc8785 <input.json>   exit 0 and {"canonical_utf8_hex": ...} on stdout,
//                                     exit 1 when the input has no canonical form.
// The function's source is read verbatim from check.mjs in the checkout named by XAIP_ROOT (the run file names the
// commit) and evaluated alone; the input is parsed with JSON.parse, as check.mjs reads its own vectors.
// Nothing of ours is mixed in.
import { readFileSync } from "node:fs";
import { join } from "node:path";

const src = readFileSync(join(process.env.XAIP_ROOT, "docs/spec/test-vectors/check.mjs"), "utf8");
const m = src.match(/function canonicalize\(value\) \{[\s\S]*?\n\}\n/);
if (!m) { console.error("canonicalize() not found in check.mjs"); process.exit(2); }
const canonicalize = new Function(m[0] + "\nreturn canonicalize;")();
const [mode, file] = process.argv.slice(2);
if (process.argv.length !== 4 || !["rfc8785", "card-signing-input"].includes(mode)) {
  console.error("usage: xaip_jcs_cli.mjs rfc8785 <input.json>");
  process.exit(2);
}
let out;
try {
  out = canonicalize(JSON.parse(readFileSync(file, "utf8")));
} catch (e) {
  console.error(e.name);
  process.exit(1);
}
console.log(JSON.stringify({ canonical_utf8_hex: Buffer.from(out, "utf8").toString("hex") }));
