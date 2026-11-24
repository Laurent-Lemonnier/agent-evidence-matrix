// Scores one canonicalization function on the rfc8785 cases of agent-evidence-vectors vectors-a2a-jcs-v01, and probes it
// with four inputs that have no RFC 8785 canonical form at the parse or decode layer (two duplicate members, a surrogate
// written as UTF-8 bytes, a raw 0xFF byte).
//
//   node adapters/jcs_function_score.mjs --source FILE --entry NAME [--decl NAME]... [--bytes] [--module] CORPUS_DIR
//
// --source  the project's own source file (.js, .mjs or .ts; TypeScript is stripped with node:module, nothing rewritten)
// --entry   the function under test
// --decl    further top-level declarations the entry needs (functions, consts, classes), copied verbatim
// --module  import the whole file as a module instead of copying declarations (for a file with imports; its
//           dependencies must already be installed beside it from the project's own lock file)
// --bytes   the entry takes the received bytes (a Uint8Array); otherwise it takes JSON.parse of the bytes read as UTF-8,
//           which is how every caller on this matrix that canonicalizes a parsed value reads its input
//
// A parsed-value entry is given the value each case denotes. Three MUST-REJECT inputs are not JSON (a bare NaN,
// Infinity or -Infinity); JSON.parse cannot read them, so they are given the JavaScript number they name. Their refusal
// is then the function's own: a harness parse that throws is never counted as the function refusing. The entry runs in
// strict mode, as the module it was copied from does, and a returned promise is awaited.
//
// A case passes when a MUST-ACCEPT input gives exactly expected.canonical_utf8_hex, or a MUST-REJECT input at the
// canonicalization layer throws. A probe line says `refused` or `accepted <hex>`; an input with no canonical form that
// is accepted is the finding. Exit 0 when the run completed (whatever it found), 2 when the setup failed.
import { createHash, randomUUID } from "node:crypto";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import * as nodeModule from "node:module";

const args = process.argv.slice(2);
const opt = { decl: [], bytes: false, module: false };
for (let i = 0; i < args.length; i++) {
  const a = args[i];
  if (a === "--source") opt.source = args[++i];
  else if (a === "--entry") opt.entry = args[++i];
  else if (a === "--decl") opt.decl.push(args[++i]);
  else if (a === "--bytes") opt.bytes = true;
  else if (a === "--module") opt.module = true;
  else opt.corpus = a;
}
const die = (msg) => { console.log("SETUP " + msg); process.exit(2); };
if (!opt.source || !opt.entry || !opt.corpus) die("usage: --source FILE --entry NAME [--decl NAME]... [--bytes] [--module] CORPUS_DIR");

const raw = readFileSync(opt.source);
console.log(`node ${process.version}`);
console.log(`source sha256 ${createHash("sha256").update(raw).digest("hex")} entry ${opt.entry} input ${opt.bytes ? "received bytes" : "JSON.parse of the bytes as UTF-8"}`);

let fn;
if (opt.module) {
  const mod = await import(pathToFileURL(resolve(opt.source)).href);
  fn = mod[opt.entry];
} else {
  let text = raw.toString("utf8");
  if (/\.ts$/.test(opt.source)) {
    if (typeof nodeModule.stripTypeScriptTypes !== "function") die("this node has no module.stripTypeScriptTypes");
    text = nodeModule.stripTypeScriptTypes(text);
  }
  // A top-level declaration runs from its first line to the first line that closes it at column 0.
  const grab = (name) => {
    const id = name.replace(/[$]/g, "\\$&");
    if (!/^[A-Za-z_$][\w$]*$/.test(name)) die(`declaration name ${JSON.stringify(name)} is not an identifier`);
    const start = new RegExp(`^(?:export )?(?:(?:async )?function\\*? ${id}(?![\\w$])|const ${id}(?![\\w$])|let ${id}(?![\\w$])|class ${id}(?![\\w$]))`, "m");
    const m = start.exec(text);
    if (!m) die(`declaration ${name} not found`);
    const rest = text.slice(m.index);
    const oneLine = rest.match(/^[^\n]*;[ \t]*(?:\/\/[^\n]*)?\n/);
    if (/^(?:export )?(?:const|let) /.test(rest) && oneLine && !/[{([]\s*$/.test(oneLine[0].split("//")[0])) return oneLine[0].replace(/^export /, "");
    // A declaration whose braces open and close on its first line is that line (a one-line function or class).
    const first = rest.slice(0, rest.indexOf("\n") + 1 || rest.length);
    const opens = (first.match(/{/g) || []).length;
    if (opens > 0 && opens === (first.match(/}/g) || []).length && /}[;)]*[ \t]*(?:\/\/[^\n]*)?\n?$/.test(first)) return first.replace(/^export /, "");
    const end = rest.search(/\n[}\]][;)]*[ \t]*\n/);
    if (end < 0) die(`declaration ${name} has no closing line`);
    return rest.slice(0, rest.indexOf("\n", end + 1) + 1).replace(/^export /, "");
  };
  const body = ['"use strict";', ...opt.decl.map(grab), grab(opt.entry), `return ${opt.entry};`].join("\n");
  fn = new Function(body)();
}
if (typeof fn !== "function") die(`${opt.entry} is not a function`);

// The value a parsed-value entry is given. JSON.parse reads every JSON input; a bare NaN, Infinity or -Infinity outside
// a string (the three non-JSON MUST-REJECT inputs) is read as the number it names. Anything else the harness cannot read
// is a setup failure, never a case the function refused.
const NON_JSON = { NaN: NaN, Infinity: Infinity, "-Infinity": -Infinity };
const MARK = `\u0000${randomUUID()}:`; // no corpus string can collide with it
const denoted = (text) => {
  try { return JSON.parse(text); } catch (first) {
    let out = "", inString = false, marked = false;
    for (let i = 0; i < text.length; i++) {
      const ch = text[i];
      if (inString) { out += ch; if (ch === "\\") out += text[++i] ?? ""; else if (ch === '"') inString = false; continue; }
      if (ch === '"') { inString = true; out += ch; continue; }
      const tok = /^(?:-Infinity|Infinity|NaN)(?![\w$])/.exec(text.slice(i));
      if (tok) { out += JSON.stringify(MARK + tok[0]); i += tok[0].length - 1; marked = true; continue; }
      out += ch;
    }
    if (!marked) throw new HarnessError(first.message);
    try {
      return JSON.parse(out, (k, v) => (typeof v === "string" && v.startsWith(MARK) && v.slice(MARK.length) in NON_JSON ? NON_JSON[v.slice(MARK.length)] : v));
    } catch (e) { throw new HarnessError(e.message); }
  }
};
class HarnessError extends Error {}
const call = async (buf) => {
  const arg = opt.bytes ? new Uint8Array(buf) : denoted(buf.toString("utf8"));
  const out = await fn(arg);
  return Buffer.isBuffer(out) || out instanceof Uint8Array ? Buffer.from(out) : Buffer.from(String(out), "utf8");
};
const errText = (e) => { try { return (e && e.message) || String(e); } catch { return "an unprintable value was thrown"; } };

const files = [];
(function walk(d) {
  for (const n of readdirSync(d)) {
    const p = join(d, n);
    if (statSync(p).isDirectory()) walk(p);
    else if (/\/a\d[^/]*\/[^/]+\.json$/.test(p)) files.push(p);
  }
})(opt.corpus);
let scored = 0, pass = 0;
const fails = [];
for (const f of files.sort()) {
  if (f.includes("/a2-signatures-exclusion/")) continue; // card-signing-input target, not rfc8785
  const c = JSON.parse(readFileSync(f, "utf8"));
  const accept = c.disposition === "MUST-ACCEPT" && c.expected && c.expected.canonical_utf8_hex;
  const reject = c.disposition === "MUST-REJECT" && c.rejection_layer === "canonicalization";
  if (!accept && !reject) continue;
  scored++;
  // The bytes the corpus harness writes: input_raw as UTF-8 (a lone surrogate escape stays an escape), else the
  // parsed input re-serialized.
  const input = Buffer.from("input_raw" in c ? c.input_raw : JSON.stringify(c.input), "utf8");
  let out = null, err = null;
  try { out = (await call(input)).toString("hex"); } catch (e) {
    if (e instanceof HarnessError) die(`case ${c.id}: the harness cannot read its input as a parsed value (${e.message})`);
    err = errText(e);
  }
  const ok = accept ? out === c.expected.canonical_utf8_hex : err !== null;
  if (ok) pass++;
  else fails.push(`FAIL ${c.id} ${accept ? "MUST-ACCEPT" : "MUST-REJECT"} got=${err !== null ? "REFUSED " + err : out}`);
}
for (const line of fails) console.log(line);
if (scored === 0) die(`no rfc8785 case found under ${opt.corpus}: a run that scored nothing is not a result`);
console.log(`scored=${scored} pass=${pass} fail=${scored - pass} (rfc8785 cases of ${opt.corpus.replace(/.*\//, "")})`);

const PROBES = [
  ["duplicate-member", Buffer.from('{"a":1,"a":2}', "utf8")],
  ["duplicate-member-name", Buffer.from('{"name":"Good","name":"Evil"}', "utf8")],
  ["surrogate-as-utf8-bytes", Buffer.from("7b2261223a22eda080227d", "hex")],
  ["invalid-utf8-ff", Buffer.from("7b2261223a22ff227d", "hex")],
];
let refusedAll = true;
for (const [name, buf] of PROBES) {
  let line;
  try { line = `accepted ${(await call(buf)).toString("hex")}`; refusedAll = false; } catch (e) {
    if (e instanceof HarnessError) die(`probe ${name}: the harness cannot read it as a parsed value (${e.message})`);
    line = "refused";
  }
  console.log(`PROBE ${name} input=${buf.toString("hex")} ${line}`);
}
console.log(`PROBES ${refusedAll ? "all 4 refused" : "an input with no canonical form was accepted"}`);
