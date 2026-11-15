// Drives THEIR pot_record_v2 module (never modified) to emit records and verdicts as JSON on stdout.
// usage: node tttps_emit.mjs <path-to-pot_record_v2.(ts|js)> <label>
import { createPrivateKey, createHash } from "node:crypto";
import { pathToFileURL } from "node:url";
import { createRequire } from "node:module";

const [, , modPath, label] = process.argv;
let m;
if (modPath.endsWith(".js")) m = createRequire(import.meta.url)(modPath);
else m = await import(pathToFileURL(modPath).href);
m = { ...(m.default ?? {}), ...m };

const hex = (b) => Buffer.from(b).toString("hex");
const H = (s) => Buffer.from(s, "hex");
const PKCS8 = H("302e020100300506032b657004220420");
const key = (seedHex) => createPrivateKey({ key: Buffer.concat([PKCS8, H(seedHex)]), format: "der", type: "pkcs8" });

// Public deterministic test inputs, copied from draft-helmprotocol-tttps-13 Appendix B.1.
const ISSUER_SEED = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const ISSUER_PUB = H("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
const HOLDER_PUB = H("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
const PSK = H("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
const EXPORTER = H("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
const TS = 2100000000000000n;
const base = {
  algId: 1, tsTaiUs: TS, dispersionUs: 100,
  ctxId: H("00112233445566778899aabbccddeeff"), nonce: H("ffeeddccbbaa99887766554433221100"),
  issuerKeyId: 1001,
};
const issuerKey = key(ISSUER_SEED);
const out = { label, module: modPath, exports: Object.keys(m).sort(), records: {}, flips: {}, freshness: {}, binding: {} };

const mk = (name, f) => {
  const rec = Buffer.from(m.encodePotRecordV2({ ...base, ...f }, issuerKey));
  out.records[name] = { hex: hex(rec), their_verdict: m.verifyPotRecordV2(rec, ISSUER_PUB) };
  // every single-bit mutation of the record (draft-12 Appendix C.5), their verifier, no freshness policy
  const verdicts = [];
  for (let byte = 0; byte < rec.length; byte++) for (let bit = 0; bit < 8; bit++) {
    const x = Buffer.from(rec); x[byte] ^= 1 << bit;
    verdicts.push(m.verifyPotRecordV2(x, ISSUER_PUB).verdict === "rejected" ? 0 : 1); // 1 = their verifier ACCEPTED the mutant
  }
  out.flips[name] = verdicts;
  return rec;
};
const recA = mk("ed25519", { holderAuthType: 1, holderAuthData: HOLDER_PUB });
mk("psk", { holderAuthType: 2, holderAuthData: createHash("sha256").update(PSK).digest() });
mk("other", { holderAuthType: 1, holderAuthData: HOLDER_PUB, tsTaiUs: 1800000000000000n, dispersionUs: 7, issuerKeyId: 0x01020304,
  ctxId: H("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"), nonce: H("0f0e0d0c0b0a09080706050403020100") });

// binding transcript as the package computes it (0.4.7: computeV2BindingInput)
if (m.computeV2BindingInput) out.binding.package_binding_input = hex(m.computeV2BindingInput(recA, EXPORTER));
if (m.computeV2ExporterContext) out.binding.package_exporter_context = hex(m.computeV2ExporterContext(recA));
if (m.computeDraft13BindingInput) {
  out.binding.draft13_binding_input = hex(m.computeDraft13BindingInput(recA, EXPORTER, 0));
  out.binding.draft13_exporter_context = hex(m.computeDraft13ExporterContext(recA, 0));
}

// freshness: record ts = TS; policy "now" is moved around it. (name -> their verdict)
const maxSkew = 500000n, D = 100n;
const fresh = (name, now, skew) => {
  const r = m.verifyPotRecordV2(recA, ISSUER_PUB, { nowTaiUs: now, maxSkewUs: skew });
  out.freshness[name] = { now: now.toString(), skew: skew.toString(), verdict: r.verdict, reason: r.reason ?? null };
};
fresh("future_equal_F", TS - maxSkew, maxSkew);
fresh("future_F_plus_1", TS - maxSkew - 1n, maxSkew);
fresh("past_equal_W_plus_D", TS + maxSkew + D, maxSkew);
fresh("past_W_plus_D_plus_1", TS + maxSkew + D + 1n, maxSkew);
fresh("overflow_W_max", TS + 1n, (1n << 64n) - 1n);
if (m.draft13Freshness) {
  const U = (1n << 64n) - 1n;
  const f = (n, ts, now, d, w, fk) => { out.freshness["d13_" + n] = { ts: ts.toString(), now: now.toString(), D: d.toString(), W: w.toString(), F: fk.toString(), ok: m.draft13Freshness(ts, now, d, w, fk) }; };
  f("future_equal_F", TS, TS - 500000n, 100n, 500000n, 500000n);
  f("future_F_plus_1", TS, TS - 500001n, 100n, 500000n, 500000n);
  f("past_equal_W_plus_D", TS, TS + 500100n, 100n, 500000n, 500000n);
  f("past_W_plus_D_plus_1", TS, TS + 500101n, 100n, 500000n, 500000n);
  f("overflow_W_gt_max_minus_D", TS, TS + 1n, 100n, U, 500000n);
  f("overflow_W_max_minus_D_ok", TS, TS + 1n, 100n, U - 100n, 500000n);
  f("future_with_huge_D", TS, TS - 500001n, 4294967295n, 500000n, 500000n);
}
// draft-13 holder proofs, their verifier on the published vectors (supplied via env as JSON)
if (m.verifyDraft13BindingProof && process.env.D13_VECTORS) {
  const v = JSON.parse(process.env.D13_VECTORS);
  const res = {};
  for (const [k, e] of Object.entries(v)) {
    const rec = H(e.record), proof = H(e.holder_proof);
    const secret = k === "psk" ? PSK : undefined;
    const ok = m.verifyDraft13BindingProof(rec, proof, EXPORTER, 0, secret).verdict;
    const bad = Buffer.from(proof); bad[0] ^= 1;
    const flipped = m.verifyDraft13BindingProof(rec, bad, EXPORTER, 0, secret).verdict;
    const wrongDir = m.verifyDraft13BindingProof(rec, proof, EXPORTER, 1, secret).verdict;
    res[k] = { published: ok, proof_byte_flipped: flipped, direction_1: wrongDir,
      input: hex(m.computeDraft13BindingInput(rec, EXPORTER, 0)), ctx: hex(m.computeDraft13ExporterContext(rec, 0)) };
  }
  out.binding.draft13_proofs = res;
}
process.stdout.write(JSON.stringify(out));
