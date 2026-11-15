"""Adapter: proofbundle content-root vectors (b7n0de/proofbundle conformance corpus), recomputed from the spec text.

Reads, from a proofbundle checkout (argument 1), the 12 `content_root_vector` cases under
conformance/action_chain_content_roots/ and the 3 `decision_crossimpl` cases under conformance/decision/crossimpl/,
and recomputes every axis we can derive from docs/adr/0002-universal-content-root.md without their code:

  jcs-sha256-v1        content root = SHA-256 over the RFC 8785 bytes of the full Statement (ADR 0002 Decision 1)
  legacy-sortkeys-json-v0
                       UTF-8 of json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False)
                       (ADR 0002 Activation 1, "The legacy byte form, exactly")
  binding check        read top-level contentRootAlg; absent selects legacy; unknown is not ok; the binding holds iff
                       the payload bytes equal the declared algorithm's serialization (ADR 0002 Activation 1)
  envelope invariance  root over the DSSE payload bytes, never the envelope (ADR 0002 Decision 3)
  evidenceRefs         some predicate.evidenceRefs[].digest.sha256 equals the evidence root
  OpenTimestamps       for a decision_crossimpl case with an .ots file: the file digest equals SHA-256 of
                       decision_receipt.jcs, and walking the proof's operations reaches each attestation; a
                       BitcoinBlockHeaderAttestation is confirmed when the reached message equals the relying-party
                       merkle root in expected.anchor.rpTrust (the proof format is the public OpenTimestamps
                       serialization; this walker is ours, written from that format)

The decision predicate findings count (their schema validator) is not recomputed here; their runner covers it.
Prints one line per case and a summary; exit 0 iff every recomputed axis equals the case's `expected` block.
"""
import base64
import hashlib
import json
import pathlib
import sys

import rfc8785

JCS = "jcs-sha256-v1"
LEGACY = "legacy-sortkeys-json-v0"


def sha(b):
    return hashlib.sha256(b).hexdigest()


def jcs(obj):
    return rfc8785.dumps(obj)


def legacy(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def load(p):
    return json.loads(p.read_bytes().decode("utf-8"))


def binding(payload):
    stmt = json.loads(payload.decode("utf-8"))
    alg = stmt.get("contentRootAlg", LEGACY) if isinstance(stmt, dict) else None
    if alg == JCS:
        return payload == jcs(stmt), alg
    if alg == LEGACY:
        return payload == legacy(stmt), alg
    return False, alg


def binds(decision, evidence_root):
    refs = (decision.get("predicate") or {}).get("evidenceRefs") or []
    return any(((r.get("digest") or {}).get("sha256")) == evidence_root for r in refs if isinstance(r, dict))


# ---- OpenTimestamps proof walker (format: python-opentimestamps core/serialize.py, op.py, notary.py) ----
OTS_MAGIC = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"
BTC_TAG = bytes.fromhex("0588960d73d71901")
PENDING_TAG = bytes.fromhex("83dfe30d2ef90c8e")


class R:
    def __init__(self, b):
        self.b, self.i = b, 0

    def byte(self):
        v = self.b[self.i]
        self.i += 1
        return v

    def take(self, n):
        v = self.b[self.i:self.i + n]
        if len(v) != n:
            raise ValueError("truncated")
        self.i += n
        return v

    def varuint(self):
        v, s = 0, 0
        while True:
            c = self.byte()
            v |= (c & 0x7F) << s
            s += 7
            if not c & 0x80:
                return v

    def varbytes(self):
        return self.take(self.varuint())


# keccak256 (0x67) is not implemented; a proof that uses it stops with "unsupported op".
UNARY = {0x08: lambda m: hashlib.sha256(m).digest(), 0x02: lambda m: hashlib.sha1(m).digest(),
         0x03: lambda m: hashlib.new("ripemd160", m).digest(), 0xF2: lambda m: m[::-1], 0xF3: lambda m: m.hex().encode()}


def walk(r, msg, out):
    def tag_step(tag):
        if tag == 0x00:
            t = r.take(8)
            payload = r.varbytes()
            pr = R(payload)
            if t == BTC_TAG:
                out.append(("bitcoin", pr.varuint(), msg))
            elif t == PENDING_TAG:
                out.append(("pending", pr.varbytes().decode("utf-8", "replace"), msg))
            else:
                out.append(("unknown:" + t.hex(), None, msg))
            return
        if tag == 0xF0:
            nm = msg + r.varbytes()
        elif tag == 0xF1:
            nm = r.varbytes() + msg
        elif tag in UNARY:
            nm = UNARY[tag](msg)
        else:
            raise ValueError("unsupported op 0x%02x" % tag)
        walk(r, nm, out)

    tag = r.byte()
    while tag == 0xFF:
        tag_step(r.byte())
        tag = r.byte()
    tag_step(tag)


def ots_verdict(ots_bytes, file_digest_hex, rp_roots):
    r = R(ots_bytes)
    if r.take(len(OTS_MAGIC)) != OTS_MAGIC:
        return "malformed", "bad magic"
    if r.varuint() != 1:
        return "malformed", "version"
    if r.byte() != 0x08:
        return "malformed", "file hash op is not sha256"
    digest = r.take(32)
    if digest.hex() != file_digest_hex:
        return "digest_mismatch", digest.hex()
    atts = []
    walk(r, digest, atts)
    btc = [a for a in atts if a[0] == "bitcoin"]
    if btc:
        if not rp_roots:
            return "needs_rp_trust", "heights %s" % [a[1] for a in btc]
        for _, h, m in btc:
            want = rp_roots.get(str(h))
            if want is not None and m.hex() == want:
                return "confirmed", "height %d" % h
        return "block_mismatch", "heights %s" % [a[1] for a in btc]
    return "pending", "%d pending attestation(s)" % len([a for a in atts if a[0] == "pending"])


# ---- case kinds ----
def content_root_case(d, c):
    e, mode, got = c["expected"], c["mode"], {}
    if mode == "canonical":
        obj = load(d / c["input"])
        jb = (d / e["jcsFile"]).read_bytes()
        got["contentRoot"] = sha(jcs(obj))
        got["objectAndBytesAgree"] = jcs(obj) == jb and sha(jb) == got["contentRoot"]
    elif mode == "pair_reference":
        dec, ev = load(d / c["input"]), load(d / "evidence.json")
        got["decisionRoot"] = sha(jcs(dec))
        got["evidenceRoot"] = sha(jcs(ev))
        got["evidenceRefBindsRoot"] = binds(dec, got["evidenceRoot"])
        # the pinned .jcs files must be the RFC 8785 bytes of the .json objects (an axis the case implies by naming them)
        got["_files"] = (d / e["decisionJcsFile"]).read_bytes() == jcs(dec) and \
            (d / e["evidenceJcsFile"]).read_bytes() == jcs(ev)
    elif mode == "envelope_invariance":
        pa = base64.b64decode(load(d / c["input"])["payload"], validate=True)
        pb = base64.b64decode(load(d / e["secondEnvelope"])["payload"], validate=True)
        got["contentRoot"] = sha(pa) if pa == pb else "PAYLOADS DIFFER"
    elif mode == "binding":
        ok, alg = binding((d / c["input"]).read_bytes())
        got["bindingOk"], got["alg"] = ok, alg
    else:
        return None
    return got


def crossimpl_case(d, c):
    e, got = c["expected"], {}
    dj, ej = (d / "decision_receipt.json"), (d / "evidence_eval_result.json")
    dec, ev = load(dj), load(ej)
    dbytes, ebytes = jcs(dec), jcs(ev)
    got["jcs_byte_identical"] = dbytes == (d / "decision_receipt.jcs").read_bytes() and \
        ebytes == (d / "evidence_eval_result.jcs").read_bytes()
    got["decision_content_root"], got["evidence_content_root"] = sha(dbytes), sha(ebytes)
    m = load(d / "MANIFEST.json")
    got["content_roots_match_manifest"] = m.get("decision_content_root_sha256") == got["decision_content_root"] and \
        m.get("evidence_content_root_sha256") == got["evidence_content_root"]
    got["evidence_ref_binds_content_root"] = binds(dec, got["evidence_content_root"])
    ea = e.get("anchor")
    if ea is not None and (d / "decision_receipt.jcs.ots").exists():
        rp = ((ea.get("rpTrust") or {}).get("bitcoinBlockHeaderMerkleRootsByHeight")) or {}
        status, why = ots_verdict((d / "decision_receipt.jcs.ots").read_bytes(),
                                  sha((d / "decision_receipt.jcs").read_bytes()), rp)
        got["anchor.status"] = status
        got["_anchor_note"] = why
    return got


def compare(c, got):
    e = c["expected"]
    diffs = []
    if got.get("_files") is False:
        diffs.append("pinned .jcs file is not the RFC 8785 form of its .json")
    for k, v in got.items():
        if k.startswith("_"):
            continue
        if k == "anchor.status":
            want = e["anchor"]["status"]
        else:
            want = e.get(k)
        if want != v:
            diffs.append("%s want %r got %r" % (k, want, v))
    return diffs


def main(argv):
    root = pathlib.Path(argv[1])
    man = load(root / "conformance" / "manifest.json")
    n = ok = 0
    axes = 0
    for rel in man["cases"]:
        d = root / "conformance" / rel
        c = load(d / "case.json")
        if c["kind"] == "content_root_vector":
            got = content_root_case(d, c)
        elif c["kind"] == "decision_crossimpl":
            got = crossimpl_case(d, c)
        else:
            continue
        n += 1
        diffs = compare(c, got)
        axes += len([k for k in got if not k.startswith("_")])
        note = (" [anchor: %s]" % got["_anchor_note"]) if "_anchor_note" in got else ""
        if diffs:
            print("DIFF  %s %s: %s" % (c["caseId"], c["kind"], "; ".join(diffs)))
        else:
            ok += 1
            print("AGREE %s %s (%d axes)%s" % (c["caseId"], c["kind"], len([k for k in got if not k.startswith('_')]), note))
    print("SUMMARY %d of %d cases agree on every recomputed axis (%d axes); decision_predicate_findings and "
          "schema_conformant not recomputed (their validator)" % (ok, n, axes))
    return 0 if ok == n else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
