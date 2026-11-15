"""Reader for the TTTPS 180-octet Proof-of-Time Record v2, written from the draft text.

Spec sources (all captured under _raw/):
  draft-helmprotocol-tttps-12 sections 2.1, 2.2, 2.5 step 3-4 and 7, 6.1, Appendix B.1, Appendix C
  draft-helmprotocol-tttps-13 sections 2.1, 2.6, 4.1, 6.1 and Appendix B (published byte vectors)

usage:
  tttps_pot_adapter.py extract <draft13.txt> <out.json>      parse Appendix B into JSON (their published bytes)
  tttps_pot_adapter.py check   <draft13.txt> <emit-dir>      read the vectors and the records their code emitted

Deterministic: no clock, no randomness, no network.
"""
import hashlib
import hmac
import json
import re
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

U64 = (1 << 64) - 1
ISSUER_PUB = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
HOLDER_PUB = bytes.fromhex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
HOLDER_SEED = bytes.fromhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
PSK = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
EXPORTER = bytes.fromhex("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f")
LABELS = ["record", "integrity_tag", "issuer_signed_bytes", "issuer_signature", "record_hash",
          "exporter_context_hash", "binding_input", "holder_proof", "presentation"]


def sha256(b):
    return hashlib.sha256(b).digest()


# ---------------------------------------------------------------- record layer (draft-12 2.1/2.2, draft-13 2.1/4.1)
def parse_record(r):
    """Fixed layout of draft-12 section 2.1."""
    if len(r) != 180:
        raise ValueError(f"expected 180 octets, got {len(r)}")
    return {
        "version": r[0], "holder_auth_type": r[1], "alg_id": int.from_bytes(r[2:4], "big"),
        "ts": int.from_bytes(r[4:12], "big"), "dispersion": int.from_bytes(r[12:16], "big"),
        "ctx_id": r[16:32], "nonce": r[32:48], "holder_auth_data": r[48:80],
        "integrity_tag": r[80:112], "issuer_key_id": int.from_bytes(r[112:116], "big"),
        "issuer_sig": r[116:180],
    }


def verify_record(r, issuer_pub=ISSUER_PUB, holder_pub=HOLDER_PUB, psk=PSK):
    """Verdict per draft-12 section 2.5 steps 2, 3 and 7 (freshness, replay and holder proof are separate)."""
    try:
        f = parse_record(r)
    except ValueError as e:
        return "rejected", str(e)
    if f["version"] != 2:
        return "rejected", "unknown version"
    if f["holder_auth_type"] not in (1, 2):
        return "rejected", "unsupported holder_auth_type"
    if f["alg_id"] != 1:
        return "rejected", "unsupported alg_id"
    if sha256(r[0:80]) != f["integrity_tag"]:
        return "rejected", "integrity_tag mismatch"
    try:
        Ed25519PublicKey.from_public_bytes(issuer_pub).verify(f["issuer_sig"], r[0:116])
    except InvalidSignature:
        return "rejected", "issuer_sig invalid"
    want = holder_pub if f["holder_auth_type"] == 1 else sha256(psk)
    if f["holder_auth_data"] != want:
        return "rejected", "holder_auth_data differs from the fixture holder"
    return "intact", ""


# ---------------------------------------------------------------- freshness (draft-12 2.5 step 4, draft-13 2.6)
def spec_fresh(ts, now, disp, W, F):
    """True when admitted. Equality is within the window; dispersion never extends the future allowance."""
    if ts > now:
        return ts - now <= F
    if W > U64 - disp:
        return False
    return now - ts <= W + disp


# ---------------------------------------------------------------- binding transcripts
def draft12_binding(record, exporter=EXPORTER):
    rh = sha256(record)
    ctx = sha256(b"tttps-binding-v2" + b"\x00" + rh)                      # draft-12 6.1 context_value
    inp = b"tttps-binding-v2" + b"\x00" + exporter + rh                     # draft-12 6.1 binding_input (81 octets)
    return rh, ctx, inp


def draft13_binding(record, exporter=EXPORTER, direction=0):
    d = b"tttps-binding-v2-draft13"
    rh = sha256(record)
    ctx = sha256(d + b"\x00" + bytes([direction]) + rh)                     # draft-13 6.1 (58-octet hash input)
    inp = d + b"\x00" + bytes([direction]) + exporter + rh                  # 90 octets
    return rh, ctx, inp


# ---------------------------------------------------------------- Appendix B extraction
def extract_vectors(text):
    # the table of contents also lists these headings; the body heading is the last occurrence
    start = text.rindex("Appendix B.  Fixed Cryptographic and Binding Vectors")
    body = text[start:text.index("Appendix C.  Verification Cases", start)]
    out = {}
    for name, head in (("ed25519", "B.2.  Ed25519 Holder Vector"), ("psk", "B.3.  PSK Holder Vector")):
        i = body.index(head)
        j = body.find("B.3.  PSK Holder Vector", i + 1) if name == "ed25519" else len(body)
        vec = {}
        label = None
        for line in body[i:j].splitlines():
            s = line.strip()
            if re.fullmatch(r"[a-z_]+:", s) and s[:-1] in LABELS:
                label = s[:-1]
                vec[label] = ""
            elif label and re.fullmatch(r"[0-9a-f]+", s):
                vec[label] += s
            elif s.startswith("Jorgen ") or s.startswith("Internet-Draft") or not s:
                continue
            else:
                label = None
        out[name] = vec
    common = {}
    i = body.index("B.1.  Common Public Test Inputs")
    seg = body[i:body.index("B.2.  Ed25519 Holder Vector")]
    m = re.search(r"ts = (\d+); dispersion = (\d+); issuer_key_id = (\d+);\s+direction = (\d+)", seg)
    common["ts"], common["dispersion"], common["issuer_key_id"], common["direction"] = (int(x) for x in m.groups())
    lab = None
    for line in seg.splitlines():
        s = line.strip()
        if re.fullmatch(r"[a-z_]+:", s):
            lab = s[:-1]
            common[lab] = ""
        elif lab and re.fullmatch(r"[0-9a-f]+", s):
            common[lab] += s
    out["common"] = common
    return out


# ---------------------------------------------------------------- reporting helpers
class Report:
    def __init__(self):
        self.lines = []
        self.bad = []

    def case(self, name, got, expect, note=""):
        ok = got == expect
        self.lines.append(f"{'match' if ok else 'DIFF '} {name}: got={got} expect={expect}{(' ' + note) if note else ''}")
        if not ok:
            self.bad.append(name)
        return ok

    def say(self, s):
        self.lines.append(s)


def flips_ours(rec):
    """Our verifier over every single-bit mutation: 1 = accepted."""
    out = []
    for byte in range(len(rec)):
        for bit in range(8):
            x = bytearray(rec)
            x[byte] ^= 1 << bit
            out.append(1 if verify_record(bytes(x))[0] == "intact" else 0)
    return out


# ---------------------------------------------------------------- check
def check(draft13_path, emit_dir):
    rep = Report()
    text = Path(draft13_path).read_text()
    vec = extract_vectors(text)
    common = vec["common"]
    rep.say(f"draft13 {draft13_path} sha256={sha256(text.encode()).hex()}")
    rep.say(f"common ts={common['ts']} dispersion={common['dispersion']} issuer_key_id={common['issuer_key_id']}")
    if bytes.fromhex(common["issuer_public"]) != ISSUER_PUB or bytes.fromhex(common["holder_public"]) != HOLDER_PUB:
        rep.case("B.1 public keys equal the constants this adapter holds", False, True)
    hk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(common["holder_seed"]))

    # ---- S1: published Appendix B vectors
    rep.say("== S1 draft-13 Appendix B vectors (their published bytes)")
    published = {}
    for name in ("ed25519", "psk"):
        v = vec[name]
        r = bytes.fromhex(v["record"])
        published[name] = r
        f = parse_record(r)
        rep.case(f"B.{2 if name == 'ed25519' else 3} {name} record length", len(r), 180)
        rep.case(f"{name} verdict (version, alg_id, integrity_tag, issuer_sig over 0-115, holder_auth_data)", verify_record(r)[0], "intact")
        rep.case(f"{name} ts/dispersion/issuer_key_id equal B.1", (f["ts"], f["dispersion"], f["issuer_key_id"]),
                 (common["ts"], common["dispersion"], common["issuer_key_id"]))
        rep.case(f"{name} ctx_id/nonce equal B.1", (f["ctx_id"].hex(), f["nonce"].hex()), (common["ctx_id"], common["nonce"]))
        rep.case(f"{name} integrity_tag field = SHA-256(record[0:80])", v["integrity_tag"], sha256(r[0:80]).hex())
        rep.case(f"{name} issuer_signed_bytes = record[0:116]", v["issuer_signed_bytes"], r[0:116].hex())
        rep.case(f"{name} issuer_signature = record[116:180]", v["issuer_signature"], r[116:180].hex())
        sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(common["issuer_seed"]))
        rep.case(f"{name} issuer_signature equals our own Ed25519 signature over record[0:116] (deterministic)",
                 sk.sign(r[0:116]).hex(), v["issuer_signature"])
        rh, ctx, inp = draft13_binding(r, bytes.fromhex(common["exporter_fixture"]), common["direction"])
        rep.case(f"{name} record_hash", rh.hex(), v["record_hash"])
        rep.case(f"{name} exporter_context_hash (draft-13 6.1, 58-octet input)", ctx.hex(), v["exporter_context_hash"])
        rep.case(f"{name} binding_input (90 octets)", inp.hex(), v["binding_input"])
        if name == "ed25519":
            proof = hk.sign(inp)
            plen = 64
        else:
            proof = hmac.new(bytes.fromhex(common["psk"]), inp, hashlib.sha256).digest()
            plen = 32
        rep.case(f"{name} holder_proof recomputed", proof.hex(), v["holder_proof"])
        rep.case(f"{name} presentation = record || holder_proof, {180 + plen} octets", v["presentation"], (r + proof).hex())
        rep.case(f"{name} presentation length", len(bytes.fromhex(v["presentation"])), 244 if name == "ed25519" else 212)

    # ---- S2: records emitted by their code
    rep.say("== S2 records emitted by their pot_record_v2 (our adapter reads the bytes)")
    for label in ("e60bae0", "npm0.4.7", "e123ba9"):
        e = json.loads((Path(emit_dir) / f"emit-{label}.json").read_text())
        rep.say(f"-- module {label}: {e['module'].split('/')[-1]} exports {','.join(e['exports'])[:120]}")
        for n in ("ed25519", "psk"):
            rec = bytes.fromhex(e["records"][n]["hex"])
            rep.case(f"{label} {n}: emitted record equals draft-13 published record", rec.hex(), published[n].hex())
        for n in ("ed25519", "psk", "other"):
            rec = bytes.fromhex(e["records"][n]["hex"])
            rep.case(f"{label} {n}: our verdict on emitted record", verify_record(rec)[0] if n != "other" else
                     verify_record(rec)[0], "intact")
            rep.case(f"{label} {n}: their own verdict on emitted record", e["records"][n]["their_verdict"]["verdict"], "intact")
            mine = flips_ours(rec)
            rep.case(f"{label} {n}: single-bit mutants accepted by our verifier (of 1440, C.5 wants 0)", sum(mine), 0)
            rep.case(f"{label} {n}: single-bit mutants accepted by their verifier (of 1440)", sum(e["flips"][n]), 0)
            rep.case(f"{label} {n}: per-mutant agreement between our verdicts and theirs (of 1440)",
                     sum(1 for a, b in zip(mine, e["flips"][n]) if a == b), 1440)

    # ---- S3: freshness
    rep.say("== S3 freshness: draft-12 2.5 step 4 and Appendix C.6, draft-13 2.6")
    TS, D, F = common["ts"], common["dispersion"], 500000
    cases = {
        "future_equal_F": (TS - F, F),
        "future_F_plus_1": (TS - F - 1, F),
        "past_equal_W_plus_D": (TS + F + D, F),
        "past_W_plus_D_plus_1": (TS + F + D + 1, F),
        "overflow_W_max": (TS + 1, U64),
    }
    e12 = json.loads((Path(emit_dir) / "emit-e60bae0.json").read_text())
    epk = json.loads((Path(emit_dir) / "emit-npm0.4.7.json").read_text())
    for label, e in (("e60bae0", e12), ("npm0.4.7", epk)):
        for name, (now, skew) in cases.items():
            want = "intact" if spec_fresh(TS, now, D, skew, skew) else "rejected"
            got = e["freshness"][name]["verdict"]
            rep.case(f"{label} verifyPotRecordV2 freshness {name} (single maxSkewUs={skew} used as W and F)", got, want,
                     f"reason={e['freshness'][name]['reason']}")
    e13 = json.loads((Path(emit_dir) / "emit-e123ba9.json").read_text())
    d13cases = {
        "future_equal_F": (TS, TS - 500000, 100, 500000, 500000),
        "future_F_plus_1": (TS, TS - 500001, 100, 500000, 500000),
        "past_equal_W_plus_D": (TS, TS + 500100, 100, 500000, 500000),
        "past_W_plus_D_plus_1": (TS, TS + 500101, 100, 500000, 500000),
        "overflow_W_gt_max_minus_D": (TS, TS + 1, 100, U64, 500000),
        "overflow_W_max_minus_D_ok": (TS, TS + 1, 100, U64 - 100, 500000),
        "future_with_huge_D": (TS, TS - 500001, 4294967295, 500000, 500000),
    }
    for name, (ts, now, d, w, fk) in d13cases.items():
        rep.case(f"e123ba9 draft13Freshness {name}", e13["freshness"]["d13_" + name]["ok"], spec_fresh(ts, now, d, w, fk))

    # ---- S4: binding transcript, draft-12 text versus the 0.4.7 package
    rep.say("== S4 holder binding transcript: draft-12 6.1 text versus 0.4.7 package computeV2BindingInput")
    rh12, ctx12, inp12 = draft12_binding(published["ed25519"])
    rep.case("draft-12 6.1 binding_input is 81 octets", len(inp12), 81)
    rep.case("draft-12 6.1 context hash input is 49 octets", len(b"tttps-binding-v2" + b"\x00" + rh12), 49)
    for label, e in (("e60bae0", e12), ("npm0.4.7", epk)):
        rep.case(f"{label} package binding_input equals draft-12 6.1 binding_input", e["binding"]["package_binding_input"], inp12.hex(),
                 f"package_len={len(e['binding']['package_binding_input']) // 2}")
        rep.case(f"{label} package exporter context equals draft-12 6.1 context_value", e["binding"]["package_exporter_context"], ctx12.hex())

    # ---- S5: draft-13 holder proofs through their HEAD verifier
    rep.say("== S5 draft-13 holder proofs through e123ba9 verifyDraft13BindingProof")
    pr = e13["binding"]["draft13_proofs"]
    for n in ("ed25519", "psk"):
        rep.case(f"e123ba9 {n}: published holder_proof", pr[n]["published"], "intact")
        rep.case(f"e123ba9 {n}: holder_proof with one byte flipped", pr[n]["proof_byte_flipped"], "rejected")
        rep.case(f"e123ba9 {n}: published proof checked as direction 1", pr[n]["direction_1"], "rejected")
        rep.case(f"e123ba9 {n}: their binding_input equals published", pr[n]["input"], vec[n]["binding_input"])
        rep.case(f"e123ba9 {n}: their exporter context equals published", pr[n]["ctx"], vec[n]["exporter_context_hash"])

    # ---- S6: tamper (second angle), on the records read from the draft text given on the command line
    rep.say("== S6 tamper: one octet of the published ed25519 record changed, nothing recomputed")
    r = bytearray(published["ed25519"])
    for off, what in ((20, "ctx_id"), (4, "ts"), (60, "holder_auth_data"), (90, "integrity_tag"), (120, "issuer_sig")):
        x = bytearray(r)
        x[off] ^= 1
        rep.case(f"tampered octet {off} ({what}): our verdict", verify_record(bytes(x))[0], "rejected", verify_record(bytes(x))[1])
    x = bytearray(r)
    x[20] ^= 1
    x[80:112] = sha256(bytes(x[0:80]))
    rep.case("tampered ctx_id with integrity_tag recomputed (draft-13 4.1: unkeyed, so only the signature catches it)",
             verify_record(bytes(x))[1], "issuer_sig invalid")
    rep.say(f"SUMMARY cases={sum(1 for l in rep.lines if l.startswith(('match', 'DIFF ')))} diff={len(rep.bad)}")
    for b in rep.bad:
        rep.say(f"DIFFCASE {b}")
    return rep


def main(argv):
    if len(argv) == 4 and argv[1] == "extract":
        v = extract_vectors(Path(argv[2]).read_text())
        Path(argv[3]).write_text(json.dumps({k: v[k] for k in ("ed25519", "psk")}, sort_keys=True))
        print(f"extracted ed25519 record {len(v['ed25519']['record']) // 2} octets, psk record {len(v['psk']['record']) // 2} octets")
        return 0
    if len(argv) == 4 and argv[1] == "check":
        rep = check(argv[2], argv[3])
        print("\n".join(rep.lines))
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
