"""Appraise the quotes emitted by the aep-sandbox tpm-demo against draft-sokolov-rats-aep-composition-06.

Usage: sokolov_aep_rats_adapter.py <aep-sandbox checkout at c5d4194f> <run-dir>

<run-dir> holds what one tpm-demo run leaves behind: ak.pub, runA.msg/.sig, runB.msg/.sig, run.log, aep.json,
reference-pcrs.txt, results.json. Nothing here calls tpm2-tools: the quote structure (TPMS_ATTEST), the key
(TPM2B_PUBLIC) and the signature (TPMT_SIGNATURE) are decoded from the TPM 2.0 Part 2 layouts, the signature is
RSASSA-PKCS1-v1_5 over SHA-256 checked with the `cryptography` package, and the expected PCR values are recomputed
from the extend strings in tpm-demo/run_pipeline.sh, not read from their files. The draft's own expectations are
the Section 11 cases V1 to V5 (V6 has no code in the demo). Python 3 standard library plus `cryptography`.
"""
import hashlib
import os
import re
import struct
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def h(data):
    return hashlib.sha256(data).hexdigest()


class Reader:
    def __init__(self, data):
        self.d, self.i = data, 0

    def take(self, n):
        if self.i + n > len(self.d):
            raise ValueError("truncated structure")
        b = self.d[self.i:self.i + n]
        self.i += n
        return b

    def u(self, fmt):
        return struct.unpack(">" + fmt, self.take(struct.calcsize(">" + fmt)))[0]

    def tpm2b(self):
        return self.take(self.u("H"))

    def done(self):
        if self.i != len(self.d):
            raise ValueError("%d trailing bytes" % (len(self.d) - self.i))


def parse_public(data):
    """TPM2B_PUBLIC holding an RSA signing key; returns (key, TPM name)."""
    r = Reader(data)
    area = r.tpm2b()
    r.done()
    p = Reader(area)
    assert p.u("H") == 0x0001, "not an RSA key"
    name_alg = p.u("H")
    assert name_alg == 0x000B, "nameAlg is not SHA-256"
    p.u("I")
    p.tpm2b()  # authPolicy
    assert p.u("H") == 0x0010, "symmetric is not NULL"
    assert p.u("H") == 0x0014 and p.u("H") == 0x000B, "scheme is not RSASSA-SHA256"
    bits = p.u("H")
    exp = p.u("I") or 65537
    mod = p.tpm2b()
    p.done()
    assert bits == len(mod) * 8
    key = rsa.RSAPublicNumbers(exp, int.from_bytes(mod, "big")).public_key()
    return key, bytes.fromhex("000b" + h(area))


def parse_attest(data):
    r = Reader(data)
    a = {"magic": r.u("I"), "type": r.u("H"), "signer": r.tpm2b(), "extra": r.tpm2b()}
    a["clock"], a["resets"], a["restarts"], a["safe"] = r.u("Q"), r.u("I"), r.u("I"), r.u("B")
    a["fw"] = r.u("Q")
    count = r.u("I")
    sel = []
    for _ in range(count):
        alg, size = r.u("H"), r.u("B")
        sel.append((alg, r.take(size)))
    a["sel"], a["pcr_digest"] = sel, r.tpm2b()
    r.done()
    return a


def parse_sig(data):
    r = Reader(data)
    alg, hash_alg = r.u("H"), r.u("H")
    sig = r.tpm2b()
    r.done()
    return alg, hash_alg, sig


def verify(key, msg, sig):
    try:
        key.verify(sig, msg, padding.PKCS1v15(), hashes.SHA256())
        return True
    except InvalidSignature:
        return False


def extend(pcr, digest_hex):
    return hashlib.sha256(pcr + bytes.fromhex(digest_hex)).digest()


def read_script(sandbox):
    text = open(os.path.join(sandbox, "tpm-demo", "run_pipeline.sh")).read()
    heredoc = re.search(r'cat > "\$OUT/aep\.json" <<JSON\n(.*?)\nJSON\n', text, re.S).group(1)
    summary = re.search(r"\$\(h '([^']+)'\)", heredoc).group(1)
    aep = (heredoc.replace("$(h '%s')" % summary, h(summary.encode())) + "\n").encode()
    extends = re.findall(r"tpm2_pcrextend (\d):sha256=\$\(h ([^)]+)\)", text)
    forged = re.search(r"AEPH_FORGED=\$\(h '([^']+)'\)", text).group(1)
    assert 'QUAL_A=$(h "${AEPH}:${NONCE_A}")' in text, "qualifying data construction changed"
    return text, aep, extends, forged, summary


def composite(pcrs):
    return hashlib.sha256(b"".join(pcrs[i] for i in range(4))).digest()


def appraise(key, msg, sig, ref_digest, expected_qual):
    """Returns (signature valid, pcr composite state, nonce state)."""
    sig_ok = verify(key, msg, sig)
    a = parse_attest(msg)
    pcr = "match" if a["pcr_digest"] == ref_digest else "diverged"
    fresh = "match" if a["extra"] == expected_qual else "mismatch"
    return sig_ok, pcr, fresh


def main(sandbox, run):
    rd = lambda n: open(os.path.join(run, n), "rb").read()
    log = rd("run.log").decode()
    out = []

    def say(s):
        out.append(s)
        print(s)

    text, aep, extends, forged_text, summary = read_script(sandbox)
    aeph = h(aep)
    key, ak_name = parse_public(rd("ak.pub"))
    say("# sokolov-aep-rats adapter: tpm-demo quotes appraised against draft-sokolov-rats-aep-composition-06 Section 11")

    # AEP record digest, four independent sources
    logged = re.search(r"AEP digest\s+= (\w+)", log).group(1)
    readme = open(os.path.join(sandbox, "tpm-demo", "README.md")).read()
    readme_digest = "b80c48d9115da3ed8d388f670af5d713cfd990d6743c77094495fcabe3e59d89"
    ok = [aeph == logged, aeph == h(rd("aep.json")), aeph == json_field(rd("results.json"), "aep_digest"), readme_digest in readme and aeph == readme_digest]
    say("RECORD-DIGEST script-heredoc=%s emitted-aep.json=%s run.log=%s results.json=%s readme=%s -> %s" % (aeph[:16], ok[1], ok[0], ok[2], ok[3], "agrees" if all(ok) else "differs"))

    # expected PCR values from the script's extend strings
    zero = bytes(32)
    pcrs = {i: zero for i in range(4)}
    for idx, name in extends[:4]:
        pcrs[int(idx)] = extend(pcrs[int(idx)], h(name.encode()))
    b_idx, b_name = extends[4]
    pcrs_b = dict(pcrs)
    pcrs_b[int(b_idx)] = extend(pcrs[int(b_idx)], h(b_name.encode()))
    ref_a, ref_b = composite(pcrs), composite(pcrs_b)
    ref_txt = rd("reference-pcrs.txt").decode()
    listed = {int(m.group(1)): m.group(2).lower() for m in re.finditer(r"^\s+(\d) : 0x([0-9A-Fa-f]{64})", ref_txt, re.M)}
    pcr_ok = all(listed[i] == pcrs[i].hex() for i in range(4))
    say("PCR-RECOMPUTE four extends from script text equal reference-pcrs.txt: %s; swapped PCR%s differs from reference: %s" % (pcr_ok, b_idx, ref_a != ref_b))

    sigs = {}
    for t in ("A", "B"):
        msg, sg = rd("run%s.msg" % t), rd("run%s.sig" % t)
        a = parse_attest(msg)
        alg, halg, sig = parse_sig(sg)
        sigs[t] = (msg, sig, a, alg, halg)
        shape = a["magic"] == 0xFF544347 and a["type"] == 0x8018 and alg == 0x0014 and halg == 0x000B and a["sel"] == [(0x000B, bytes([0x0F, 0, 0]))]
        say("STRUCT run%s magic=TCG type=QUOTE selection=sha256:PCR0-3 sigAlg=RSASSA hash=SHA256 extraData=%d bytes safe=%d -> %s" % (t, len(a["extra"]), a["safe"], "ok" if shape else "unexpected"))
    nm = re.search(r"^\s+name: (\w+)$", log, re.M).group(1)
    qn = re.search(r"qualified name: (\w+)", log).group(1)
    say("KEY-NAME TPM name of ak.pub recomputed %s logged name %s; quote qualifiedSigner equals logged qualified name: %s" % (ak_name.hex() == nm, "equal" if ak_name.hex() == nm else "differs", sigs["A"][2]["signer"].hex() == qn))

    nonce_a = re.search(r"fresh nonce \(run A\) = (\w+)", log).group(1)
    qual_a = bytes.fromhex(h(("%s:%s" % (aeph, nonce_a)).encode()))
    logged_qual = re.search(r"qualifying data A\s+= (\w+)", log).group(1)

    # V1: known instance and approved measurement
    msg, sig, a, _, _ = sigs["A"]
    s, p, f = appraise(key, msg, sig, ref_a, qual_a)
    v1 = s and p == "match" and f == "match" and qual_a.hex() == logged_qual
    say("V1 run A signature=%s pcrComposite=%s extraData(H(AEPH:nonceA))=%s -> %s" % (s, p, f, "ATTESTED" if v1 else "NOT-ATTESTED"))

    # V2: correctly signed, composite differs
    msg_b, sig_b, a_b, _, _ = sigs["B"]
    s2, p2, f2 = appraise(key, msg_b, sig_b, ref_a, a_b["extra"])
    on_swapped = a_b["pcr_digest"] == ref_b
    v2 = s2 and p2 == "diverged" and on_swapped and a_b["extra"] != a["extra"]
    say("V2 run B signature=%s pcrComposite-vs-approved=%s composite-equals-swapped-PCR3-recompute=%s -> %s" % (s2, p2, on_swapped, "CONTESTED" if v2 else "UNEXPECTED"))

    # V3: one byte of TPMS_ATTEST altered, every position
    rejected = 0
    for i in range(len(msg)):
        bad = bytearray(msg)
        bad[i] ^= 0x01
        if not verify(key, bytes(bad), sig):
            rejected += 1
    say("V3 one-byte alteration of runA TPMS_ATTEST at each of %d positions: signature rejected %d of %d -> %s" % (len(msg), rejected, len(msg), "CONTRAINDICATED" if rejected == len(msg) else "ACCEPTED-SOME"))

    # V4: stale replay under a fresh expected nonce
    new_nonce = os.urandom(16).hex()
    assert new_nonce != nonce_a
    qual_new = bytes.fromhex(h(("%s:%s" % (aeph, new_nonce)).encode()))
    s4, p4, f4 = appraise(key, msg, sig, ref_a, qual_new)
    v4 = s4 and p4 == "match" and f4 == "mismatch"
    say("V4 run A quote replayed against a fresh expected nonce: signature=%s pcrComposite=%s extraData=%s -> %s" % (s4, p4, f4, "FAIL-CLOSED" if v4 else "UNEXPECTED"))

    # V5: outcome substitution, their forgery and one changed in the record itself
    q_forged = bytes.fromhex(h(("%s:%s" % (h(forged_text.encode()), nonce_a)).encode()))
    s5a, p5a, f5a = appraise(key, msg, sig, ref_a, q_forged)
    tampered = aep.replace(h(summary.encode()).encode(), h(b"a DIFFERENT, fabricated summary").encode())
    assert tampered != aep and h(tampered) != aeph
    q_changed = bytes.fromhex(h(("%s:%s" % (h(tampered), nonce_a)).encode()))
    s5b, p5b, f5b = appraise(key, msg, sig, ref_a, q_changed)
    v5 = s5a and f5a == "mismatch" and s5b and f5b == "mismatch" and p5b == "match"
    say("V5 platform evidence kept, outcome changed: their forged digest extraData=%s; aep.json with outcome_digest replaced (record digest %s, was %s) extraData=%s; signature and PCR composite still valid -> %s" % (f5a, h(tampered)[:16], aeph[:16], f5b, "REJECTED" if v5 else "UNEXPECTED"))

    # their own verdict lines
    theirs = re.findall(r"VERDICT: (\w+)", log) + re.findall(r"-> (rejected)", log)
    say("THEIR-VERDICTS run.log %s; ours Attested/Contested/Expired/rejected %s" % (theirs, [("Attested" if v1 else "-"), ("Contested" if v2 else "-"), ("Expired" if v4 else "-"), ("rejected" if v5 else "-")]))
    allok = all(ok) and pcr_ok and v1 and v2 and v4 and v5 and rejected == len(msg) and theirs == ["Attested", "Contested", "Expired", "rejected"]
    say("RESULT record-digest=%s V1=%s V2=%s V3=%d/%d V4=%s V5=%s agree-with-their-verdicts=%s" % (all(ok), v1, v2, rejected, len(msg), v4, v5, allok))
    return 0


def json_field(raw, name):
    import json
    return json.loads(raw)[name]


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2]))
