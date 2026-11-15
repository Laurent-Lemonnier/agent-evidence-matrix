"""Adapter: Succession Receipts (jsabey24/css-succession-receipts), Authority-Handoff Receipt, recomputed from the spec text.

Reads the checkout named by argument 1 and, with no code of theirs (the repository holds none), implements
spec/authority-handoff-receipts.md Sections 3 and 4 steps 1 to 5 and runs every case of corpus/ahr-v0.1/r1 and
corpus/ahr-v0.2/r1:
  step 1 proof               canonical bytes without `proof` (Section 3), SHA-256, Ed25519 over the ASCII hash string
  step 2 evidence_hash       event hash rule of Section 4 step 2 (Go json.Marshal escapes, RFC3339Nano timestamp)
  step 3 evidence_signature  Ed25519 over the event_hash string
  step 4 claim_grounding     the eight grounding rules
  step 5 version_claims      0.1 carries neither v0.2 claim; 0.2 constitution and ledger binding; other versions rejected
Each case's verdict (pass or the first failing step) is compared with the manifest's expect and failing_check.
A second check recomputes corpus/SHA256SUMS over the files it lists and over every file under corpus/.
The OTS file header digest is compared with SHA-256 of corpus/SHA256SUMS (no Bitcoin attestation is verified). Authorization binding (step 6) and the other artifacts are not run here. Exit 0 iff everything agrees.
"""
import base64
import hashlib
import json
import pathlib
import re
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import load_pem_public_key

root = pathlib.Path(sys.argv[1])
corpus = root / "corpus"


def esc(s, go_html):
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\b":
            out.append("\\b")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\f":
            out.append("\\f")
        elif ch == "\r":
            out.append("\\r")
        elif o < 0x20:
            out.append("\\u%04x" % o)
        elif o in (0x2028, 0x2029):
            out.append("\\u%04x" % o)
        elif go_html and ch in "<>&":
            out.append("\\u%04x" % o)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def ser(v, sort_keys, go_html=False):
    if v is True:
        return "true"
    if v is False:
        return "false"
    if v is None:
        return "null"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        raise ValueError("float")
    if isinstance(v, str):
        return esc(v, go_html)
    if isinstance(v, list):
        return "[" + ",".join(ser(x, sort_keys, go_html) for x in v) + "]"
    keys = sorted(v) if sort_keys else list(v)
    return "{" + ",".join(esc(k, go_html) + ":" + ser(v[k], sort_keys, go_html) for k in keys) + "}"


def nano(ts):
    m = re.fullmatch(r"(.*?)(?:\.(\d+))?(Z|[+-]\d\d:\d\d)", ts)
    base, frac, zone = m.groups()
    frac = (frac or "").rstrip("0")
    return base + ("." + frac if frac else "") + zone


def event_hash(e):
    parts = [e["event_id"], e["event_type"], e["aggregate_type"], e["aggregate_id"], nano(e["timestamp"]),
             str(e["event_version"]), ser(e["payload"], False, True), e.get("previous_event_id") or ""]
    return hashlib.sha256("".join(parts).encode("utf-8")).hexdigest()


def sig_ok(keys, sig, msg):
    try:
        alg, kid, b = sig.split(":", 2)
        if alg != "ed25519" or kid not in keys:
            return False
        keys[kid].verify(base64.urlsafe_b64decode(b + "=" * (-len(b) % 4)), msg.encode("ascii"))
        return True
    except (InvalidSignature, ValueError, KeyError):
        return False


def order(ev):
    return sorted(ev, key=lambda e: (e["timestamp"], e["event_id"]))


def grounding(r):
    ev, cs = r["evidence"], r["credentialSubject"]
    by = lambda t: [e for e in ev if e["event_type"] == t]
    comp = [e for e in by("SuccessionCompleted") if e["payload"].get("succession_id") == cs["succession_id"]]
    if not comp or r["validFrom"] != comp[0]["timestamp"] or cs["id"] != "urn:uuid:" + cs["succession_id"]:
        return False
    pr, su = cs["predecessor"], cs["successor"]
    if not any(e["payload"].get("predecessor_steward_id") == pr["steward_id"]
               and e["payload"].get("successor_steward_id") == su["steward_id"] for e in by("SuccessionProposed")):
        return False
    ap = by("SuccessionApproved")
    if not ap or any(e["payload"].get("legitimacy_id") not in (None, "", cs["legitimacy"]["legitimacy_id"]) for e in ap):
        return False
    if not any(e["payload"].get("authority_id") == su["authority_id"] and e["payload"].get("steward_id") == su["steward_id"]
               and e["payload"].get("scope") == su["authority_scope"]
               and e["payload"].get("accountability_chain_id") == su["accountability_chain_id"]
               and e.get("correlation_id") == comp[0].get("correlation_id") for e in by("AuthorityGranted")):
        return False
    if su["authority_status"] == "active":
        if not any(e["payload"].get("authority_id") == su["authority_id"] for e in by("AuthorityValidated")):
            return False
    elif su["authority_status"] != "granted":
        return False
    if pr.get("replaced") and not any(e["payload"].get("steward_id") == pr["steward_id"] for e in by("StewardReplaced")):
        return False
    rev = {(e["payload"].get("authority_id"), e["payload"].get("revocation_basis")) for e in by("AuthorityRevoked")}
    claimed = {(x["authority_id"], x["revocation_basis"]) for x in pr.get("revoked_authorities", [])}
    if rev != claimed:
        return False
    for key, typ, idk in (("obligations_carried", "ObligationInherited", "obligation_id"),
                          ("commitments_carried", "CommitmentInherited", "commitment_id")):
        got = {e["payload"].get(idk) for e in by(typ) if e["payload"].get("successor_steward_id") == su["steward_id"]}
        if set(cs.get(key, [])) != got:
            return False
    return True


def version_claims(r):
    cs, ev = r["credentialSubject"], r["evidence"]
    v = r.get("spec_version")
    if v == "0.1":
        return "constitution" not in cs and "ledger_binding" not in cs
    if v != "0.2":
        return False
    c, lb = cs.get("constitution"), cs.get("ledger_binding")
    if c is None or lb is None:
        return False
    gen = [e for e in ev if e["event_type"] == "GenesisInitialized"]
    if len(gen) != 1 or event_hash(gen[0]) != c.get("genesis_event_hash"):
        return False
    am = order([e for e in ev if e["event_type"] == "AmendmentRatified"])
    if c.get("amendments_ratified") != len(am) or any(e["timestamp"] > r["validFrom"] for e in am):
        return False
    if len(am) == 0:
        if "amendment_head_hash" in c:
            return False
    elif c.get("amendment_head_hash") != event_hash(am[-1]):
        return False
    last = order(ev)[-1]
    return lb.get("event_hash") == event_hash(last) and lb.get("height", 0) >= len(ev)


def verify(r, keys):
    proof = r.get("proof")
    if not isinstance(proof, dict):
        return "proof"
    body = {k: v for k, v in r.items() if k != "proof"}
    h = hashlib.sha256(ser(body, True).encode("utf-8")).hexdigest()
    if not sig_ok(keys, proof.get("signature", ""), h):
        return "proof"
    for e in r["evidence"]:
        if event_hash(e) != e.get("event_hash"):
            return "evidence_hash"
    for e in r["evidence"]:
        if e.get("signature") and not sig_ok(keys, e["signature"], e["event_hash"]):
            return "evidence_signature"
    if not grounding(r):
        return "claim_grounding"
    if not version_claims(r):
        return "version_claims"
    return None


agree = diff = 0
for mp in ("ahr-v0.1/r1", "ahr-v0.2/r1"):
    d = corpus / mp
    man = json.loads((d / "manifest.json").read_text())
    keys = {k: load_pem_public_key((d / p).read_bytes()) for k, p in man["keys"].items()}
    for c in man["cases"]:
        got = verify(json.loads((d / c["file"]).read_text()), keys)
        want = None if c["expect"] == "pass" else c.get("failing_check")
        ok = got == want
        agree += ok
        diff += not ok
        print(("AGREE" if ok else "DIFF ") + " %s %s expected %s got %s" % (mp, c["name"], want or "pass", got or "pass"))

sums = {}
for line in (corpus / "SHA256SUMS").read_text().splitlines():
    h, p = line.split("  ", 1)
    sums[p] = h
bad = [p for p, h in sums.items() if hashlib.sha256((root / p).read_bytes()).hexdigest() != h]
actual = {f.relative_to(root).as_posix() for f in corpus.rglob("*") if f.is_file()} - {"corpus/SHA256SUMS", "corpus/SHA256SUMS.ots"}
extra = sorted(actual - set(sums))
missing = sorted(set(sums) - actual)
print("SHA256SUMS: %d listed, %d mismatched, %d files under corpus/ not listed %s, %d listed absent %s"
      % (len(sums), len(bad), len(extra), extra[:3], len(missing), missing[:3]))
sums_ok = not (bad or extra or missing)
print(("AGREE" if sums_ok else "DIFF ") + " corpus/SHA256SUMS over %d files" % len(sums))
agree += sums_ok
diff += not sums_ok
ots = (corpus / "SHA256SUMS.ots").read_bytes()
hdr = bytes.fromhex("004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294" "01" "08")
head_ok = ots.startswith(hdr) and ots[len(hdr):len(hdr) + 32] == hashlib.sha256((corpus / "SHA256SUMS").read_bytes()).digest()
print(("AGREE" if head_ok else "DIFF ") + " corpus/SHA256SUMS.ots stamps the SHA-256 of corpus/SHA256SUMS (file header digest; no Bitcoin block was fetched)")
agree += head_ok
diff += not head_ok
print("SUMMARY %d of %d agree" % (agree, agree + diff))
sys.exit(0 if diff == 0 else 1)
