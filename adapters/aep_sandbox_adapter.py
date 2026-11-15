"""Adapter: a VERIFIER-SPEC-v1 verifier for the aep-sandbox JSON packages.

Written from section 2 to 5 of the frozen specification
(hackathon/ietf127/round1/VERIFIER-SPEC-v1.md, SHA-256 591eafd1...bb97d) and the
vectors; it does not import or run the project's verifier. Where the text is
silent: the package agent identifier is the top-level `agent_id`; a signature
is over the canonical form of the credential body, the mandate body or the
receipt core; an absent `measurements` is a failed step 4 (the digest is
compared with nothing).

For every vector it prints the ordered verdict (first failing check) and, from
independent evaluations that do not stop at the first failure, the per-layer
results:
  chain   receipt_hash == SHA-256(canonical(receipt core))
  aepsig  Ed25519 aep_sig by agent_pub over canonical(receipt core)
  credsig credential.sig by credential.body.issuer_pub over canonical(body)
  princ   mandate.sig by credential.body.principal_pub over canonical(body)
Layer values: ok, bad, n/a (the inputs needed are missing or malformed).

usage: aep_sandbox_adapter.py <vectors dir holding cases.json> <trusted_issuers.json>
Round 1 has no published answer key, so `--expect` is optional; Round 0 carries
`design_expectation` in cases.json and the adapter compares against it.
"""
import hashlib
import json
import pathlib
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

REASONS = (
    "malformed_aep content_mutated aep_sig_invalid measurement_mismatch malformed_mandate "
    "issuer_not_listed credential_sig_invalid principal_sig_invalid agent_binding_mismatch "
    "scope_violation expired replayed"
).split()
MAX_SAFE = 2**53 - 1


def canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha(obj):
    return hashlib.sha256(canon(obj)).hexdigest()


def edok(pub_hex, sig_hex, msg):
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex)).verify(bytes.fromhex(sig_hex), msg)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def is_obj(x):
    return isinstance(x, dict)


def in_profile(x):
    """True when every number is an integer within +-(2^53-1)."""
    if isinstance(x, bool) or x is None or isinstance(x, str):
        return True
    if isinstance(x, int):
        return abs(x) <= MAX_SAFE
    if isinstance(x, float):
        return False
    if isinstance(x, list):
        return all(in_profile(i) for i in x)
    if isinstance(x, dict):
        return all(in_profile(v) for v in x.values())
    return False


def layers(p):
    """Independent per-layer results, never stopped by an earlier failure."""
    out = {"chain": "n/a", "aepsig": "n/a", "credsig": "n/a", "princ": "n/a"}
    if not is_obj(p):
        return out
    core = {k: v for k, v in p.items() if k not in ("aep_sig", "receipt_hash")}
    try:
        cb = canon(core)
        out["chain"] = "ok" if hashlib.sha256(cb).hexdigest() == p.get("receipt_hash") else "bad"
        if isinstance(p.get("agent_pub"), str) and isinstance(p.get("aep_sig"), str):
            out["aepsig"] = "ok" if edok(p["agent_pub"], p["aep_sig"], cb) else "bad"
    except Exception:
        pass
    cred, man = p.get("credential"), p.get("mandate")
    cbody = cred.get("body") if is_obj(cred) else None
    mbody = man.get("body") if is_obj(man) else None
    if is_obj(cbody) and isinstance(cred.get("sig"), str) and isinstance(cbody.get("issuer_pub"), str):
        out["credsig"] = "ok" if edok(cbody["issuer_pub"], cred["sig"], canon(cbody)) else "bad"
    if is_obj(cbody) and is_obj(mbody) and isinstance(man.get("sig"), str) and isinstance(cbody.get("principal_pub"), str):
        out["princ"] = "ok" if edok(cbody["principal_pub"], man["sig"], canon(mbody)) else "bad"
    return out


def numeric(x):
    return isinstance(x, (int, float)) and not isinstance(x, bool)


def verify(p, anchors, now, consumed):
    """Ordered checks of section 4; returns (verdict, reason)."""
    need = ("agent_pub", "action", "credential", "mandate", "nonce", "aep_sig", "receipt_hash")
    if not is_obj(p) or any(k not in p for k in need):
        return "DENY", "malformed_aep"
    if not (is_obj(p["action"]) and is_obj(p["credential"]) and is_obj(p["mandate"])):
        return "DENY", "malformed_aep"
    if "measurements" in p and not is_obj(p["measurements"]):
        return "DENY", "malformed_aep"
    L = layers(p)
    if L["chain"] != "ok":
        return "DENY", "content_mutated"
    if L["aepsig"] != "ok":
        return "DENY", "aep_sig_invalid"
    m = p.get("measurements")
    if not is_obj(m) or m.get("action_sha256") != sha(p["action"]) or m.get("outcome_sha256") != sha(p.get("outcome", {})):
        return "DENY", "measurement_mismatch"
    cb, mb = p["credential"].get("body"), p["mandate"].get("body")
    if not (is_obj(cb) and is_obj(mb)):
        return "DENY", "malformed_mandate"
    if anchors.get(cb.get("issuer_id")) is None or anchors.get(cb.get("issuer_id")) != cb.get("issuer_pub"):
        return "DENY", "issuer_not_listed"
    if L["credsig"] != "ok":
        return "DENY", "credential_sig_invalid"
    if mb.get("principal_id") != cb.get("principal_id") or L["princ"] != "ok":
        return "DENY", "principal_sig_invalid"
    if mb.get("agent_pub") != p["agent_pub"] or mb.get("agent_id") != p.get("agent_id"):
        return "DENY", "agent_binding_mismatch"
    scope = mb.get("scope") if is_obj(mb.get("scope")) else {}
    if "allowed_methods" in scope and p["action"].get("method") not in scope["allowed_methods"]:
        return "DENY", "scope_violation"
    args = p["action"].get("args")
    if "max_amount" in scope and is_obj(args) and "amount" in args:
        if not numeric(args["amount"]) or args["amount"] > scope["max_amount"]:
            return "DENY", "scope_violation"
    exp = mb.get("exp")
    if not numeric(exp) or now > exp:
        return "DENY", "expired"
    n = p["nonce"]
    if any(type(c) is type(n) and c == n for c in consumed):
        return "DENY", "replayed"
    return "ALLOW", None


def fmt(v, r):
    return v if r is None else f"{v}:{r}"


def main(vec_dir, anchors_path, out_json=None):
    vec = pathlib.Path(vec_dir)
    anchors = json.loads(pathlib.Path(anchors_path).read_text())["issuers"]
    cases = json.loads((vec / "cases.json").read_text())
    rows = []
    for c in cases:
        raw = (vec / c["file"]).read_text(encoding="utf-8")
        p = json.loads(raw)
        v, r = verify(p, anchors, c["now"], c["consumed"])
        L = layers(p)
        prof = "in-profile" if in_profile(p) else "outside-profile"
        exp = c.get("design_expectation")
        rows.append({"file": c["file"], "verdict": v, "reason": r, "layers": L, "profile": prof,
                     "expected": exp, "scored": c.get("scored"), "class": c.get("class")})
        tail = ""
        if exp is not None:
            tail = f"\texpected={exp}\tscored={c.get('scored')}"
        print(f"{c['file']}\t{fmt(v, r)}\tchain={L['chain']} aepsig={L['aepsig']} credsig={L['credsig']} princ={L['princ']}\t{prof}{tail}")
    if out_json:
        pathlib.Path(out_json).write_text(json.dumps([{"file": r["file"], "verdict": r["verdict"], "reason": r["reason"]} for r in rows], indent=1) + "\n")
    return rows


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else None)
