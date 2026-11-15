"""Adapter: Seal records (Aqta-ai/attestation-spec), ATTESTATION-v1 and ACTION-v1, recomputed from the spec text.

Reads test-vectors/{valid,invalid} (ATTESTATION-v1, pinned key from test-vectors/README.md) and
test-vectors/action/{valid,invalid} (ACTION-v1, pinned key from test-vectors/action/README.md) from a checkout
(argument 1), and judges each record with checks written from spec/ATTESTATION-v1.md sections 4 to 7 and
spec/ACTION-v1.md sections 4 to 7, with no code of theirs:

  exact top-level field set; v (integer 1, not a boolean / the string "action-1"); outcome enum; request_hash,
  intent_hash, args_hash 64 lowercase hex over the whole value (intent_hash may be ""; "" whenever session_id is "");
  tool non-empty; policy_applied an array of strings sorted by UTF-16 code unit; timestamp an RFC 3339 date-time with
  an explicit offset in ASCII digits (leap second 60 allowed); cost_prevented_eur a non-negative number; public_key
  equal to the pinned key; signature base64url without padding decoding to 64 bytes; Ed25519 over the canonical
  payload, which is the record without `signature` serialised with UTF-16 key order, compact separators, literal
  UTF-8 and ECMA-262 numbers (ATTESTATION-v1 section 6 points to RFC 8785 for both), computed here with rfc8785.

Expected verdict = the directory (valid/ or invalid/), as both READMEs state. Prints one line per vector.
"""
import base64
import json
import pathlib
import re
import sys

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ATT_FIELDS = {"v", "attestation_id", "trace_id", "org_id", "request_hash", "model", "outcome", "policy_applied",
              "cost_prevented_eur", "timestamp", "public_key", "signature"}
ACT_FIELDS = {"v", "action_id", "org_id", "session_id", "intent_hash", "agent", "tool", "args_hash", "outcome",
              "policy_applied", "timestamp", "public_key", "signature"}
HEX64 = re.compile(r"[0-9a-f]{64}")
B64URL = re.compile(r"[A-Za-z0-9_-]+")
# RFC 3339 section 5.6 date-time; ASCII digits only; T/Z per the ABNF (case-insensitive per its note)
TS = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})[Tt]([0-9]{2}):([0-9]{2}):([0-9]{2})(\.[0-9]+)?"
                r"([Zz]|[+-]([0-9]{2}):([0-9]{2}))")


def full(rx, s):
    return isinstance(s, str) and rx.fullmatch(s) is not None


def ts_ok(s):
    if not isinstance(s, str):
        return False
    m = TS.fullmatch(s)
    if not m:
        return False
    y, mo, d, h, mi, se = (int(m.group(i)) for i in range(1, 7))
    if not (1 <= mo <= 12 and 1 <= d <= 31 and h <= 23 and mi <= 59 and se <= 60):
        return False
    if m.group(9) is not None and (int(m.group(9)) > 23 or int(m.group(10)) > 59):
        return False
    return True


def u16(s):
    return s.encode("utf-16-be", "surrogatepass")


def sorted_u16(arr):
    return isinstance(arr, list) and all(isinstance(x, str) for x in arr) and \
        [u16(x) for x in arr] == sorted(u16(x) for x in arr)


def b64url_nopad(s):
    if not full(B64URL, s) or len(s) % 4 == 1:
        return None
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def sig_ok(rec, pinned):
    if rec.get("public_key") != pinned:
        return "public_key is not the pinned key"
    sig = b64url_nopad(rec.get("signature"))
    if sig is None or len(sig) != 64:
        return "signature is not 64 bytes of unpadded base64url"
    payload = {k: v for k, v in rec.items() if k != "signature"}
    try:
        msg = rfc8785.dumps(payload)
    except Exception as exc:  # noqa: BLE001 - any refusal means no canonical payload
        return "no canonical payload (%s)" % type(exc).__name__
    try:
        Ed25519PublicKey.from_public_bytes(b64url_nopad(pinned)).verify(sig, msg)
    except InvalidSignature:
        return "Ed25519 signature does not verify"
    return None


def check_attestation(r, pinned):
    if not isinstance(r, dict):
        return "not an object"
    if set(r) != ATT_FIELDS:
        return "field set differs: missing %s extra %s" % (sorted(ATT_FIELDS - set(r)), sorted(set(r) - ATT_FIELDS))
    if type(r["v"]) is not int or r["v"] != 1:
        return "v is not the integer 1"
    if not isinstance(r["outcome"], str) or r["outcome"] not in ("ALLOWED", "BLOCKED", "SUPPRESSED", "PASSED"):
        return "outcome not in section 5"
    if not full(HEX64, r["request_hash"]):
        return "request_hash not 64 lowercase hex"
    if not sorted_u16(r["policy_applied"]):
        return "policy_applied not strings sorted by UTF-16 code unit"
    if not ts_ok(r["timestamp"]):
        return "timestamp not RFC 3339 with offset"
    c = r["cost_prevented_eur"]
    if isinstance(c, bool) or not isinstance(c, (int, float)) or c < 0:
        return "cost_prevented_eur not a non-negative number"
    for k in ("attestation_id", "trace_id", "org_id", "model"):
        if not isinstance(r[k], str):
            return "%s not a string" % k
    return sig_ok(r, pinned)


def check_action(r, pinned):
    if not isinstance(r, dict):
        return "not an object"
    if set(r) != ACT_FIELDS:
        return "field set differs: missing %s extra %s" % (sorted(ACT_FIELDS - set(r)), sorted(set(r) - ACT_FIELDS))
    if r["v"] != "action-1" or not isinstance(r["v"], str):
        return "v is not the string action-1"
    if not isinstance(r["outcome"], str) or r["outcome"] not in ("ALLOWED", "BLOCKED"):
        return "outcome not ALLOWED or BLOCKED"
    for k in ("action_id", "org_id", "session_id", "agent", "tool", "intent_hash", "args_hash"):
        if not isinstance(r[k], str):
            return "%s not a string" % k
    if not full(HEX64, r["args_hash"]):
        return "args_hash not 64 lowercase hex"
    if r["intent_hash"] != "" and not full(HEX64, r["intent_hash"]):
        return "intent_hash not empty or 64 lowercase hex"
    if r["session_id"] == "" and r["intent_hash"] != "":
        return "intent_hash set without a session"
    if r["tool"] == "":
        return "tool is empty"
    if not sorted_u16(r["policy_applied"]):
        return "policy_applied not strings sorted by UTF-16 code unit"
    if not ts_ok(r["timestamp"]):
        return "timestamp not RFC 3339 with offset"
    return sig_ok(r, pinned)


SETS = [("ATTESTATION-v1", "test-vectors", "alWzEnrA_z9McN9z_MFfQCnH9mVgOwRZ26wrI7oix4E", check_attestation),
        ("ACTION-v1", "test-vectors/action", "pOaccW6Csyo1POtxjixPH80oux9--YC1tzzaENT4vQ0", check_action)]


def main(argv):
    root = pathlib.Path(argv[1])
    total = agree = 0
    for name, base, key, fn in SETS:
        n = k = 0
        for want in ("valid", "invalid"):
            for p in sorted((root / base / want).glob("*.json")):
                rec = json.loads(p.read_bytes().decode("utf-8"))
                why = fn(rec, key)
                got = "valid" if why is None else "invalid"
                n += 1
                ok = got == want
                k += ok
                print("%s %s %s/%s expected %s got %s%s" % ("AGREE" if ok else "DIFF ", name, want, p.name, want, got,
                                                            "" if why is None else " (" + why + ")"))
        print("SET %s: %d of %d agree" % (name, k, n))
        total += n
        agree += k
    print("SUMMARY %d of %d vectors agree" % (agree, total))
    return 0 if agree == total else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
