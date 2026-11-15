"""Adapter: draft-xg-payment-dispute-profile-01 (ActaSeal dispute packets).

Reads the dispute packets published in https://github.com/actaseal/actaseal-verify (the
conformance vectors, four frozen releases of them, the rotated-key pair and the two demo packets)
and re-checks, with code written here from SPEC.md and the draft, what the draft says a verifier
recomputes: event hashes and chain links, the receipt signature over canonical bytes, the scope
hashes and headline consistency, the settlement anchor hash, the custody binding.

Two points beyond the repository's own verdicts:
 1. Draft Section 3 says the packet's canonical form is byte-identical to RFC 8785 JCS for every
    field the profile emits.  Every hashed or signed object is canonicalized here with rfc8785
    (not with the repository's json.dumps form) and compared byte for byte with the repository's form.
 2. Draft Sections 4.2 and 5 say the scope verdict MUST be re-derived from the recorded intent
    scope and executed action.  A packet is built whose recorded action breaches the recorded
    scope (amount 9999.00 against max_amount 5000.00) but is signed as IN_SCOPE with a key the
    adapter generates (deterministic seed); the repository's verify.py is run on it, in
    isolated mode, and its verdict is recorded.

usage: actaseal_dispute_adapter.py <actaseal-verify checkout or copy> <work dir for the forged packet>
Every line: <case>\t<verdict>\t<detail>   verdicts: agrees | contradicted | cannot-tell
"""
import copy
import hashlib
import json
import pathlib
import subprocess
import sys
from decimal import Decimal

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

OUT = []


def emit(case, verdict, detail):
    OUT.append(verdict)
    print(f"{case}\t{verdict}\t{detail}")


def sha(b):
    return hashlib.sha256(b).hexdigest()


def their_canon(v):
    # SPEC.md: json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


class Jcs:
    """Canonicalize with RFC 8785 and count disagreements with the repository's form."""
    checked = 0
    differ = 0

    @classmethod
    def c(cls, v):
        a = rfc8785.dumps(v)
        cls.checked += 1
        if a != their_canon(v):
            cls.differ += 1
        return a


def h(v):
    return sha(Jcs.c(v))


EVENT_FIELDS = ("event_type", "tenant_id", "workspace_id", "actor_id", "action_id", "action_type",
                "timestamp", "schema_version", "payload", "payload_hash", "previous_event_hash")


def check_packet(d):
    """Return the set of failure codes found by re-derivation."""
    f = set()
    man = json.loads((d / "manifest.json").read_text())
    rec = json.loads((d / "receipt.json").read_text())
    events = [json.loads(l) for l in (d / "ledger_slice.ndjson").read_text().splitlines() if l.strip()]
    cust = json.loads((d / "custody.json").read_text())
    auth = json.loads((d / "authentication.json").read_text())
    if man.get("event_count") != len(events):
        f.add("EVENT_COUNT_MISMATCH")
    if not events or events[0]["previous_event_hash"] != man.get("chain_start_previous_event_hash"):
        f.add("CHAIN_START_MISMATCH")
    for i, e in enumerate(events):
        mat = {k: e[k] for k in EVENT_FIELDS}
        if h(e["payload"]) != e["payload_hash"]:
            f.add("PAYLOAD_HASH_MISMATCH")
        eid = h({**mat, "event_id_basis": "ledger_event_id.v1"})
        if eid != e["event_id"]:
            f.add("EVENT_ID_MISMATCH")
        if h({**mat, "event_id": e["event_id"]}) != e["event_hash"]:
            f.add("EVENT_HASH_MISMATCH")
        if i and e["previous_event_hash"] != events[i - 1]["event_hash"]:
            f.add("CHAIN_BROKEN")
    # receipt signature over canonical(receipt minus signature)
    pk = bytes.fromhex(man["receipt_public_key_hex"])
    body = {k: v for k, v in rec.items() if k != "signature"}
    try:
        Ed25519PublicKey.from_public_bytes(pk).verify(bytes.fromhex(rec["signature"]), Jcs.c(body))
    except (InvalidSignature, ValueError):
        f.add("RECEIPT_SIGNATURE_INVALID")
    if rec.get("signer_pubkey_hash") != sha(pk):
        f.add("RECEIPT_SIGNER_PUBKEY_HASH_MISMATCH")
    # receipt bound to a ledger event
    bound = [e for e in events if e["event_hash"] == rec["ledger_entry_hash"]]
    if not bound:
        f.add("RECEIPT_LEDGER_ENTRY_MISSING")
    else:
        b = bound[0]
        if "action_packet_hash" in b["payload"] and b["payload"]["action_packet_hash"] != rec["action_hash"]:
            f.add("RECEIPT_ACTION_HASH_MISMATCH")
        if b["action_id"] != man["action_id"]:
            f.add("RECEIPT_ACTION_ID_MISMATCH")
    # scope: hashes recompute from recorded inputs, verdict/headline consistency
    sc = rec.get("scope_conformance")
    head = "not_evaluated" if sc is None else ("in_scope" if sc.get("verdict") == "IN_SCOPE" else
                                               "BREACH:" + ",".join(str(b.get("dimension")) for b in sc.get("breaches") or []))
    if man.get("scope_conformance_headline") != head:
        f.add("SCOPE_HEADLINE_MISMATCH")
    sev = [e for e in events if e["event_type"] == "ScopeEvaluated" and e["action_id"] == man["action_id"]]
    if sc is not None and not sev:
        f.add("SCOPE_EVENT_MISSING")
    if sc is not None and sev:
        p = sev[-1]["payload"]
        if p.get("verdict") != sc.get("verdict"):
            f.add("SCOPE_VERDICT_MISMATCH")
        for hf, sf in (("scope_hash", "intent_scope"), ("action_hash", "executed_action")):
            if p.get(sf) is None or p.get(hf) != h(p[sf]) or sc.get(hf) != p.get(hf):
                f.add("SCOPE_HASH_MISMATCH")
    # settlement anchor
    sa = man.get("settlement_anchor")
    if not isinstance(sa, dict):
        f.add("SETTLEMENT_ANCHOR_MISSING")
    elif sa.get("status") == "anchored" and sa.get("anchor_hash") != h(sa.get("anchor")):
        f.add("SETTLEMENT_ANCHOR_HASH_MISMATCH")
    # custody events name ledger events that exist
    hashes = {e["event_hash"] for e in events}
    if any(c["ledger_event_hash"] not in hashes for c in cust.get("custody_events", [])):
        f.add("CUSTODY_EVENT_NOT_IN_SLICE")
    if auth.get("signer_pubkey_hash") != rec.get("signer_pubkey_hash") or auth.get("mandate_hash") != rec.get("mandate_hash"):
        f.add("AUTHENTICATION_MISMATCH")
    return f


def expectations(root):
    """(label, dir, expected_verified, expected_code_substrings_or_None, where_stated)"""
    rows = []
    v = root / "conformance" / "vectors"
    for name in ("valid", "tampered_payload", "tampered_chain", "wrong_signature"):
        e = json.loads((v / name / "expected.json").read_text())
        rows.append((f"vectors/{name}", v / name, e["verified"], e["must_include_failure_substrings"], "expected.json"))
    rot = json.loads((v / "rotated_key_still_verifies" / "expected.json").read_text())
    for name in ("issued_before_rotation", "issued_after_rotation"):
        rows.append((f"vectors/rotated/{name}", v / "rotated_key_still_verifies" / name, rot[name]["verified"], [], "expected.json"))
    exp = json.loads((root / "conformance" / "frozen" / "expectations.json").read_text())
    for rel, spec in sorted(exp.items()):
        for name, (res, code) in sorted(spec["expect"].items()):
            rows.append((f"frozen/{rel}/{name}", root / "conformance" / "frozen" / rel / name, res == "PASS",
                         [code] if code else [], "frozen/expectations.json"))
    for name in ("demo-packet-unanchored", "demo-packet-anchored"):
        rows.append((f"demo/{name}", root / "demo" / name, True, [], "README: python verify.py demo/<packet> exits 0"))
    return rows


def forged_packet(src, dst):
    """Rebuild the valid vector with executed_action.amount 9999.00 (recorded max_amount 5000.00),
    verdict still IN_SCOPE, everything re-hashed, chained, and the receipt re-signed with a key
    derived from a fixed seed.  Nothing here calls the repository's code."""
    dst.mkdir(parents=True, exist_ok=True)
    sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("5e" * 32))
    pk = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    man = json.loads((src / "manifest.json").read_text())
    rec = json.loads((src / "receipt.json").read_text())
    cust = json.loads((src / "custody.json").read_text())
    auth = json.loads((src / "authentication.json").read_text())
    events = [json.loads(l) for l in (src / "ledger_slice.ndjson").read_text().splitlines() if l.strip()]
    old_hashes = [e["event_hash"] for e in events]
    se = next(e for e in events if e["event_type"] == "ScopeEvaluated")
    se["payload"]["executed_action"]["amount"] = "9999.00"
    new_action_hash = h(se["payload"]["executed_action"])
    se["payload"]["action_hash"] = new_action_hash
    for e in events:
        if "action_packet_hash" in e["payload"]:
            e["payload"]["action_packet_hash"] = new_action_hash
    prev = man["chain_start_previous_event_hash"]
    for e in events:
        e["previous_event_hash"] = prev
        e["payload_hash"] = h(e["payload"])
        mat = {k: e[k] for k in EVENT_FIELDS}
        e["event_id"] = h({**mat, "event_id_basis": "ledger_event_id.v1"})
        e["event_hash"] = h({**mat, "event_id": e["event_id"]})
        prev = e["event_hash"]
    bound_old = rec["ledger_entry_hash"]
    rec["ledger_entry_hash"] = events[old_hashes.index(bound_old)]["event_hash"]
    rec["action_hash"] = new_action_hash
    rec["scope_conformance"]["action_hash"] = new_action_hash
    rec["signer_pubkey_hash"] = sha(pk)
    rec.pop("signature", None)
    rec["signature"] = sk.sign(Jcs.c(rec)).hex()
    man["receipt_public_key_hex"] = pk.hex()
    auth["signer_pubkey_hash"] = sha(pk)
    for c, e in zip(cust["custody_events"], events):
        c["ledger_event_hash"] = e["event_hash"]
    (dst / "manifest.json").write_text(json.dumps(man, sort_keys=True))
    (dst / "receipt.json").write_text(json.dumps(rec, sort_keys=True))
    (dst / "custody.json").write_text(json.dumps(cust, sort_keys=True))
    (dst / "authentication.json").write_text(json.dumps(auth, sort_keys=True))
    (dst / "acquisition.json").write_text((src / "acquisition.json").read_text())
    (dst / "ledger_slice.ndjson").write_text("\n".join(json.dumps(e, sort_keys=True) for e in events) + "\n")
    return se["payload"]


def main(root, work):
    root, work = pathlib.Path(root), pathlib.Path(work)
    for label, d, want_ok, codes, where in expectations(root):
        got = check_packet(d)
        ok = not got
        missing = [c for c in codes if not any(c in g for g in got)]
        if ok == want_ok and not missing:
            emit(f"packet/{label}", "agrees",
                 f"verified={ok} as {where} says" + ("" if ok else f"; named {sorted(got)}"))
        else:
            emit(f"packet/{label}", "contradicted",
                 f"adapter verified={ok} codes={sorted(got)}; {where} says verified={want_ok} codes={codes}")
    emit("draft-s3/canonical-form-equals-JCS", "agrees" if Jcs.differ == 0 else "contradicted",
         f"{Jcs.checked} hashed or signed objects canonicalized with rfc8785; {Jcs.differ} differ from the repository's json.dumps form")

    # Draft 4.2 / 5: the scope verdict must be re-derived from recorded inputs
    src = root / "conformance" / "vectors" / "valid"
    payload = forged_packet(src, work / "forged-in-scope")
    emit("forged/adapter-consistency", "agrees" if not check_packet(work / "forged-in-scope") else "contradicted",
         "forged packet is internally consistent: hashes, chain, signature (own key), anchor, custody all recompute")
    intent, action = payload["intent_scope"], payload["executed_action"]
    breach = Decimal(action["amount"]) > Decimal(intent["max_amount"]) or action["action_type"] not in intent["action_types"]
    emit("forged/recorded-inputs-breach-the-scope", "agrees" if breach else "contradicted",
         f"executed amount {action['amount']} vs intent max_amount {intent['max_amount']}; verdict recorded as {payload['verdict']}")
    r = subprocess.run([sys.executable, "-I", str(root / "verify.py"), str(work / "forged-in-scope")],
                       capture_output=True, text=True, timeout=120)
    first = (r.stdout.strip().splitlines() or ["<no output>"])[0]
    emit("draft-s4.2-s5/scope-verdict-rederived-by-verify.py", "contradicted" if r.returncode == 0 else "agrees",
         f"verify.py exit {r.returncode} on a packet whose recorded action breaches its recorded scope but is signed IN_SCOPE: {first[:140]}")
    # the same packet with the signing key pinned: the key holder itself signed a verdict the recorded inputs do not support
    pk_hex = json.loads((work / "forged-in-scope" / "manifest.json").read_text())["receipt_public_key_hex"]
    rp = subprocess.run([sys.executable, "-I", str(root / "verify.py"), str(work / "forged-in-scope"),
                         "--receipt-public-key", pk_hex], capture_output=True, text=True, timeout=120)
    pinned = [l.strip() for l in rp.stdout.strip().splitlines()]
    emit("draft-s4.2-s5/scope-verdict-rederived-by-verify.py-key-pinned", "contradicted" if rp.returncode == 0 else "agrees",
         f"verify.py --receipt-public-key <signing key> exit {rp.returncode}: {(pinned or ['<no output>'])[0][:100]}; "
         f"{next((l for l in pinned if 'receipt key' in l), '')[:90]}")
    # control: the same forged packet with one signature character changed must be refused by verify.py
    ctl = work / "forged-bad-signature"
    ctl.mkdir(parents=True, exist_ok=True)
    for fn in (work / "forged-in-scope").iterdir():
        (ctl / fn.name).write_bytes(fn.read_bytes())
    rr = json.loads((ctl / "receipt.json").read_text())
    rr["signature"] = ("0" if rr["signature"][0] != "0" else "1") + rr["signature"][1:]
    (ctl / "receipt.json").write_text(json.dumps(rr, sort_keys=True))
    r2 = subprocess.run([sys.executable, "-I", str(root / "verify.py"), str(ctl)], capture_output=True, text=True, timeout=120)
    emit("forged/control-bad-signature-refused-by-verify.py", "agrees" if r2.returncode != 0 else "contradicted",
         f"verify.py exit {r2.returncode} when one signature character is changed: {(r2.stdout.strip().splitlines() or ['<no output>'])[0][:120]}")
    print(f"SUMMARY\tagrees={OUT.count('agrees')}\tcontradicted={OUT.count('contradicted')}\tcannot-tell={OUT.count('cannot-tell')}\ttotal={len(OUT)}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
