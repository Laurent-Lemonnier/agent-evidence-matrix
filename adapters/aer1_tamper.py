"""Second-angle check for aer1_adapter.py: one byte flipped in a hashed field of a copy of a kit record;
the adapter's verdict for the copy must differ from its verdict for the original.
Usage: python -I aer1_tamper.py <kit-checkout> <output-dir>   (copies are written under output-dir)"""
import importlib.util
import json
import sys
from pathlib import Path

here = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("aer1_adapter", here / "aer1_adapter.py")
A = importlib.util.module_from_spec(spec)
spec.loader.exec_module(A)

kit, out = Path(sys.argv[1]), Path(sys.argv[2])
out.mkdir(parents=True, exist_ok=True)
tv = kit / "base" / "test-vectors"


def flip(s, i):
    c = s[i]
    return s[:i] + ("B" if c != "B" else "C") + s[i + 1:]


def verdict_receipt(r):
    A.KIT_READING = True  # isolate the tampered field: the unrelated 0.4 rule must not mask it
    why, _ = A.check_receipt(r, None)
    return "accept" if not why else "reject(" + ",".join(sorted({c for c, _ in why})) + ")"


results = []
r = json.loads((tv / "valid" / "receipt-01.json").read_text())
t = dict(r, canonical_bytes=flip(r["canonical_bytes"], 10))
(out / "receipt-01.tampered.json").write_text(json.dumps(t, indent=1))
results.append(("receipt-01 canonical_bytes one char flipped", verdict_receipt(r), verdict_receipt(t)))

r = json.loads((tv / "valid" / "real-04.json").read_text())
t = dict(r, created_at=r["created_at"][:14] + ("6" if r["created_at"][14] != "6" else "7") + r["created_at"][15:])
(out / "real-04.tampered.json").write_text(json.dumps(t, indent=1))
results.append(("real-04 created_at one digit flipped", verdict_receipt(r), verdict_receipt(t)))

v = [x for x in json.loads((kit / "base" / "chain-vectors-v07.json").read_text())["vectors"]
     if x["name"] == "v07-valid-5"][0]
tl = json.loads(json.dumps(v["timeline"]))
tl[2]["canonical_bytes"] = flip(tl[2]["canonical_bytes"], 8)
(out / "v07-valid-5.tampered.json").write_text(json.dumps(tl, indent=1))
results.append(("v07-valid-5 entry 3 canonical_bytes one char flipped",
                "valid" if not A.verify_chain_07(v["timeline"]) else "invalid",
                "valid" if not A.verify_chain_07(tl) else "invalid"))

m = [x for x in json.loads((kit / "base" / "merkle-vectors.json").read_text())["vectors"]
     if x["name"] == "canonical-5-step"][0]
ids = list(m["receipt_ids"])
ids2 = ids[:]
ids2[1] = flip(ids2[1], 3)
results.append(("canonical-5-step receipt_id 2 one char changed",
                "root " + ("matches" if A.merkle(ids) == m["expected_root"] else "differs"),
                "root " + ("matches" if A.merkle(ids2) == m["expected_root"] else "differs")))

r = json.loads((tv / "valid" / "input-hash-multikey-20.json").read_text())
t = dict(r, input_hash=r["input_hash"][:-1] + ("0" if r["input_hash"][-1] != "0" else "1"))
(out / "input-hash-multikey-20.tampered.json").write_text(json.dumps(t, indent=1))
results.append(("input-hash-multikey-20 input_hash last hex digit changed", verdict_receipt(r), verdict_receipt(t)))

bad = 0
for name, a, b in results:
    flipped = a != b
    bad += not flipped
    print("TAMPER %-62s original=%-22s tampered=%-30s %s" % (name, a, b, "FLIPS" if flipped else "NO FLIP"))
print("TAMPER SUMMARY %d of %d flip" % (len(results) - bad, len(results)))
sys.exit(1 if bad else 0)
