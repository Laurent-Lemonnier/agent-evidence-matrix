"""Adversarial review of the two AER-1 cells marked contradicted (metadata_hash on 0.4 receipts; entry_count 5.0).

Usage: python -I aer1_review.py <kit-checkout> <output-dir>

For each case it prints three verdicts side by side:
  draft   our adapter reading draft-zambo-aer1-26 verbatim (aer1_adapter.py, default reading)
  kitread our adapter with the kit's stated rule (absent metadata_hash not failed)
  kit     the kit's own Python runner, base/conformance.py, loaded from the pinned checkout (this IS the replay
          of their verdict: check() for receipts, verify_chain_commitment() for commitments)
Tampered copies are written under <output-dir> as text edits of the original file bytes, then parsed."""
import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path

here = Path(__file__).resolve().parent
_ad = here / "aer1_adapter.py"  # side by side in the matrix repo's adapters/; ../adapter/ in the lane folder
if not _ad.exists():
    _ad = here.parent / "adapter" / "aer1_adapter.py"
spec = importlib.util.spec_from_file_location("aer1_adapter", _ad)
A = importlib.util.module_from_spec(spec)
spec.loader.exec_module(A)

kit, out = Path(sys.argv[1]), Path(sys.argv[2])
out.mkdir(parents=True, exist_ok=True)
kspec = importlib.util.spec_from_file_location("aer1_kit_conformance", kit / "base" / "conformance.py")
K = importlib.util.module_from_spec(kspec)
kspec.loader.exec_module(K)

TEN = ["bound-04", "deep-nesting", "edge-numbers", "empty-members", "input-hash-multikey-20", "large-payload",
       "maximum-offset-timestamp", "optional-members-18", "typographic-unicode", "uuid-v1-core"]
tv = kit / "base" / "test-vectors"


def ours(text, kit_reading):
    A.KIT_READING = kit_reading
    r, dup = A.parse(text)
    why, _ = A.check_receipt(r, dup)
    return "accept" if not why else "reject(" + ",".join(sorted({c for c, _ in why})) + ")"


def theirs(text):
    f = K.check(json.loads(text))
    return "accept" if not f else "reject(" + "; ".join(f) + ")"


def row(label, text):
    print("%-58s draft=%-22s kitread=%-10s kit=%s" % (label, ours(text, False), ours(text, True), theirs(text)))


def metadata_hash(r):
    blk = A.meta_block(r)
    return "sha256:" + hashlib.sha256(A.ser(blk).encode("utf-8")).hexdigest()


print("== Cell A: the ten valid/ vectors (kit: valid/ files MUST conform) ==")
for n in TEN:
    p = tv / "valid" / (n + ".json")
    text = p.read_text(encoding="utf-8")
    r = json.loads(text)
    print("%-26s schema=%s metadata_hash=%s sha256(file)=%s" % (
        n, json.dumps(r.get("receipt_schema_version")), "present" if "metadata_hash" in r else "absent",
        hashlib.sha256(p.read_bytes()).hexdigest()[:16]))
    row("  " + n, text)

print()
print("== Cell A ground truth: our Section 3.1 block reproduces the kit's real-04 metadata_hash ==")
real04 = (tv / "valid" / "real-04.json").read_text(encoding="utf-8")
r = json.loads(real04)
print("real-04 stored   %s" % r["metadata_hash"])
print("real-04 ours     %s  %s" % (metadata_hash(r), "MATCH" if metadata_hash(r) == r["metadata_hash"] else "DIFFER"))
row("real-04 (as published)", real04)

print()
print("== Cell A tamper: add a correct metadata_hash to each of the ten (must flip draft to accept) ==")
for n in TEN:
    text = (tv / "valid" / (n + ".json")).read_text(encoding="utf-8")
    r = json.loads(text)
    mh = metadata_hash(r)
    # insert the member after the opening brace of the top-level object, every other byte unchanged
    i = text.index("{") + 1
    t = text[:i] + '\n  "metadata_hash": "%s",' % mh + text[i:]
    (out / (n + ".with-metadata-hash.json")).write_text(t, encoding="utf-8")
    row("  " + n + " + metadata_hash", t)

print()
print("== Cell A reverse control: remove metadata_hash from real-04 (must flip draft to reject) ==")
t = re.sub(r'\n\s*"metadata_hash":\s*"sha256:[0-9a-f]{64}",', "", real04, count=1)
assert t != real04 and "metadata_hash" not in t
(out / "real-04.metadata-hash-removed.json").write_text(t, encoding="utf-8")
row("real-04 - metadata_hash", t)

print()
print("== Cell A consequence: strip metadata_hash from real-04, then move created_at by one minute ==")
r = json.loads(t)
old = r["created_at"]
new = old[:15] + ("5" if old[15] != "5" else "6") + old[16:]
t2 = t.replace('"created_at": "%s"' % old, '"created_at": "%s"' % new, 1)
assert t2 != t
(out / "real-04.metadata-hash-removed.created-at-moved.json").write_text(t2, encoding="utf-8")
print("created_at %s -> %s" % (old, new))
row("real-04 - metadata_hash, created_at moved", t2)
row("real-04 created_at moved, metadata_hash kept", real04.replace(
    '"created_at": "%s"' % old, '"created_at": "%s"' % new, 1))

print()
print("== Cell B: commitment vectors (expected_verdict from commitment-vectors.json) ==")
cpath = kit / "base" / "commitment-vectors.json"
ctext = cpath.read_text(encoding="utf-8")
print("raw spelling in the file:", sorted(set(re.findall(r'"entry_count":\s*([^,\n]+)', ctext))))


def cverdicts(text, name):
    v = [x for x in json.loads(text)["vectors"] if x["name"] == name][0]
    d = "valid" if not A.verify_commitment(v["timeline"], v["commitment"]) else "invalid"
    kf = K.verify_chain_commitment(v["timeline"], v["commitment"])
    k = "valid" if not kf else "invalid(" + "; ".join(kf) + ")"
    return v["expected_verdict"], d, k, v["commitment"].get("entry_count") if isinstance(v["commitment"], dict) else None


for name in [x["name"] for x in json.loads(ctext)["vectors"]]:
    e, d, k, c = cverdicts(ctext, name)
    print("%-26s entry_count=%-6r expected=%-8s draft=%-8s kit=%s" % (name, c, e, d, k))

print()
print("== Cell B tamper: x-entry-count-float with 5.0 spelled 5 (kit must flip to valid) ==")
t = ctext.replace('"entry_count": 5.0,', '"entry_count": 5,', 1)
assert t != ctext and t.count('"entry_count": 5.0') == 0
(out / "commitment-vectors.entry-count-5.json").write_text(t, encoding="utf-8")
e, d, k, c = cverdicts(t, "x-entry-count-float")
print("%-26s entry_count=%-6r expected=%-8s draft=%-8s kit=%s" % ("x-entry-count-float", c, e, d, k))

print()
print("== Cell B reverse control: commit-valid-1 with 5 spelled 5.0 (kit must flip to invalid) ==")
m = re.search(r'"name": "commit-valid-1".*?"entry_count": 5,', ctext, re.S)
t = ctext[:m.end() - 2] + "5.0," + ctext[m.end():]
(out / "commitment-vectors.commit-valid-1-5.0.json").write_text(t, encoding="utf-8")
e, d, k, c = cverdicts(t, "commit-valid-1")
print("%-26s entry_count=%-6r expected=%-8s draft=%-8s kit=%s" % ("commit-valid-1", c, e, d, k))

print()
print("== Cell B parallel: the same phrase for seq (Section 7.1) and the kit's own chain vectors ==")
cv = json.loads((kit / "base" / "chain-vectors-v07.json").read_text(encoding="utf-8"))
for v in cv["vectors"]:
    tl = v.get("timeline")
    if isinstance(tl, list) and any(isinstance(e, dict) and isinstance(e.get("seq"), float) for e in tl):
        kf = K.verify_chain_v07(tl)
        print("%-26s float seq values=%s expected=%s kit=%s" % (
            v["name"], [e["seq"] for e in tl if isinstance(e.get("seq"), float)], v.get("expected_verdict"),
            "valid" if not kf else "invalid(" + "; ".join(kf) + ")"))
