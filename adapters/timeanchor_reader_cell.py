"""Carry the Appendix D vectors through our reader (agent_evidence_vectors.recorded).

Usage: venv/bin/python -I adapters/timeanchor_reader_cell.py <raw-dir>

Builds a recorded set (artifact bytes, .ots proofs, SHA256SUMS) from the four
vectors extracted out of the draft text and checks it with
recorded.check_set using four opentimestamps-bitcoin-header bindings that
hold the 80-byte header of block 957289 (taken from two public explorers,
and checked to hash to the block id the draft prints).  Then repeats the
check over tampered copies.  Needs no network and reads no key.
"""
import hashlib
import json
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import timeanchor_adapter as ta  # our own module, same folder
from agent_evidence_vectors import recorded

WORK = HERE / "_work" / "recorded-set"


def build(root, vec, d5, header, flip=None):
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True)
    files = {}
    for n in range(1, 5):
        art = vec[n]["artifact"].encode("ascii")
        proof = d5[n]["bytes"]
        if flip == "artifact" and n == 1:
            art = bytes([art[0] ^ 1]) + art[1:]
        if flip == "proof" and n == 1:
            i = proof.index(bytes.fromhex(vec[1]["nonce"]))
            proof = proof[:i] + bytes([proof[i] ^ 1]) + proof[i + 1:]
        files["vector-%d.artifact" % n] = art
        files["vector-%d.ots" % n] = proof
    sums = ""
    for name in sorted(files):
        (root / name).write_bytes(files[name])
        sums += "%s  %s\n" % (hashlib.sha256(files[name]).hexdigest(), name)
    (root / "SHA256SUMS").write_text(sums)
    if flip == "header":
        header = header[:36] + bytes([header[36] ^ 1]) + header[37:]
    bid = recorded.block_id(header)
    return [{"type": "opentimestamps-bitcoin-header", "subject": "vector-%d.artifact" % n,
             "proof": "vector-%d.ots" % n,
             "block": {"height": 957289, "header": header.hex(), "id": bid}} for n in range(1, 5)]


def main():
    raw = Path(sys.argv[1])
    text = (raw / ta.DRAFT).read_text()
    lines = ta.clean_lines(text)
    vec, d5, d3 = ta.parse_vectors(lines), ta.parse_d5(lines), ta.parse_d3(lines)
    header = bytes.fromhex((raw / "block-957289-header-blockstream.hex").read_text().strip())
    print("READER agent_evidence_vectors.recorded.check_set, 4 bindings, header id %s (draft prints %s)"
          % (recorded.block_id(header)[:24], d3["block_hash"][:24]))
    expect = {"clean": [], "tamper-artifact-byte-v1": ["binding-mismatch"],
              "tamper-proof-nonce-byte-v1": ["anchor-mismatch"],
              "tamper-header-merkle-root-byte": ["anchor-mismatch"]}
    seen = {}
    for label, flip in (("clean", None), ("tamper-artifact-byte-v1", "artifact"),
                        ("tamper-proof-nonce-byte-v1", "proof"),
                        ("tamper-header-merkle-root-byte", "header")):
        bindings = build(WORK, vec, d5, header, flip)
        codes = recorded.check_set(WORK, None, bindings)
        seen[label] = codes
        verdict = "verified" if not codes else "failed"
        print("READER-CASE %s %s codes=%s expected=%s %s" % (
            label, verdict, ",".join(codes) or "-", ",".join(expect[label]) or "-",
            "PASS" if codes == expect[label] else "FAIL"))
    ok = sum(1 for k in seen if seen[k] == expect[k])
    print("READER-TOTAL %d of %d" % (ok, len(seen)))
    shutil.rmtree(WORK.parent)


if __name__ == "__main__":
    main()
