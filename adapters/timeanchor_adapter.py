"""Recompute the Appendix D vectors of draft-fassbender-scitt-time-anchor.

Usage: venv/bin/python -I adapters/timeanchor_adapter.py <raw-dir> [--tamper]

<raw-dir> holds draft-fassbender-scitt-time-anchor-08.txt and the Bitcoin
block 957289 header and block JSON captured from two public explorers.
The adapter extracts every stated value and all four .ots proofs from the
draft text (page breaks removed), recomputes each value with its own
standard-library code, and prints one line per case. It reads no key and
makes no network call.  With --tamper it also reruns the cases over two
deliberately altered copies and prints the cases that flip.
"""

import base64
import datetime
import hashlib
import json
import re
import sys
import tempfile
from pathlib import Path

DRAFT = "draft-fassbender-scitt-time-anchor-08.txt"
OTS_MAGIC = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"
BTC_TAG = bytes.fromhex("0588960d73d71901")
PENDING_TAG = bytes.fromhex("83dfe30d2ef90c8e")
EXPECTED_HEIGHT = 957289


def sha(b):
    return hashlib.sha256(b).digest()


# ---------------------------------------------------------------- draft text

def clean_lines(text):
    """Drop the page footer and header lines the .txt rendering inserts."""
    out = []
    for line in text.split("\n"):
        if re.match(r"^Fassbender\s+Expires .*\[Page \d+\]\s*$", line):
            continue
        if re.match(r"^Internet-Draft\s+Umarise Temporal Proofs\s+\w+ \d{4}\s*$", line):
            continue
        out.append(line.rstrip("\r"))
    return out


def section(lines, start_re, end_re):
    i = next(n for n, l in enumerate(lines) if re.match(start_re, l))
    j = next(n for n, l in enumerate(lines) if n > i and re.match(end_re, l))
    return lines[i:j]


def parse_vectors(lines):
    block = section(lines, r"^D\.1\.\s", r"^D\.2\.\s")
    vectors, cur, label = {}, None, None
    for l in block:
        m = re.match(r"^   Vector (\d)\s*$", l)
        if m:
            cur, label = vectors.setdefault(int(m.group(1)), {}), None
            continue
        if cur is None:
            continue
        m = re.match(r"^\s+(artifact|hash|nonce|leaf):\s+(.*?)\s*$", l)
        if m:
            label = m.group(1)
            cur[label] = m.group(2)
        elif label and re.fullmatch(r"\s+[0-9a-f]+", l):
            cur[label] += l.strip()
    for v in vectors.values():
        v["artifact"] = v["artifact"].strip('"')
    return vectors


def parse_nodes(lines):
    block = section(lines, r"^D\.2\.\s", r"^D\.3\.\s")
    nodes = {}
    for n, l in enumerate(block):
        m = re.match(r"^   (node_12|node_34|root)\s+= SHA-256\(", l)
        if not m:
            continue
        hexs = ""
        for l2 in block[n + 1:]:
            m2 = re.match(r"^\s+= ([0-9a-f]+)\s*$", l2) if not hexs else re.fullmatch(r"\s+([0-9a-f]+)", l2)
            if not m2:
                break
            hexs += m2.group(1)
        nodes[m.group(1)] = hexs
    return nodes


def parse_d3(lines):
    t = "\n".join(section(lines, r"^D\.3\.\s", r"^D\.4\.\s"))
    g = {}
    g["height"] = int(re.search(r"Bitcoin block at height (\d+)", t).group(1))
    m = re.search(r"Block hash:\s+([0-9a-f]{32})\s+([0-9a-f]{32})", t)
    g["block_hash"] = m.group(1) + m.group(2)
    m = re.search(r"Header Merkle root,\s+([0-9a-f]{32})\s+as committed:\s+([0-9a-f]{32})", t)
    g["root_committed"] = m.group(1) + m.group(2)
    m = re.search(r"Header Merkle root,\s+([0-9a-f]{32})\s+as displayed by\s+([0-9a-f]{32})", t)
    g["root_displayed"] = m.group(1) + m.group(2)
    g["rwcp"] = re.search(r"RWCP block\.time\(H\):\s+(\S+Z)", t).group(1)
    g["mtp"] = re.search(r"Median Time Past:\s+(\S+Z)", t).group(1)
    return g


def parse_d4(lines):
    block = section(lines, r"^D\.4\.\s", r"^D\.5\.\s")
    ops = {}
    for l in block:
        m = re.match(r"^\s+(\d+)\s+(append|prepend|sha256)\s*(.*)$", l)
        if m:
            ops[int(m.group(1))] = (m.group(2), m.group(3).split("(")[0].replace("->", "").strip())
    t = "\n".join(block)
    return {"ops": ops,
            "size": int(re.search(r"is (\d+) bytes and records (\d+) operations", t).group(1)),
            "nops": int(re.search(r"is (\d+) bytes and records (\d+) operations", t).group(2))}


def parse_d5(lines):
    block = section(lines, r"^D\.5\.\s", r"^D\.6\.\s")
    proofs, cur = {}, None
    for l in block:
        m = re.match(r"^   \*Vector (\d)\* \((\d+) bytes; SHA-256 of the file:\s*$", l)
        if m:
            cur = {"n": int(m.group(1)), "size": int(m.group(2)), "b64": "", "sha": None}
            proofs[cur["n"]] = cur
            continue
        if cur is None:
            continue
        m = re.fullmatch(r"   ([0-9a-f]{64})\)", l)
        if m and cur["sha"] is None:
            cur["sha"] = m.group(1)
            continue
        if re.fullmatch(r"   [A-Za-z0-9+/=]+", l) and cur["sha"]:
            cur["b64"] += l.strip()
    for p in proofs.values():
        p["bytes"] = base64.b64decode(p["b64"], validate=True)
    return proofs


# ------------------------------------------------------------------ OTS file

class Reader:
    def __init__(self, data):
        self.d, self.i = data, 0

    def byte(self):
        b = self.d[self.i]
        self.i += 1
        return b

    def take(self, n):
        if self.i + n > len(self.d):
            raise ValueError("short read")
        out = self.d[self.i:self.i + n]
        self.i += n
        return out

    def varuint(self):
        v = shift = 0
        while True:
            b = self.byte()
            v |= (b & 0x7F) << shift
            shift += 7
            if not b & 0x80:
                return v

    def varbytes(self):
        return self.take(self.varuint())


def apply(op, msg, arg):
    if op == "sha256":
        return sha(msg)
    if op == "append":
        return msg + arg
    if op == "prepend":
        return arg + msg
    raise ValueError("operation outside the profile: " + op)


def parse_ots(data):
    """Return (file digest, list of (kind, payload, ops-path, message at node))."""
    if not data.startswith(OTS_MAGIC):
        raise ValueError("bad magic")
    r = Reader(data)
    r.i = len(OTS_MAGIC)
    if r.varuint() != 1 or r.byte() != 0x08:
        raise ValueError("version or file hash op")
    digest = r.take(32)
    found = []

    def walk(msg, path, depth=0):
        if depth > 256:
            raise ValueError("recursion limit")
        while True:
            tag = r.byte()
            more = False
            if tag == 0xFF:
                more, tag = True, r.byte()
            if tag == 0x00:
                t8 = r.take(8)
                found.append((t8, r.varbytes(), tuple(path), msg))
            else:
                name = {0x08: "sha256", 0xF0: "append", 0xF1: "prepend"}.get(tag)
                if name is None:
                    raise ValueError("unsupported tag %02x" % tag)
                arg = r.varbytes() if tag in (0xF0, 0xF1) else None
                walk(apply(name, msg, arg), path + [(name, arg)], depth + 1)
            if not more:
                return

    walk(digest, [])
    if r.i != len(data):
        raise ValueError("trailing bytes")
    return digest, found


def bitcoin_branches(found):
    out = []
    for t8, payload, path, msg in found:
        if t8 == BTC_TAG:
            rr = Reader(payload)
            out.append((rr.varuint(), path, msg))
    return out


def pending_count(found):
    return sum(1 for f in found if f[0] == PENDING_TAG)


def verify_anchor_own(artifact, proof, chain):
    """Steps 1 to 8 of the draft's VERIFY-ANCHOR; chain is None or {height: header}."""
    digest, found = parse_ots(proof)
    if sha(artifact) != digest:
        return "invalid", "step 2: hash mismatch"
    branches = bitcoin_branches(found)
    if not branches:
        return "unverifiable", "no Bitcoin attestation"
    if not chain:
        return "unverifiable", "step 7b: no validated chain supplied"
    return "unverifiable", "validated chain supplied but not established by this adapter"


# --------------------------------------------------------------------- cases

def header_bits_target(h):
    bits = int.from_bytes(h[72:76], "little")
    return (bits & 0xFFFFFF) * 256 ** ((bits >> 24) - 3)


def iso(ts):
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def run(raw, draft_text, mutate_proof1=None, quiet=False):
    lines = clean_lines(draft_text)
    vec, nodes = parse_vectors(lines), parse_nodes(lines)
    d3, d4, d5 = parse_d3(lines), parse_d4(lines), parse_d5(lines)
    if mutate_proof1:
        d5[1]["bytes"] = mutate_proof1(d5[1]["bytes"])
    res = []  # (group, id, ok, detail)

    def case(group, cid, ok, detail=""):
        res.append((group, cid, bool(ok), detail))

    g = "D1D2"
    leaves = {}
    for n in range(1, 5):
        v = vec[n]
        h = sha(v["artifact"].encode("ascii"))
        case(g, "D1-v%d-artifact-hash" % n, h.hex() == v["hash"], h.hex()[:16])
        leaf = sha(h + bytes.fromhex(v["nonce"]))
        leaves[n] = leaf
        case(g, "D1-v%d-leaf" % n, leaf.hex() == v["leaf"], leaf.hex()[:16])
    n12, n34 = sha(leaves[1] + leaves[2]), sha(leaves[3] + leaves[4])
    root = sha(n12 + n34)
    case(g, "D2-node_12", n12.hex() == nodes["node_12"], n12.hex()[:16])
    case(g, "D2-node_34", n34.hex() == nodes["node_34"], n34.hex()[:16])
    case(g, "D2-root", root.hex() == nodes["root"], root.hex()[:16])

    g = "D4D5"
    parsed = {}
    for n in range(1, 5):
        p = d5[n]
        b = p["bytes"]
        case(g, "D5-v%d-file" % n,
             len(b) == p["size"] == 1877 and hashlib.sha256(b).hexdigest() == p["sha"],
             "%d bytes sha256 %s" % (len(b), hashlib.sha256(b).hexdigest()[:16]))
        try:
            digest, found = parse_ots(b)
            parsed[n] = (digest, found)
        except ValueError as e:
            case(g, "D5-v%d-parse" % n, False, str(e))
            continue
        case(g, "D5-v%d-message" % n, digest.hex() == vec[n]["hash"], digest.hex()[:16])
        br = bitcoin_branches(found)
        case(g, "D5-v%d-one-bitcoin-attestation-at-%d" % (n, d3["height"]),
             len(br) == 1 and br[0][0] == d3["height"], "%d branch(es)" % len(br))
        if br:
            height, path, endmsg = br[0]
            case(g, "D4-v%d-82-operations" % n, len(path) == d4["nops"] == 82, "%d ops" % len(path))
            case(g, "D5-v%d-replay-to-header-root" % n, endmsg.hex() == d3["root_committed"],
                 endmsg.hex()[:16])
            run_msg = digest
            vals = []
            for name, arg in path:
                run_msg = apply(name, run_msg, arg)
                vals.append(run_msg)
            case(g, "D4-v%d-op2-leaf" % n, path[1][0] == "sha256" and vals[1] == leaves[n],
                 vals[1].hex()[:16])
            case(g, "D4-v%d-op6-root" % n, vals[5] == root, vals[5].hex()[:16])
            if n == 1:
                o = d4["ops"]
                ok = (path[0][0] == "append" and path[0][1].hex() == vec[1]["nonce"]
                      and vals[2 - 1].hex().startswith(o[2][1].rstrip(".")) and path[2][1].hex().startswith(o[3][1].replace("...", "").strip())
                      and vals[3].hex().startswith(o[4][1].rstrip("."))
                      and path[4][1].hex().startswith(o[5][1].replace("...", "").strip())
                      and vals[5].hex().startswith(o[6][1].rstrip(".")))
                case(g, "D4-v1-ops-1-to-6", ok, "trace matches")
                tx = path[39]
                ok40 = (tx[0] == "prepend" and len(tx[1]) == 89 and tx[1].hex().startswith("0100000001")
                        and tx[1].hex().endswith("6a20"))
                ok41 = path[40][0] == "append" and path[40][1].hex() == "689b0e00"
                txid_ok = (path[41][0] == path[42][0] == "sha256"
                           and vals[42].hex().startswith("3cad384e"))
                case(g, "D4-v1-ops-40-41-43", ok40 and ok41 and txid_ok,
                     "prepend 89 bytes, append locktime 689b0e00, txid 3cad384e")
                case(g, "D4-v1-op82-header-root", vals[81].hex().startswith("81383c9c")
                     and len(path) == 82, vals[81].hex()[:16])
            case(g, "D5-v%d-pending-calendar-attestations" % n, pending_count(found) > 0,
                 "%d pending" % pending_count(found))

    g = "D3"
    hdr = {}
    for name in ("blockstream", "mempool"):
        hdr[name] = bytes.fromhex((Path(raw) / ("block-957289-header-%s.hex" % name)).read_text().strip())
    case(g, "D3-two-explorers-same-80-bytes", len(hdr["blockstream"]) == 80 and hdr["blockstream"] == hdr["mempool"],
         "%d bytes" % len(hdr["blockstream"]))
    h = hdr["blockstream"]
    bid = sha(sha(h))[::-1].hex()
    case(g, "D3-block-hash-from-header", bid == d3["block_hash"], bid[:24])
    case(g, "D3-pow-meets-nBits", int(bid, 16) <= header_bits_target(h), "hash <= target(nBits)")
    case(g, "D3-merkle-root-as-committed", h[36:68].hex() == d3["root_committed"], h[36:68].hex()[:16])
    case(g, "D3-merkle-root-as-displayed", h[36:68][::-1].hex() == d3["root_displayed"],
         h[36:68][::-1].hex()[:16])
    case(g, "D3-replay-equals-header-root-all-vectors",
         all(bitcoin_branches(parsed[n][1])[0][2] == h[36:68] for n in parsed if bitcoin_branches(parsed[n][1])) and len(parsed) == 4,
         "%d of 4 proofs" % len(parsed))
    ntime = int.from_bytes(h[68:72], "little")
    case(g, "D3-RWCP-nTime", iso(ntime) == d3["rwcp"], iso(ntime))
    blk = json.loads((Path(raw) / "block-957289-blockstream.json").read_text())
    blk2 = json.loads((Path(raw) / "block-957289-mempool.json").read_text())
    case(g, "D3-height-from-explorers", blk["height"] == blk2["height"] == d3["height"] == EXPECTED_HEIGHT,
         str(blk["height"]))
    case(g, "D3-MTP-from-explorer-mediantime", iso(blk["mediantime"]) == iso(blk2["mediantime"]) == d3["mtp"],
         iso(blk["mediantime"]))

    g = "D6"
    for n in range(1, 5):
        art = vec[n]["artifact"].encode("ascii")
        bad = bytes([art[0] ^ 0x01]) + art[1:]
        out, why = verify_anchor_own(bad, d5[n]["bytes"], {EXPECTED_HEIGHT: h})
        case(g, "D6-negative-v%d-one-byte-artifact-change" % n, out == "invalid", out + " (" + why + ")")
    for n in range(1, 5):
        out, why = verify_anchor_own(vec[n]["artifact"].encode("ascii"), d5[n]["bytes"], None)
        case(g, "D6-unverifiable-v%d-no-validated-chain" % n, out == "unverifiable", out + " (" + why + ")")
    return res, {"vec": vec, "d5": d5, "d3": d3, "hdr": h}


def report(res, label):
    groups = {}
    for gname, cid, ok, detail in res:
        print("CASE %s %s %s %s" % (label, cid, "PASS" if ok else "FAIL", detail))
        groups.setdefault(gname, []).append(ok)
    for gname in sorted(groups):
        print("GROUP %s %s %d of %d" % (label, gname, sum(groups[gname]), len(groups[gname])))
    tot = [ok for _, _, ok, _ in res]
    print("TOTAL %s %d of %d" % (label, sum(tot), len(tot)))


def flip_nonce_byte(b):
    # the 16-byte nonce is the first operation argument; flip one byte of it
    i = b.index(bytes.fromhex("14ed82e243f4aff3f1794e6754bfae3b"))
    return b[:i] + bytes([b[i] ^ 0x01]) + b[i + 1:]


def main():
    raw = Path(sys.argv[1])
    text = (raw / DRAFT).read_text()
    res, ctx = run(raw, text)
    print("ADAPTER timeanchor_adapter draft=%s sha256=%s" % (DRAFT, hashlib.sha256(text.encode()).hexdigest()))
    report(res, "clean")
    ids = {c: ok for _, c, ok, _ in res}
    if "--write" in sys.argv:
        out = Path(sys.argv[sys.argv.index("--write") + 1])
        out.mkdir(parents=True, exist_ok=True)
        for n in range(1, 5):
            (out / ("vector-%d.ots" % n)).write_bytes(ctx["d5"][n]["bytes"])
            (out / ("vector-%d.artifact" % n)).write_bytes(ctx["vec"][n]["artifact"].encode("ascii"))
        (out / "vectors.json").write_text(json.dumps(ctx["vec"], indent=1, sort_keys=True) + "\n")
        print("WROTE extracted vectors to", out)
    if "--tamper" in sys.argv:
        # tamper 1: one hex digit of vector 1's nonce changed in the draft text
        marker = "14ed82e243f4aff3f1794e6754bfae3b"
        assert text.count(marker) >= 1
        t1 = text.replace(marker, "04ed82e243f4aff3f1794e6754bfae3b", 1)  # D.1 occurrence only
        res1, _ = run(raw, t1)
        # tamper 2: one byte of the nonce flipped inside the decoded proof 1
        res2, _ = run(raw, text, mutate_proof1=flip_nonce_byte)
        for label, r in (("tamper-draft-nonce", res1), ("tamper-proof-byte", res2)):
            flipped = [c for _, c, ok, _ in r if ids.get(c) and not ok]
            print("TAMPER %s flipped %d case(s): %s" % (label, len(flipped), ", ".join(flipped)))
            tot = [ok for _, _, ok, _ in r]
            print("TOTAL %s %d of %d" % (label, sum(tot), len(tot)))


if __name__ == "__main__":
    main()
