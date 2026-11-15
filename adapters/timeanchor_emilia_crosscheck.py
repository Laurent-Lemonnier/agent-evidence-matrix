"""Run the independent verifier core (EMILIA, release v0.1.0-draft-06) on the
Appendix D proofs extracted from draft -08, and compare its vector files.

Usage: venv/bin/python -I adapters/timeanchor_emilia_crosscheck.py <raw-dir> <their-repo-dir>

This script puts <their-repo-dir>/src on sys.path and imports their package:
that is the replay, so their code runs in this process (standard library only,
no network, no key).  Header source: the explorer header is supplied as
a plain in-memory source.  It is not a validated most-work chain, so the
`valid` outcome their code would return with it is NOT scored; only the
branch replay, the three invalid/unverifiable outcomes the draft states, and
byte equality of their vectors with ours are scored.
"""
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import timeanchor_adapter as ta

raw, repo = Path(sys.argv[1]), Path(sys.argv[2])
sys.path.insert(0, str(repo / "src"))
from scitt_time_anchor import BlockHeader, Outcome, ProofBundle, parse_detached_timestamp, verify_anchor

lines = ta.clean_lines((raw / ta.DRAFT).read_text())
vec, d5, d3 = ta.parse_vectors(lines), ta.parse_d5(lines), ta.parse_d3(lines)
header = bytes.fromhex((raw / "block-957289-header-blockstream.hex").read_text().strip())
manifest = json.loads((repo / "vectors" / "manifest.json").read_text())


class Source:
    def __init__(self, headers, depth):
        self.headers, self.depth = headers, depth

    def header_by_height(self, h):
        return self.headers.get(h)

    def confirmations_on(self, h):
        return self.depth


cases = []


def case(cid, ok, detail=""):
    cases.append(ok)
    print("CASE emilia %s %s %s" % (cid, "PASS" if ok else "FAIL", detail))


for n in range(1, 5):
    theirs = (repo / "vectors" / ("vector-%d.ots" % n)).read_bytes()
    ours = d5[n]["bytes"]
    case("v%d-their-file-equals-draft-08-extraction" % n, theirs == ours,
         "%d bytes sha256 %s" % (len(theirs), hashlib.sha256(theirs).hexdigest()[:16]))
    parsed = parse_detached_timestamp(ours)
    br = parsed.bitcoin_branches
    case("v%d-their-parser-one-branch-82-ops-height-957289" % n,
         len(br) == 1 and br[0].height == 957289 and len(br[0].operations) == 82, "")
    case("v%d-their-replay-equals-draft-header-root" % n,
         br[0].replay_sha256_profile(parsed.message).hex() == d3["root_committed"], "")
    art = vec[n]["artifact"].encode("ascii")
    bundle = ProofBundle(ours, "sha256:" + vec[n]["hash"])
    # D.6 second vector: no validated chain -> unverifiable
    r = verify_anchor(art, bundle, Source({}, None))
    case("v%d-D6-no-validated-chain-unverifiable" % n, r.outcome == Outcome.UNVERIFIABLE, r.outcome.value)
    # D.6 first vector: one byte of the artifact changed -> invalid
    bad = bytes([art[0] ^ 1]) + art[1:]
    r = verify_anchor(bad, ProofBundle(ours, "sha256:" + hashlib.sha256(bad).hexdigest()), Source({}, None))
    case("v%d-D6-artifact-byte-changed-invalid" % n, r.outcome == Outcome.INVALID, r.outcome.value)

for k in ("batch_root", "node_12", "node_34"):
    key = {"batch_root": "root"}.get(k, k)
    case("manifest-%s-equals-draft" % k, manifest[k] == ta.parse_nodes(lines)[key], "")
case("manifest-header-root-internal-equals-draft", manifest["header_merkle_root_internal"] == d3["root_committed"], "")
case("manifest-RWCP-equals-draft", ta.iso(manifest["reference_wall_clock_projection"]) == d3["rwcp"], "")

# informational, not scored: their core with the unvalidated explorer header
for n in range(1, 5):
    r = verify_anchor(vec[n]["artifact"].encode("ascii"), ProofBundle(d5[n]["bytes"], "sha256:" + vec[n]["hash"]),
                      Source({957289: BlockHeader(header)}, 18583))
    print("INFO emilia v%d with unvalidated explorer header and depth 18583 (tip 975871 from one explorer): %s height=%s"
          % (n, r.outcome.value, r.block_height))
print("TOTAL emilia %d of %d" % (sum(cases), len(cases)))

# second angle: one byte of vector 1's nonce flipped in their own file
theirs = (repo / "vectors" / "vector-1.ots").read_bytes()
i = theirs.index(bytes.fromhex(vec[1]["nonce"]))
bad = theirs[:i] + bytes([theirs[i] ^ 1]) + theirs[i + 1:]
pb = parse_detached_timestamp(bad)
replay = pb.bitcoin_branches[0].replay_sha256_profile(pb.message).hex()
print("TAMPER emilia v1 nonce byte flipped: file equals draft extraction=%s; their replay equals draft header root=%s"
      % (bad == d5[1]["bytes"], replay == d3["root_committed"]))

