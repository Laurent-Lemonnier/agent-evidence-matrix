"""Edit detection: does a log format let a verifier see an edit to a committed log?

Six edits to one valid log, each judged by a verifier function: drop an entry, swap two entries, flip
a status field, rewrite a link to the previous entry, edit an entry's body, truncate the tail. A
seventh edit, to the copy a consumer reads when the format carries one, is supplied by the driver.
An edit counts as detected when the verifier's verdict for the edited log differs from its verdict
for the original; an original the verifier already rejects makes every count meaningless and is
reported as such, and a log with no entries is cannot-tell (empty_denominator), never a pass.

usage: edit_detection.py aer1 <AER-1 kit checkout>
    runs the six edits on the valid five-entry timeline v07-valid-5 of the kit's chain-vectors-v07.json,
    judged by the Section 7 chain reading in adapters/aer1_adapter.py (verify_chain_07)
Prints one line per edit and a SUMMARY line; exit 0 when the count was taken, 2 on a setup error.
"""
from __future__ import annotations

import base64
import copy
import importlib.util
import json
import pathlib
import sys


def edits(log, status_key, link_key, body_key, body_value):
    """The six edits as (name, edited log); each leaves the original untouched."""
    out = []
    a = copy.deepcopy(log)
    del a[len(a) // 2]
    out.append(("drop an entry", a))
    b = copy.deepcopy(log)
    b[1], b[2] = b[2], b[1]
    out.append(("swap two entries", b))
    c = copy.deepcopy(log)
    c[1][status_key] = "FLIPPED" if c[1].get(status_key) != "FLIPPED" else "AGAIN"
    out.append((f"flip {status_key} of entry 1", c))
    d = copy.deepcopy(log)
    d[2][link_key] = "f" * 64
    out.append((f"rewrite {link_key} of entry 2", d))
    e = copy.deepcopy(log)
    e[1][body_key] = body_value
    out.append((f"edit {body_key} of entry 1", e))
    f = copy.deepcopy(log)
    del f[-1]
    out.append(("truncate the tail", f))
    return out


def detect(log, verify, named_edits):
    """(lines, detected, total) for the edits under ``verify`` (returns a truthy failure or a falsy pass)."""
    if not log:
        return ["cannot-tell  empty_denominator: the log has no entries"], 0, 0
    if verify(log):
        return ["cannot-tell  the unedited log already fails the verifier"], 0, 0
    lines, hit = [], 0
    for name, edited in named_edits:
        caught = bool(verify(edited))
        hit += caught
        lines.append(f"{'detected' if caught else 'MISSED':9} {name}")
    return lines, hit, len(named_edits)


def aer1(kit):
    here = pathlib.Path(__file__).resolve().parent
    spec = importlib.util.spec_from_file_location("aer1_adapter", here / "aer1_adapter.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    vectors = json.loads((pathlib.Path(kit) / "base" / "chain-vectors-v07.json").read_text())["vectors"]
    log = next(v["timeline"] for v in vectors if v["name"] == "v07-valid-5")
    body = base64.b64encode(b'{"job":"job-7a1f","entry":1,"tag":"edited"}').decode()
    return detect(log, mod.verify_chain_07, edits(log, "provenance_class", "prev_digest", "canonical_bytes", body))


def main(argv):
    if len(argv) != 2 or argv[0] != "aer1":
        print(__doc__, file=sys.stderr)
        return 2
    lines, hit, total = aer1(argv[1])
    for line in lines:
        print(line)
    print(f"SUMMARY detected {hit} of {total}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
