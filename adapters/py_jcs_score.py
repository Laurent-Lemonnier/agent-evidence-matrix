"""Scores the matrix's own Python reader (agent-evidence-verify, ``adapters.jcs_canonical.canonical``) the way
adapters/jcs_function_score.mjs scores a JavaScript function: the rfc8785 cases of vectors-a2a-jcs-v01, then the four
parse-layer probes (two duplicate members, a surrogate written as UTF-8 bytes, a raw 0xFF byte).

    python -I adapters/py_jcs_score.py CORPUS_DIR

The reader receives text, so the bytes are decoded first with strict UTF-8, as every caller of it does; a decode error is
a refusal. Exit 0 when the run completed, 2 when the setup failed.
"""
import hashlib
import json
import pathlib
import re
import sys

# The same cases adapters/jcs_function_score.mjs scores: a file directly under a directory named a<digit>..., the
# card-signing-input group a2-signatures-exclusion left out.
CASE_DIR = re.compile(r"a\d")


def cases(corpus: pathlib.Path):
    """The (case, input bytes) pairs scored on the rfc8785 target, in path order."""
    for path in sorted(corpus.rglob("*.json")):
        if not CASE_DIR.match(path.parent.name) or path.parent.name.startswith("a2-signatures-exclusion"):
            continue
        case = json.loads(path.read_text(encoding="utf-8"))
        accept = case.get("disposition") == "MUST-ACCEPT" and (case.get("expected") or {}).get("canonical_utf8_hex")
        reject = case.get("disposition") == "MUST-REJECT" and case.get("rejection_layer") == "canonicalization"
        if accept or reject:
            yield case, bool(accept), case_bytes(case)


def case_bytes(case: dict) -> bytes:
    """input_raw as UTF-8, else the parsed input re-serialized; a lone surrogate stays a \\u escape, as in JSON.stringify."""
    text = case["input_raw"] if "input_raw" in case else json.dumps(case["input"], ensure_ascii=False)
    return text.encode("utf-8", "backslashreplace")


PROBES = [
    ("duplicate-member", b'{"a":1,"a":2}'),
    ("duplicate-member-name", b'{"name":"Good","name":"Evil"}'),
    ("surrogate-as-utf8-bytes", bytes.fromhex("7b2261223a22eda080227d")),
    ("invalid-utf8-ff", bytes.fromhex("7b2261223a22ff227d")),
]


def main(argv):
    if len(argv) != 2:
        print("SETUP usage: py_jcs_score.py CORPUS_DIR")
        return 2
    try:
        from importlib.metadata import version

        from agent_evidence_verify.adapters import jcs_canonical
    except ImportError as exc:  # a missing reader is a setup error, never a result
        print(f"SETUP {exc}")
        return 2
    src = pathlib.Path(jcs_canonical.__file__).read_bytes()
    print(f"python {sys.version.split()[0]}")
    print(f"agent-evidence-verify {version('agent-evidence-verify')} jcs_canonical.py sha256 {hashlib.sha256(src).hexdigest()}"
          " entry canonical input strict UTF-8 decode of the bytes")

    def call(raw: bytes) -> bytes:
        return jcs_canonical.canonical("rfc8785", raw.decode("utf-8"))

    scored = passed = 0
    for case, accept, raw in cases(pathlib.Path(argv[1])):
        scored += 1
        try:
            out, err = call(raw).hex(), None
        except (ValueError, UnicodeError) as exc:
            out, err = None, f"{type(exc).__name__}: {exc}"
        ok = out == case["expected"]["canonical_utf8_hex"] if accept else err is not None
        if ok:
            passed += 1
        else:
            print(f"FAIL {case['id']} {'MUST-ACCEPT' if accept else 'MUST-REJECT'} got={'REFUSED ' + err if err else out}")
    if scored == 0:
        print(f"SETUP no rfc8785 case found under {argv[1]}: a run that scored nothing is not a result")
        return 2
    print(f"scored={scored} pass={passed} fail={scored - passed} (rfc8785 cases of {pathlib.Path(argv[1]).name})")
    refused_all = True
    for name, raw in PROBES:
        try:
            line = f"accepted {call(raw).hex()}"
            refused_all = False
        except (ValueError, UnicodeError):
            line = "refused"
        print(f"PROBE {name} input={raw.hex()} {line}")
    print(f"PROBES {'all 4 refused' if refused_all else 'an input with no canonical form was accepted'}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
