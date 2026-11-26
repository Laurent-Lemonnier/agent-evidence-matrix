"""Author replay for the proposed project 4 reference-comparison vectors.

Pass the exact COSE file pinned in records/pria-reference/vectors.json.
The fixture supplies the candidate target. The three verdicts address digest
comparison only. An unreadable or unpinned target is a setup error.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("statement", type=Path)
    parser.add_argument("--mutation", action="store_true", help="flip a bit in the reference digest")
    args = parser.parse_args()
    vectors = Path(__file__).resolve().parents[1] / "records/pria-reference/vectors.json"
    try:
        import cbor2

        manifest = json.loads(vectors.read_bytes())
        raw = args.statement.read_bytes()
        if hashlib.sha256(raw).hexdigest() != manifest["statement_sha256"]:
            raise ValueError("statement does not match the fixture pin")
        tagged = cbor2.loads(raw)
        if not isinstance(tagged, cbor2.CBORTag) or tagged.tag != 18:
            raise ValueError("expected a tagged COSE_Sign1")
        protected, _, payload, _ = tagged.value
        inputs = {
            "to-be-signed": cbor2.dumps(["Signature1", protected, b"", payload], canonical=True),
            "exact-envelope": raw,
        }
        reference = bytes.fromhex(manifest["reference_digest"])
        if args.mutation:
            reference = reference[:-1] + bytes([reference[-1] ^ 1])
    except (ImportError, OSError, ValueError, TypeError) as error:
        print(f"setup error: {error}", file=sys.stderr)
        return 2

    agrees = 0
    for case in manifest["cases"]:
        preimage = inputs.get(case["rule"])
        if preimage is None:
            actual = "indeterminate"
        elif hashlib.sha256(preimage).digest() == reference:
            actual = "match"
        else:
            actual = "mismatch"
        equal = actual == case["expected"]
        agrees += equal
        print(f"{case['id']}\t{'agrees' if equal else 'differs'}\t{actual}")
    total = len(manifest["cases"])
    print(f"{agrees}/{total} agree")
    return 0 if agrees == total else 1


if __name__ == "__main__":
    sys.exit(main())
