"""INFORMATIONAL adapter: AER-1's own JSON serialization (draft-zambo-aer1-26 Section 7.1, as written in
aer1_adapter.py ser()) behind the a2a-jcs-v01 verifier contract.

Contract (agent-evidence-vectors docs/reference/corpus-readers.md):
  <verifier> rfc8785 <input.json>   exit 0 and {"canonical_utf8_hex": ...} on stdout,
                                    exit 1 when the input has no canonical form.
AER-1 does not claim RFC 8785 (draft section 12: it carries the producer's exact bytes and 'rather than
mandating a canonicalization scheme such as ... RFC8785'), so a difference here is a measurement of how
the two serializations differ, never a failed claim. Nothing of ours is mixed in.
"""
import importlib.util
import json
import sys
from pathlib import Path

spec = importlib.util.spec_from_file_location("aer1_adapter", Path(__file__).resolve().parent / "aer1_adapter.py")
A = importlib.util.module_from_spec(spec)
spec.loader.exec_module(A)


def _refuse(token):
    raise ValueError(token)


def main(argv):
    if len(argv) != 3 or argv[1] not in ("rfc8785", "card-signing-input"):
        print("usage: aer1_ser_cli.py rfc8785 <input.json>", file=sys.stderr)
        return 2
    raw = open(argv[2], "rb").read()
    try:
        value = json.loads(raw.decode("utf-8"), parse_constant=_refuse)
        out = A.ser(value).encode("utf-8")
    except Exception as exc:
        print(type(exc).__name__, file=sys.stderr)
        return 1
    print(json.dumps({"canonical_utf8_hex": out.hex()}))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
