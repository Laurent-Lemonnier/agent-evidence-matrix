"""Adapter: the Python rfc8785 package behind the a2a-jcs-v01 verifier contract.

Contract (agent-evidence-vectors docs/reference/corpus-readers.md):
  <verifier> rfc8785 <input.json>   exit 0 and {"canonical_utf8_hex": ...} on stdout,
                                    exit 1 when the input has no canonical form.
The canonicalizer is the Python rfc8785 package.
Nothing of ours is mixed in.
"""
import json
import os
import sys


import rfc8785  # noqa: E402


def main(argv):
    # card-signing-input would need the top-level signatures member removed first; this adapter does not do that.
    if len(argv) != 3 or argv[1] != "rfc8785":
        print("usage: rfc8785_cli.py rfc8785 <input.json>", file=sys.stderr)
        return 2
    raw = open(argv[2], "rb").read()
    try:
        value = json.loads(raw.decode("utf-8"), parse_constant=_refuse, object_pairs_hook=_no_duplicates)
        out = rfc8785.dumps(value)
    except Exception as exc:  # any refusal means: no canonical form
        print(type(exc).__name__, file=sys.stderr)
        return 1
    print(json.dumps({"canonical_utf8_hex": out.hex()}))
    return 0


def _no_duplicates(pairs):
    # RFC 8785 section 3.1 takes I-JSON input, and RFC 7493 section 2.3 forbids duplicate member names;
    # json.loads keeps the last value, which would canonicalize text that has no canonical form
    names = [key for key, _ in pairs]
    if len(names) != len(set(names)):
        raise ValueError("duplicate member name")
    return dict(pairs)


def _refuse(token):
    raise ValueError(token)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
