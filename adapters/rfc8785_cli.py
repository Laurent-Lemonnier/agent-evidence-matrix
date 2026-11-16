"""Adapter: the Python rfc8785 package behind the a2a-jcs-v01 verifier contract.

Contract (agent-evidence-vectors docs/reference/corpus-readers.md):
  <verifier> rfc8785 <input.json>   exit 0 and {"canonical_utf8_hex": ...} on stdout,
                                    exit 1 when the input has no canonical form,
                                    exit 2 for anything else (errored, never a refusal).
The canonicalizer is the Python rfc8785 package; the parse refuses what I-JSON forbids.
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
    try:
        raw = open(argv[2], "rb").read()
    except OSError as exc:  # an input that cannot be read was never judged
        print("errored", type(exc).__name__, file=sys.stderr)
        return 2
    try:
        value = json.loads(raw.decode("utf-8"), parse_constant=_refuse, object_pairs_hook=_no_duplicates)
    except RecursionError as exc:  # the parser's stack, not the input, ran out: not a refusal
        print("errored", type(exc).__name__, file=sys.stderr)
        return 2
    except ValueError as exc:  # JSONDecodeError, UnicodeDecodeError, a duplicate member or a non-finite number
        print("refused-by-parser", type(exc).__name__, file=sys.stderr)
        return 1
    try:
        out = rfc8785.dumps(value)
    except rfc8785.CanonicalizationError as exc:
        print("refused-by-canonicalizer", type(exc).__name__, file=sys.stderr)
        return 1
    except UnicodeEncodeError as exc:  # a lone surrogate reached the encoder
        print("refused-by-encoder", type(exc).__name__, file=sys.stderr)
        return 1
    except Exception as exc:  # anything else is a crash, never a refusal
        print("errored", type(exc).__name__, file=sys.stderr)
        return 2
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
