"""Adapter: the EATF Python JCS function behind the a2a-jcs-v01 verifier contract.

Contract (agent-evidence-vectors docs/reference/corpus-readers.md):
  <verifier> rfc8785 <input.json>   exit 0 and {"canonical_utf8_hex": ...} on stdout,
                                    exit 1 when the input has no canonical form,
                                    exit 2 for anything else (errored, never a refusal).
The canonicalizer is eatf_verifier.canonical.jcs, imported from a local clone given by EATF_LIB_PYTHON,
and the parse is json.loads unmodified, as theirs is: nothing of ours decides a refusal. Each refusal
names the path that made it on stderr (refused-by-parser, refused-by-profile, refused-by-encoder), and
with EATF_CLASS_LOG set the same class is appended there, one line per input, so a run records which
code refused each vector. card-signing-input is not implemented here; asking for it is a usage error.
"""
import json
import os
import sys

sys.path.insert(0, os.environ["EATF_LIB_PYTHON"])
import rfc8785  # noqa: E402  (their dependency, installed with their lib-python)
from eatf_verifier.canonical import jcs  # noqa: E402


def outcome(raw):
    """(exit code, class, canonical bytes or None) for one input."""
    try:
        value = json.loads(raw.decode("utf-8"))  # their parse, unmodified
    except ValueError as exc:  # JSONDecodeError and UnicodeDecodeError
        return 1, f"refused-by-parser {type(exc).__name__}", None
    try:
        return 0, "canonical", jcs(value)
    except rfc8785.CanonicalizationError as exc:  # their designed refusals, the profile's included
        return 1, f"refused-by-profile {type(exc).__name__}", None
    except UnicodeEncodeError as exc:  # a lone surrogate reached the encoder: refused, on an undesigned path
        return 1, f"refused-by-encoder {type(exc).__name__}", None
    except Exception as exc:  # anything else is a crash, never a refusal
        return 2, f"errored {type(exc).__name__}", None


def main(argv):
    if len(argv) != 3 or argv[1] != "rfc8785":
        print("usage: eatf_jcs_cli.py rfc8785 <input.json>", file=sys.stderr)
        return 2
    raw = open(argv[2], "rb").read()
    code, cls, out = outcome(raw)
    if os.environ.get("EATF_CLASS_LOG"):
        with open(os.environ["EATF_CLASS_LOG"], "a", encoding="utf-8") as log:
            log.write(f"{os.path.basename(argv[2])}\t{cls}\n")
    if code:
        print(cls, file=sys.stderr)
        return code
    print(json.dumps({"canonical_utf8_hex": out.hex()}))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
