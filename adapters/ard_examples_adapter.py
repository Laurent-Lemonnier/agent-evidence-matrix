"""Adapter: the ARD conformance examples (ards-project/ard-spec conformance/examples) read under two texts.

usage: ard_examples_adapter.py <ard-spec checkout>

For every JSON document under conformance/examples/*/ (read with a strict I-JSON parser: a duplicate
member, NaN or Infinity refuses the document) and every entry in it, prints tab-separated lines:

  <example>/<file>#<n>  attestation-digest  agrees|contradicted|cannot-tell  <detail>
      every attestations[] item with a digest whose uri names a file vendored beside the example:
      SHA-256 of that file against the stated digest (64 hex digits, read without case; anything else is
      cannot-tell); a uri with no vendored file is cannot-tell
  <example>/<file>#<n>  draft-bu-00  agrees|contradicted  <missing parts>
      draft-bu-dawn-ard-discovery-00 sections 3.5 and 3.5.2 item 1, read as prose: a trustManifest
      MUST carry subject and signature; an entry referenced by url whose trustManifest carries
      attestations MUST carry the top-level digest; each attestation statement MUST be signed or
      carry a signed subject claim (an attestation object with no signature or subject member has
      neither)
  <example>/<file>#<n>  repository-spec  agrees  identity present
      the repository's own spec (spec/ard.md v0.91, section 4.5) constrains a trustManifest only by
      identity
  <example>/<file>#<n>  manifest-only  unsupported  no trustManifest: no digest or signature to recompute

then SUMMARY lines. Exit 0 when every document parsed, 2 otherwise.
"""
import hashlib
import json
import pathlib
import sys


class Refusal(ValueError):
    pass


def strict_loads(text):
    def pairs(items):
        out = {}
        for k, v in items:
            if k in out:
                raise Refusal(f"duplicate_member:{k}")
            out[k] = v
        return out

    def const(name):
        raise Refusal(f"non_json_constant:{name}")

    return json.loads(text, object_pairs_hook=pairs, parse_constant=const)


def entry_lines(where, entry, folder):
    tm = entry.get("trustManifest")
    if not isinstance(tm, dict):
        return [(where, "manifest-only", "unsupported", "no trustManifest: no digest or signature to recompute")]
    out = []
    atts = tm.get("attestations") or []
    for i, att in enumerate(atts):
        if not att.get("digest"):
            continue
        name = str(att.get("uri", "")).rsplit("/", 1)[-1]
        local = folder / name
        if not name or not local.is_file():
            out.append((where, "attestation-digest", "cannot-tell", f"attestations[{i}] {name or 'no uri'} not vendored"))
            continue
        alg, _, want = att["digest"].partition(":")
        if alg != "sha256":
            out.append((where, "attestation-digest", "cannot-tell", f"attestations[{i}] algorithm {alg} not read"))
            continue
        if len(want) != 64 or any(c not in "0123456789abcdefABCDEF" for c in want):
            out.append((where, "attestation-digest", "cannot-tell", f"attestations[{i}] digest is not 64 hex digits"))
            continue
        have = hashlib.sha256(local.read_bytes()).hexdigest()
        verdict = "agrees" if have == want.lower() else "contradicted"  # hex is read without case
        out.append((where, "attestation-digest", verdict, f"attestations[{i}] {name} sha256 {have[:12]}"))
    missing = [m for m in ("subject", "signature") if m not in tm]
    if "url" in entry and atts and "digest" not in entry:
        missing.append("top-level digest (url-referenced entry with attestations)")
    unsigned = [i for i, a in enumerate(atts) if not ({"signature", "subject"} & set(a))]
    if unsigned:
        missing.append("signed attestation statement (attestations " + ", ".join(map(str, unsigned)) + ")")
    out.append((where, "draft-bu-00", "contradicted" if missing else "agrees",
                "missing: " + "; ".join(missing) if missing else "subject, signature, digest and signed statements present"))
    out.append((where, "repository-spec", "agrees" if tm.get("identity") else "contradicted",
                "identity present" if tm.get("identity") else "identity missing"))
    return out


def main(root):
    base = pathlib.Path(root) / "conformance" / "examples"
    lines, failed = [], False
    for doc in sorted(base.glob("*/*.json")):
        rel = f"{doc.parent.name}/{doc.name}"
        try:
            data = strict_loads(doc.read_text(encoding="utf-8"))
        except (Refusal, ValueError) as exc:
            lines.append((rel, "document", "refused", str(exc)))
            failed = True
            continue
        entries = data.get("entries") if isinstance(data, dict) else None
        if not isinstance(entries, list):
            lines.append((rel, "document", "unsupported", "no entries array"))
            continue
        for n, entry in enumerate(entries):
            lines += entry_lines(f"{rel}#{n}", entry, doc.parent)
    for line in lines:
        print("\t".join(line))
    for check in ("attestation-digest", "draft-bu-00", "repository-spec", "manifest-only"):
        got = [v for _, c, v, _ in lines if c == check]
        if got:
            tally = ", ".join(f"{v} {got.count(v)}" for v in sorted(set(got)))
            print(f"SUMMARY {check}: {len(got)} ({tally})")
    return 2 if failed else 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    sys.exit(main(sys.argv[1]))
