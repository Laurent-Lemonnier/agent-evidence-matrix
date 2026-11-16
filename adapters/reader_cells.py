"""Reader cells: the pinned agent-evidence-verify judges record bytes a project says are RFC 8785.

For every `*.jcs` file under each named checkout, this writes one case and one policy for the claim
`jcs_canonical/v1` (target rfc8785: are these bytes the RFC 8785 canonical form of the JSON value they
encode?), runs the installed `agent-evidence-verify` command on it, and prints one line per file:

    <label>/<path>\t<decision>\t<reason>

then one summary line per label. The reader, not this script, decides: this script only builds the
case, binds the file by length and SHA-256, and copies the decision out.

usage: reader_cells.py [--mutation <label>/<path>] <label>=<checkout> [<label>=<checkout> ...]

--mutation names one file whose bytes are rewritten with its first two object members swapped before
the reader sees it (the copy is in a scratch directory; the checkout is not touched). A mutation that
the reader does not turn into a different decision on that line is a broken comparison, and a mutation
that names no file it reads is a setup error (exit 2): it would leave the run unmutated and passing.

Exit codes: 0 every file supported; 1 at least one decision is not supported (the comparison failed);
2 setup error (missing checkout, no *.jcs file, the reader exited 2 or is not installed).
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile

READER = "agent-evidence-verify"


class _Obj(list):
    """An object's members in their written order."""


def swap_first_members(raw: bytes) -> bytes:
    """The same JSON value with its first two top-level members written in the other order."""
    value = json.loads(raw, object_pairs_hook=_Obj)
    if not isinstance(value, _Obj) or len(value) < 2:
        sys.exit("mutation: the file is not an object with two members")
    value[0], value[1] = value[1], value[0]

    def dump(v):
        if isinstance(v, _Obj):
            return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + dump(x) for k, x in v) + "}"
        if isinstance(v, list):
            return "[" + ",".join(dump(x) for x in v) + "]"
        return json.dumps(v, ensure_ascii=False)
    return dump(value).encode("utf-8")


def judge(root: pathlib.Path, rel: str, work: pathlib.Path) -> tuple[str, str]:
    data = (root / rel).read_bytes()
    binding = {"path": rel, "sha256": hashlib.sha256(data).hexdigest(), "length": len(data)}
    case_id = "jcs-" + hashlib.sha256(rel.encode()).hexdigest()[:16]
    case = {"schema_version": "probity-case/v1", "case_id": case_id,
            "artifacts": {"input": binding, "claimed": binding}}
    policy = {"schema_version": "probity-policy/v1",
              "assessments": {case_id: {"claim_type": "jcs_canonical/v1", "target": "rfc8785",
                                        "input": "input", "claimed": "claimed"}}}
    (work / "case.json").write_text(json.dumps(case))
    (work / "policy.json").write_text(json.dumps(policy))
    out = subprocess.run([READER, str(work / "case.json"), "--policy", str(work / "policy.json"),
                          "--artifact-root", str(root), "--json"], capture_output=True, text=True)
    if out.returncode != 0:
        print(f"setup: the reader exited {out.returncode} on {rel}: {out.stderr.strip()}", file=sys.stderr)
        sys.exit(2)
    result = json.loads(out.stdout)
    return result["decision"], result["reason"]


def main(argv: list[str]) -> int:
    mutation = None
    if argv[:1] == ["--mutation"]:
        if len(argv) < 2:
            print(__doc__, file=sys.stderr)
            return 2
        mutation, argv = argv[1], argv[2:]
    if not argv or any("=" not in a for a in argv):
        print(__doc__, file=sys.stderr)
        return 2
    if shutil.which(READER) is None:
        print(f"setup: {READER} is not installed", file=sys.stderr)
        return 2
    failed = False
    mutated = False
    with tempfile.TemporaryDirectory() as tmp:
        work = pathlib.Path(tmp)
        for arg in argv:
            label, checkout = arg.split("=", 1)
            root = pathlib.Path(checkout)
            files = sorted(str(p.relative_to(root)) for p in root.rglob("*.jcs") if ".git" not in p.parts)
            if not files:
                print(f"setup: no *.jcs file under {label}", file=sys.stderr)
                return 2
            supported = 0
            for rel in files:
                base = root
                if mutation == f"{label}/{rel}":
                    base = work / "mut"
                    (base / rel).parent.mkdir(parents=True, exist_ok=True)
                    (base / rel).write_bytes(swap_first_members((root / rel).read_bytes()))
                    mutated = True
                decision, reason = judge(base, rel, work)
                supported += decision == "supported"
                failed |= decision != "supported"
                print(f"{label}/{rel}\t{decision}\t{reason}")
            print(f"SUMMARY {label}: {supported} of {len(files)} supported")
    if mutation is not None and not mutated:
        print(f"setup: --mutation {mutation} names no file this run read", file=sys.stderr)
        return 2
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
