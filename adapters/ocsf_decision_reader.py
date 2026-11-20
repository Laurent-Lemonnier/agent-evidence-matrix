"""OCSF decision-record reader cells: the pinned agent-evidence-verify reads the format's published samples.

The format is the OCSF API Activity decision record of AID-EMIT-1 (``record_integrity``), as the
Praxis Policy Engine's ``ocsf-audit`` sink writes it. This adapter reads the sink's three published
sample outputs from a checkout of its repository (``reference/plugins/ocsf-audit/SAMPLE-OUTPUT*.md``),
runs them through ``agent_evidence_verify.ocsf_decision`` and prints one line per sample record:

    <file>#<n>\tagrees\t<dimensions>
    <file>#<n>\tdiffers\t<what differs>

The two records of ``SAMPLE-OUTPUT.md`` must read with fingerprint, signature and key binding
``verified`` under the published demo key (the P-256 scalar of 32 bytes 0x42) and one chain; the nine
decision records of the other two files must read as one dense stream with every ruling consistent.
Then one changed byte in each signed record must fail its fingerprint. The reader decides; this script
only extracts the records the samples print and compares.

usage: ocsf_decision_reader.py [--mutation] <checkout of the format's repository>

--mutation injects an earlier duplicate ``disposition`` into the first signed record before the
reader sees it. A mutation that does not turn that line into ``differs`` is a broken comparison.

Exit codes: 0 every record agrees; 1 at least one differs; 2 setup error (no checkout, no reader).
"""
from __future__ import annotations

import json
import pathlib
import re
import sys

PLUGIN = pathlib.Path("reference") / "plugins" / "ocsf-audit"
SIGNED = "SAMPLE-OUTPUT.md"
STREAM = ("SAMPLE-OUTPUT-DECISIONS.md", "SAMPLE-OUTPUT-PROVENANCE.md")


def records(path: pathlib.Path) -> list[str]:
    out = []
    for block in re.findall(r"```(?:jsonc|text)\n(.*?)```", path.read_text(encoding="utf-8"), re.S):
        for part in re.split(r"^// =====.*$", block, flags=re.M):
            body = "\n".join(line for line in part.splitlines() if not line.startswith("//")).strip()
            if body.startswith("{"):
                out.append(json.dumps(json.loads(body), separators=(",", ":")))
    return out


def main(argv: list[str]) -> int:
    mutation = argv[:1] == ["--mutation"]
    argv = argv[1:] if mutation else argv
    if len(argv) != 1:
        print(__doc__.split("\n\n")[-2], file=sys.stderr)
        return 2
    root = pathlib.Path(argv[0]) / PLUGIN
    try:
        from cryptography.hazmat.primitives.asymmetric import ec

        from agent_evidence_verify import ocsf_decision as o
        signed = records(root / SIGNED)
        stream = [r for name in STREAM for r in records(root / name)]
    except (ImportError, OSError, ValueError) as exc:
        print(f"setup error: {exc}", file=sys.stderr)
        return 2
    demo = ec.derive_private_key(int.from_bytes(b"\x42" * 32, "big"), ec.SECP256R1()).public_key()
    policy = {"keys": [o.jwk(demo, "demo-key-2026-07", "org-f3576cf6")]}
    if mutation:
        signed[0] = signed[0].replace('"disposition":"Logged"',
                                      '"disposition":"Blocked","disposition_id":2,"disposition":"Logged"', 1)
    agree = differ = 0

    def line(name: str, rec: dict, want: dict) -> None:
        nonlocal agree, differ
        got = {k: rec[k]["status"] for k in want}
        if got == want:
            agree += 1
            print(f"{name}\tagrees\t{', '.join(f'{k} {v}' for k, v in got.items())}")
        else:
            differ += 1
            print(f"{name}\tdiffers\t" + "; ".join(f"{k}: expected {want[k]}, read {got[k]}"
                                                   for k in want if got[k] != want[k]))

    report = o.read("\n".join(signed).encode(), trust_policy=policy)
    for i, rec in enumerate(report["records"]):
        line(f"{SIGNED}#{i + 1}", rec, {k: o.VERIFIED for k in o.RECORD_DIMENSIONS})
    chain = {k: report[k]["status"] for k in ("chain_links", "chain_gaps", "chain_head")}
    print(f"chain\t{', '.join(f'{k} {v}' for k, v in chain.items())}; tail {report['tail']['status']}")
    report = o.read("\n".join(stream).encode())
    for i, rec in enumerate(report["records"]):
        line(f"stream#{i + 1}", rec, {"structural_validity": o.VERIFIED, "decision_consistency": o.VERIFIED})
    print(f"stream\tstream_sequence {report['stream_sequence']['status']}, "
          f"stream_head {report['stream_head']['status']}")
    flips = 0
    for i, text in enumerate(signed if not mutation else signed[1:]):
        changed = text.replace('"severity_id":1', '"severity_id":2', 1)
        flips += o.read(changed.encode(), trust_policy=policy)["records"][0]["fingerprint"]["status"] == o.FAILED
    total = len(signed) + len(stream)
    ok_chain = all(v == o.VERIFIED for v in chain.values())
    print(f"summary\trecords {agree} of {total} agree, {differ} differ; chain "
          f"{'verified' if ok_chain else 'not verified'}; one changed byte fails the fingerprint "
          f"{flips} of {len(signed) - mutation}")
    if mutation and differ == 0:
        print("setup error: the mutation changed no dimension", file=sys.stderr)
        return 2
    return 0 if differ == 0 and ok_chain and flips == len(signed) - mutation else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
