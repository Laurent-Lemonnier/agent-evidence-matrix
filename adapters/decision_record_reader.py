"""Decision-record reader cells: the pinned agent-evidence-verify reads the format's published cases.

The format is the action-binding attachment beside a decision record (documents carrying
``"profile": "dps-action-binding"``, ``"profile_version": "0.3.0"``). This adapter reads the
format's own published test data from a checkout of its repository
(``extensions/action-binding/tests/cases.json`` and ``vectors.json``), runs every binding case
through ``agent_evidence_verify.decision_record`` and compares each dimension with the case's
expected value, then checks the published signed attachments' seals under the published trust
policy. It prints one line per case:

    <case id>\tagrees
    <case id>\tdiffers\t<what differs>

then the seal lines and one summary line. The reader decides; this script only applies each case's
published patch, as the cases define it, and compares.

usage: decision_record_reader.py [--mutation <case id>] <checkout of the format's repository>

--mutation names one binding case whose attachment gets one more edit before the reader sees it
(its first stage names a specification the attachment does not carry). A mutation that does not turn that line
into ``differs`` is a broken comparison, and one naming no case is a setup error (exit 2).

Exit codes: 0 every case agrees; 1 at least one differs; 2 setup error (no checkout, no reader).
"""
from __future__ import annotations

import copy
import json
import pathlib
import sys


def main(argv: list[str]) -> int:
    mutation = None
    if argv[:1] == ["--mutation"] and len(argv) >= 2:
        mutation, argv = argv[1], argv[2:]
    if len(argv) != 1:
        print(__doc__.split("\n\n")[-2], file=sys.stderr)
        return 2
    tests = pathlib.Path(argv[0]) / "extensions" / "action-binding" / "tests"
    try:
        from agent_evidence_verify import decision_record as dr
        cases = json.loads((tests / "cases.json").read_bytes())
        vectors = json.loads((tests / "vectors.json").read_bytes())
    except (ImportError, OSError, ValueError) as exc:
        print(f"setup error: {exc}", file=sys.stderr)
        return 2
    if mutation is not None and mutation not in {c["id"] for c in cases["binding_cases"]}:
        print(f"setup error: --mutation names no binding case ({mutation})", file=sys.stderr)
        return 2
    agree = differ = 0
    for case in cases["binding_cases"]:
        doc = dr.apply_patch(copy.deepcopy(vectors["attachments"][case["attachment"]]), case["patch"])
        if case["id"] == mutation:
            doc["stages"][0]["spec_digest"] = "a" * 64
        record = cases["records"][case["record"]].encode("utf-8") if case["record"] else None
        report = dr.read(dr.compact(doc), record=record)
        diffs = dr.expected_differences(case, report)
        if report["structural_validity"]["status"] != dr.VERIFIED:
            diffs.insert(0, "structural_validity: " + report["structural_validity"]["status"])
        if diffs:
            differ += 1
            print(f"{case['id']}\tdiffers\t{'; '.join(diffs)}")
        else:
            agree += 1
            print(f"{case['id']}\tagrees")
    if mutation is not None and differ == 0:
        print(f"setup error: the mutation of {mutation} changed no dimension", file=sys.stderr)
        return 2
    policy = vectors["trust_policy"]
    seals = 0
    for name in ("A0", "B0"):
        data = dr.compact(vectors["attachments"][name])
        sig = dr.read(data, trust_policy=policy)["issuer_signature"]
        decision = vectors["attachments"][name]["decision_id"].encode("utf-8")
        changed = dr.read(data.replace(decision, decision[:-1] + (b"8" if decision[-1:] == b"9" else b"9")),
                          trust_policy=policy)
        ok = sig["status"] == dr.VERIFIED and changed["issuer_signature"]["status"] == dr.FAILED
        seals += ok
        print(f"seal {name}\t{sig['status']}\tholder {sig.get('holder')!r}, key state "
              f"{sig.get('key_state', {}).get('status')} on {sig.get('key_state', {}).get('time_basis')}; "
              f"one changed byte: {changed['issuer_signature']['status']}")
    total = len(cases["binding_cases"])
    print(f"summary\tbinding cases {agree} of {total} agree, {differ} differ; seals {seals} of 2 as expected")
    return 0 if differ == 0 and seals == 2 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
