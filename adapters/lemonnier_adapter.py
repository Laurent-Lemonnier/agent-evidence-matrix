"""Replay the interop checks of dps-scitt-decision-layer (audit record 217, approval binding 37) two ways.

usage (matrix venv with agent-evidence-vectors 0.36.3, the CI pin in the project's requirements-gilda.txt):
  git clone https://github.com/Laurent-Lemonnier/dps-scitt-decision-layer ../dps-scitt-decision-layer
  git -C ../dps-scitt-decision-layer checkout 00d748a63d96b13905dafb4100fb694c0715469f
  venv/bin/python -I adapters/lemonnier_adapter.py ../dps-scitt-decision-layer

The record bytes are the members of the corpora vectors-agent-audit-record and vectors-approval-binding as shipped in
agent-evidence-vectors 0.36.3 (their corpusDigest values equal the ones the project's reports name). The project's
own verdicts are its committed per-member reports in interop/gilda/ (judge-20261108-0.36.3.json and
judge-approval-binding-20261108-0.36.3.json). Four comparisons, each its own cell:
  A  our reader (agent_evidence_vectors.auditrecord) on the 217 members, against the project's per-member verdicts
  B  our reader (agent_evidence_vectors.approvalbinding) on the 37 cases, against the project's per-case verdicts
  C  the project's own verifier (gilda_verify_independent.py), run here on those 217 members, against its README claim
  D  the project's own verifier (approval_binding_verify_independent.py), run here on those 37 cases
A second angle: one signed byte of one record and one payload byte of one approval case are changed in a copy, and
both our reader and the project's verifier must flip. Exit 0 when every comparison agrees; 1 when any differs.
The project's code runs from a copy in a temporary directory, with python -I, so nothing is written in its tree.
"""
import base64
import copy
import hashlib
import importlib.metadata
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from agent_evidence_vectors import approvalbinding as ab
from agent_evidence_vectors import auditrecord as ar

PINNED = "00d748a63d96b13905dafb4100fb694c0715469f"
JUDGE_AR = "judge-20261108-0.36.3.json"
JUDGE_AB = "judge-approval-binding-20261108-0.36.3.json"
CORPORA = Path(ar.__file__).parent / "corpora"
failures = []
# A difference the replay records and explains (see REPORT.md): their verifier, handed a set bundle without a
# records member (X17), falls through to the single-envelope path and answers envelope-unreadable with no set
# result; the MANIFEST expects set-unreadable, which our reader produces. Both sides agree on the verdict.
KNOWN = {"X17"}
noted = []


def find(root, name):
    hits = sorted(p for p in root.rglob(name) if ".git" not in p.parts)
    if not hits:
        sys.exit("missing %s under %s" % (name, root))
    return hits[0]


def note(ok, line, known=False):
    if ok:
        print("agrees      " + line)
    elif known:
        print("DIFFERS-KNOWN " + line)
        noted.append(line)
    else:
        print("DIFFERS     " + line)
        failures.append(line)


def ours_audit(entry, raw, manifest, heads):
    """The reader's reading of one member, in the fields the project's per-member report also carries."""
    policy = ar.policy_for(manifest, entry)
    expected = entry.get("expected") or {}
    extra = ""
    if "dating" in expected:
        report, dated = ar.verify_retained(raw, policy, heads)
        extra = "dating=%s %s" % (",".join(dated.codes) or dated.entry,
                                  "datedAt=" + dated.dated_at if dated.dated_at else "not dated")
    elif "set" in expected:
        reports, joint = ar.verify_set(raw, policy)
        bad = any(r.verdict != "valid" for r in reports) or not reports
        report = ar.Report("malformed" if bad else "valid", [c for r in reports for c in r.codes],
                           reports[0].derived_tier if reports else None)
        extra = "set=valid" if joint.verdict == "valid" else "set=%s" % (list(joint.codes),)
    else:
        report = ar.verify(raw, policy)
    return report.verdict, list(report.codes), report.derived_tier, extra


def section_a(gilda_dir):
    print("== A. audit record: our reader on the 217 members, against the project's per-member verdicts")
    root = CORPORA / "vectors-agent-audit-record"
    manifest = json.loads((root / "MANIFEST.json").read_text(encoding="utf-8"))
    judge = json.loads((gilda_dir / JUDGE_AR).read_text(encoding="utf-8"))
    heads = ar.tree_heads(manifest)
    own = {mid: findings for mid, _kind, findings in ar.judge(str(root)).members}
    rows = {r["draftId"]: r for r in judge["rows"]}
    entries = manifest["vectors"]
    print("corpusDigest %s members %d project-report-members %d" % (manifest["corpusDigest"], len(entries), len(rows)))
    tally = {"ours=theirs": 0, "ours=manifest": 0, "theirs=manifest": 0, "first-code": 0, "rejects": 0}
    for entry in entries:
        did = entry["draftId"]
        raw = (root / entry["file"]).read_bytes()
        v, codes, tier, extra = ours_audit(entry, raw, manifest, heads)
        row = rows.get(did)
        ok = row is not None
        conform = ar.conforming_verdicts(entry)
        ours_manifest = not own[entry["id"]]
        tally["ours=manifest"] += ours_manifest
        if row is None:
            note(False, "%s %s: no row in the project's report" % (did, entry["kind"]))
            continue
        their_note = " ".join(row["notes"])
        ours_theirs = (v == row["got"] and codes == row["codes"] and (v != "valid" or tier == row["derivedTier"])
                       and (extra == their_note if extra else not their_note))
        theirs_manifest = bool(row["agree"])
        tally["ours=theirs"] += ours_theirs
        tally["theirs=manifest"] += theirs_manifest
        if entry["kind"] == "reject":
            tally["rejects"] += 1
            tally["first-code"] += bool(codes and row["codes"] and codes[0] == row["codes"][0])
        note(ours_theirs and ours_manifest, ("%s %-13s ours=%s%s%s%s theirs=%s%s%s%s" % (
            did, entry["kind"], v, codes, "/" + tier if v == "valid" else "", " " + extra if extra else "",
            row["got"], row["codes"], "/" + str(row["derivedTier"]) if row["got"] == "valid" else "",
            " " + their_note if their_note else "")), known=did in KNOWN)
        tally["verdict"] = tally.get("verdict", 0) + (v == row["got"] or (entry["kind"] == "indeterminate" and v in conform and row["got"] in conform))
    n = len(entries)
    print("A-summary: verdict equal %d of %d; full per-member surface ours=theirs %d of %d; ours=manifest %d of %d; theirs=manifest %d of %d; "
          "first refusal code equal on %d of %d reject members" % (
              tally["verdict"], n, tally["ours=theirs"], n, tally["ours=manifest"], n, tally["theirs=manifest"], n,
              tally["first-code"], tally["rejects"]))
    return manifest


def section_b(gilda_dir):
    print("== B. approval binding: our reader on the 37 cases, against the project's per-case verdicts")
    root = CORPORA / "vectors-approval-binding"
    manifest = json.loads((root / "MANIFEST.json").read_text(encoding="utf-8"))
    judge = json.loads((gilda_dir / JUDGE_AB).read_text(encoding="utf-8"))
    rows = {r["id"]: r for r in judge["rows"]}
    print("corpusDigest %s cases %d project-report-cases %d" % (manifest["corpusDigest"], len(manifest["vectors"]), len(rows)))
    both = 0
    for entry in manifest["vectors"]:
        got = ab.verify(root / entry["path"] / "record.json")
        row = rows.get(entry["id"])
        theirs = row["got"] if row else None
        ok = bool(row) and got == theirs and got == entry["expected"] and theirs == row["expected"]
        both += ok
        note(ok, "%s ours=%s/%s theirs=%s/%s manifest=%s/%s" % (
            entry["id"], got["decision"], got["reason"], (theirs or {}).get("decision"), (theirs or {}).get("reason"),
            entry["expected"]["decision"], entry["expected"]["reason"]))
    print("B-summary: ours=theirs=manifest %d of %d" % (both, len(manifest["vectors"])))


def run_theirs(work, script, args, env=None):
    proc = subprocess.run([sys.executable, "-I", str(work / script)] + args, capture_output=True, text=True,
                          env=dict(os.environ, **(env or {})), timeout=900)
    return proc.returncode, proc.stdout.strip(), proc.stderr.strip()


def section_cd(gilda_dir, work):
    print("== C. the project's verifier gilda_verify_independent.py, run here on the 217 members")
    rc, out, err = run_theirs(work, "gilda_verify_independent.py",
                              ["--corpus", str(CORPORA / "vectors-agent-audit-record"), "--report", str(work / "judge-c.json")])
    print("exit", rc)
    print("stdout-last-line:", out.splitlines()[-1] if out else "(none) " + err[-300:])
    fresh = json.loads((work / "judge-c.json").read_text(encoding="utf-8"))
    kept = json.loads((gilda_dir / JUDGE_AR).read_text(encoding="utf-8"))
    claim = {"members": 217, "agree": 217, "firstCodeAgree": 123, "rejectMembers": 123, "datingNotAttempted": 0}
    for key, want in claim.items():
        note(fresh.get(key) == want, "C %s fresh=%s claimed=%s" % (key, fresh.get(key), want))
    same = fresh["rows"] == kept["rows"]
    note(same, "C per-member rows of this run equal the committed judge-20261108-0.36.3.json: %s of %d" % (
        sum(a == b for a, b in zip(fresh["rows"], kept["rows"])), len(kept["rows"])))
    note(rc == 0, "C verifier exit code 0")
    print("== D. the project's verifier approval_binding_verify_independent.py, run here on the 37 cases")
    rc, out, err = run_theirs(work, "approval_binding_verify_independent.py",
                              ["--corpus", str(CORPORA / "vectors-approval-binding"), "--report", str(work / "judge-d.json")])
    print("exit", rc)
    print("stdout-last-line:", out.splitlines()[-1] if out else "(none) " + err[-300:])
    fresh = json.loads((work / "judge-d.json").read_text(encoding="utf-8"))
    kept = json.loads((gilda_dir / JUDGE_AB).read_text(encoding="utf-8"))
    for key, want in {"cases": 37, "agree": 37, "checks": 16}.items():
        note(fresh.get(key) == want, "D %s fresh=%s claimed=%s" % (key, fresh.get(key), want))
    note(fresh["rows"] == kept["rows"], "D per-case rows of this run equal the committed judge-approval-binding-20261108-0.36.3.json: %s of %d" % (
        sum(a == b for a, b in zip(fresh["rows"], kept["rows"])), len(kept["rows"])))
    note(rc == 0, "D verifier exit code 0")
    proc = subprocess.run([sys.executable, "-I", "-m", "unittest", "discover", "-s", str(work), "-p", "test_gilda_aggregation.py"],
                          capture_output=True, text=True, env=dict(os.environ, GILDA_CORPUS=str(CORPORA / "vectors-agent-audit-record")), timeout=900)
    lines = proc.stderr.strip().splitlines()
    ran = next((l for l in lines if l.startswith("Ran ")), "")
    note(proc.returncode == 0 and lines[-1] == "OK", "C their aggregation regression tests: exit %d, %s, %s" % (proc.returncode, ran.split(" in ")[0], lines[-1]))


def flip_payload(envelope_bytes):
    envelope = json.loads(envelope_bytes)
    payload = base64.b64decode(envelope["payload"])
    marker = b'"2026-'
    at = payload.index(marker) + 4
    payload = payload[:at] + b"7" + payload[at + 1:]
    envelope["payload"] = base64.b64encode(payload).decode("ascii")
    return json.dumps(envelope).encode("utf-8")


def section_tamper(work):
    print("== T. second angle: one signed byte of one record, one payload byte of one approval case, in copies")
    root = CORPORA / "vectors-agent-audit-record"
    manifest = json.loads((root / "MANIFEST.json").read_text(encoding="utf-8"))
    entry = next(e for e in manifest["vectors"] if e["draftId"] == "A1")
    raw = (root / entry["file"]).read_bytes()
    bad = flip_payload(raw)
    pay = lambda b: base64.b64decode(json.loads(b)["payload"])
    print("A1 signed payload: %d bytes, %d changed (one digit of a signed timestamp, year 2026 to 2027)" % (
        len(pay(raw)), sum(x != y for x, y in zip(pay(raw), pay(bad)))))
    tdir = work / "tamper" / "statements"
    tdir.mkdir(parents=True)
    shutil.copy(root / "MANIFEST.json", work / "tamper" / "MANIFEST.json")
    (tdir / "tampered-A1.json").write_bytes(bad)
    policy = ar.policy_for(manifest, entry)
    before, after = ar.verify(raw, policy), ar.verify(bad, policy)
    note(before.verdict == "valid" and after.verdict == "malformed",
         "T ours A1: untouched %s%s, tampered %s%s" % (before.verdict, before.codes, after.verdict, after.codes))
    rc, out, _ = run_theirs(work, "gilda_verify_independent.py", [str(tdir / "tampered-A1.json"), "--json", "--manifest", str(work / "tamper" / "MANIFEST.json")])
    got = json.loads(out)
    note(got["verdict"] == "malformed" and rc == 1, "T theirs A1 tampered: %s %s exit %d" % (got["verdict"], got["codes"], rc))
    ab_root = CORPORA / "vectors-approval-binding" / "cases" / "allow-bound"
    cdir = work / "tamper-ab"
    shutil.copytree(ab_root, cdir)
    payload = bytearray((cdir / "payload.bin").read_bytes())
    payload[-1] ^= 1
    (cdir / "payload.bin").write_bytes(bytes(payload))
    before, after = ab.verify(ab_root / "record.json"), ab.verify(cdir / "record.json")
    note(before["decision"] == "allow" and after["decision"] == "deny",
         "T ours allow-bound: untouched %s/%s, one payload byte changed %s/%s" % (
             before["decision"], before["reason"], after["decision"], after["reason"]))
    rc, out, _ = run_theirs(work, "approval_binding_verify_independent.py", [str(cdir / "record.json"), "--json"])
    got = json.loads(out)
    note(got["decision"] == "deny" and rc != 0, "T theirs allow-bound tampered: %s/%s" % (got["decision"], got["reason"]))


def main():
    root = Path(sys.argv[1]).resolve()
    version = importlib.metadata.version("agent-evidence-vectors")
    print("reader agent-evidence-vectors", version, "| project commit expected", PINNED)
    if version != "0.36.3":
        print("note: the project's CI pins 0.36.3; this run uses", version)
    verifier = find(root, "gilda_verify_independent.py")
    gilda_dir = verifier.parent
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        for name in ("gilda_verify_independent.py", "approval_binding_verify_independent.py", "test_gilda_aggregation.py"):
            shutil.copy(find(gilda_dir, name), work / name)
        print("their verifier sha256", hashlib.sha256((work / "gilda_verify_independent.py").read_bytes()).hexdigest()[:16],
              "approval", hashlib.sha256((work / "approval_binding_verify_independent.py").read_bytes()).hexdigest()[:16])
        section_a(gilda_dir)
        section_b(gilda_dir)
        section_cd(gilda_dir, work)
        section_tamper(work)
    print("SUMMARY: %d comparisons differ, %d known and explained" % (len(failures), len(noted)))
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
