"""The agentops adapter binds each hash to the copy the analyzer reads, and refuses what it cannot read.

Counter-examples the first adapter accepted: an inline-attribute edit (the hash binds only the stored
copy), a session with no events (0 of 0 read as a pass) and a duplicate member (a last-wins parse).
"""
import hashlib
import json
import pathlib
import subprocess
import sys

ADAPTER = pathlib.Path(__file__).resolve().parents[1] / "adapters" / "icon_agentops.py"


def h(body):
    return "sha256:" + hashlib.sha256(json.dumps(body, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def session(n=10):
    events, evidence = [], {}
    for i in range(n):
        attrs = {"route": "B", "step": i}
        rid = f"clean:e{i:03d}:evidence"
        events.append({"event_id": f"clean:e{i:03d}", "status": "ok", "parent_event_ids": [],
                       "attributes": attrs, "evidence": [{"id": rid, "hash": h(attrs)}]})
        evidence[rid] = dict(attrs)
    return events, evidence


def run(tmp_path, events, evidence, raw_events=None):
    d = tmp_path / "agentops" / "examples" / "results" / "clean"
    d.mkdir(parents=True)
    (d / "events.json").write_text(raw_events if raw_events is not None else json.dumps(events))
    (d / "evidence.json").write_text(json.dumps(evidence))
    out = subprocess.run([sys.executable, "-I", str(ADAPTER), str(tmp_path / "agentops")], capture_output=True, text=True)
    return out.returncode, out.stdout


def test_a_clean_session_passes(tmp_path):
    rc, out = run(tmp_path, *session())
    assert rc == 0 and "PASS  agentops/evidence-hash: 10 of 10" in out


def test_an_inline_edit_of_the_consumed_copy_is_caught(tmp_path):
    events, evidence = session()
    events[4]["attributes"]["route"] = "A"
    rc, out = run(tmp_path, events, evidence)
    assert rc == 1 and "differs from the attributes the analyzer reads" in out


def test_no_events_is_not_a_pass(tmp_path):
    rc, out = run(tmp_path, [], {})
    assert rc == 1 and "DIFF  agentops/evidence-hash: 0 of 0" in out


def test_a_duplicate_member_refuses_the_file(tmp_path):
    events, evidence = session()
    raw = json.dumps(events).replace('"status": "ok"', '"status": "ok", "status": "error"', 1)
    rc, out = run(tmp_path, events, evidence, raw_events=raw)
    assert rc == 1 and "1 files refused" in out


def test_a_refused_session_is_reported_and_the_run_still_finishes(tmp_path):
    """Counter-example: a duplicate member in one session crashed the later readings (traceback, no SUMMARY,
    edit detection never ran), and the crash exited 1 like a comparison result."""
    events, evidence = session()
    run(tmp_path, events, evidence)
    other = tmp_path / "agentops" / "examples" / "results" / "s2"
    other.mkdir()
    (other / "events.json").write_text(json.dumps(events[:1]))
    (other / "evidence.json").write_text('{"clean:e000:evidence":{"route":"B","step":0},'
                                         '"clean:e000:evidence":{"route":"B","step":0}}')
    out = subprocess.run([sys.executable, "-I", str(ADAPTER), str(tmp_path / "agentops")], capture_output=True, text=True)
    assert out.returncode == 1 and "Traceback" not in out.stderr
    assert "1 files refused" in out.stdout and "1 sessions refused" in out.stdout
    assert "agentops/edit-detection: the project's hash rule detects" in out.stdout
    assert out.stdout.splitlines()[-1].startswith("SUMMARY")


def test_no_events_is_a_reported_difference_not_a_crash(tmp_path):
    """Counter-example: the empty session passed its test only because edit detection indexed events[5]
    and crashed with exit 1; edit detection now finds its events by id and says which are missing."""
    d = tmp_path / "agentops" / "examples" / "results" / "clean"
    d.mkdir(parents=True)
    (d / "events.json").write_text("[]")
    (d / "evidence.json").write_text("{}")
    out = subprocess.run([sys.executable, "-I", str(ADAPTER), str(tmp_path / "agentops")], capture_output=True, text=True)
    assert out.returncode == 1 and "Traceback" not in out.stderr
    assert "DIFF  agentops/edit-detection: the clean session has no" in out.stdout
