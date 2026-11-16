"""The edit-detection harness counts what a verifier sees, and never reads an empty log as a pass."""
import hashlib
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "adapters"))
import edit_detection as ed  # noqa: E402


def chain(n=5):
    log, prev = [], "0" * 64
    for i in range(n):
        e = {"seq": i + 1, "status": "ok", "prev": prev, "body": f"b{i}"}
        prev = hashlib.sha256(json.dumps(e, sort_keys=True).encode()).hexdigest()
        log.append(e)
    return log


def strict(log):
    prev = "0" * 64
    for i, e in enumerate(log):
        if e["seq"] != i + 1 or e["prev"] != prev or e["status"] != "ok" or not e["body"].startswith("b"):
            return "bad"
        prev = hashlib.sha256(json.dumps(e, sort_keys=True).encode()).hexdigest()
    return None if len(log) == 5 else "short"


def order_blind(log):
    """Checks bodies and statuses but not order, links or length."""
    return "bad" if any(e["status"] != "ok" or not e["body"].startswith("b") for e in log) else None


def named(log):
    return ed.edits(log, "status", "prev", "body", "edited")


def test_a_verifier_that_checks_everything_detects_all_six():
    log = chain()
    _, hit, total = ed.detect(log, strict, named(log))
    assert (hit, total) == (6, 6)


def test_a_verifier_blind_to_order_misses_the_structural_edits():
    log = chain()
    lines, hit, total = ed.detect(log, order_blind, named(log))
    missed = [line for line in lines if line.startswith("MISSED")]
    assert hit == 2 and total == 6
    assert any("swap two entries" in line for line in missed)
    assert any("drop an entry" in line for line in missed)


def test_an_empty_log_is_cannot_tell():
    lines, hit, total = ed.detect([], strict, [])
    assert (hit, total) == (0, 0) and "empty_denominator" in lines[0]


def test_an_original_that_already_fails_counts_nothing():
    log = chain()
    log[0]["status"] = "bad"
    lines, hit, total = ed.detect(log, strict, named(log))
    assert total == 0 and "already fails" in lines[0]
