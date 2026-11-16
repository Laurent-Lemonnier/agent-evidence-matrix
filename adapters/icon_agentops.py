"""Adapter: the agentops records of the ICON hackathon running code, read from the committed bytes.

usage: icon_agentops.py <agentops dir> [--regenerated <dir written by `python3 -m agentops demo --out <dir>`>]

Reads examples/results/<session>/{events,evidence}.json with a strict I-JSON parser (a duplicate member,
NaN or Infinity refuses the file) and prints one line per check ("PASS|DIFF|INFO  case: detail"):

  agentops/evidence-hash      every event carries one evidence ref whose hash equals SHA-256 of
                              json.dumps(attributes, sort_keys=True, ensure_ascii=False) (the rule in
                              agentops/telemetry.py) and whose evidence.json body equals those attributes,
                              the copy agentops/analysis.py reads; an uncited body is a problem
  agentops/rfc8785            the same hashes recomputed over RFC 8785 bytes (the rfc8785 package); a body
                              with no RFC 8785 form (an integer past 2^53, a non-finite number) is counted
                              apart, never folded into the agreeing count
  agentops/edit-detection     five edits to the committed clean session (drop an event, flip a status, rewrite
                              a parent link, edit an evidence body, edit the inline attributes the analyzer
                              reads), judged by the project's own hash rule and by the bound rule above
  agentops/<file>-normalized  with --regenerated: the regenerated session files against the committed ones,
                              after dropping the fields that differ by design (times, ids, durations)

A session file the strict parser refuses is reported by agentops/evidence-hash and left out of the other
readings, which say how many sessions they read. Exit 1 when the evidence-hash check or a regenerated
events or evidence file differs; 2 on a crash (never 1); 0 otherwise.
"""
from __future__ import annotations

import copy
import hashlib
import json
import sys
from pathlib import Path

import rfc8785

results: list[str] = []


def _no_dup(pairs):
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError(f"duplicate member {sorted(k for k in set(keys) if keys.count(k) > 1)}")
    return dict(pairs)


def _no_const(name):
    raise ValueError(f"non-I-JSON number {name}")


def load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"), object_pairs_hook=_no_dup, parse_constant=_no_const)


def emit(status, case, detail):
    results.append(status)
    print(f"{status:4}  {case}: {detail}")


def py_hash(body):
    return "sha256:" + hashlib.sha256(json.dumps(body, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def own_rule(events, ev):
    """The project's check: the evidence body's hash, nothing else."""
    return sum(ev.get(ref["id"]) is None or py_hash(ev[ref["id"]]) != ref["hash"] for e in events for ref in e["evidence"])


def bound_rule(events, ev):
    """The hash over the copy the analyzer reads, and the stored body equal to it."""
    return sum(py_hash(e.get("attributes", {})) != ref["hash"] or ev.get(ref["id"]) != e.get("attributes", {})
               for e in events for ref in e["evidence"])


def sessions(results_dir):
    return sorted(p for p in results_dir.iterdir() if p.is_dir())


def evidence_hash(results_dir):
    ok = bad = n = refused = 0
    problems = []
    for sess in sessions(results_dir):
        try:
            ev, events = load(sess / "evidence.json"), load(sess / "events.json")
        except ValueError as exc:
            refused += 1
            problems.append(f"{sess.name}: {exc}")
            continue
        cited = set()
        for e in events:
            n += 1
            refs = e.get("evidence", [])
            if len(refs) != 1:
                bad += 1
                problems.append(f"{e.get('event_id')}: {len(refs)} evidence refs")
                continue
            ref = refs[0]
            cited.add(ref["id"])
            consumed = e.get("attributes", {})
            if ev.get(ref["id"]) != consumed:
                bad += 1
                problems.append(f"{ref['id']}: evidence.json body differs from the attributes the analyzer reads")
            elif py_hash(consumed) != ref["hash"]:
                bad += 1
                problems.append(f"{ref['id']}: hash mismatch")
            else:
                ok += 1
        orphans = sorted(set(ev) - cited)
        if orphans:
            bad += len(orphans)
            problems.append(f"{sess.name}: uncited evidence bodies {orphans}")
    good = n > 0 and ok == n and bad == 0 and refused == 0
    emit("PASS" if good else "DIFF", "agentops/evidence-hash",
         f"{ok} of {n} events: one ref, hash = sha256 of json.dumps(attributes, sort_keys=True, ensure_ascii=False), "
         f"evidence.json body equal to those attributes; {refused} files refused; first problems: {problems[:3]}")


def rfc8785_reading(results_dir):
    total = match = no_form = empty = refused = missing = 0
    for sess in sessions(results_dir):
        try:
            ev, events = load(sess / "evidence.json"), load(sess / "events.json")
        except ValueError:
            refused += 1
            continue
        for e in events:
            for ref in e["evidence"]:
                body = ev.get(ref["id"])
                if body is None:
                    missing += 1
                    continue
                total += 1
                empty += body == {}
                try:
                    raw = rfc8785.dumps(body)
                except Exception:  # IntegerDomainError, FloatDomainError, CanonicalizationError
                    no_form += 1
                    continue
                match += ref["hash"] == "sha256:" + hashlib.sha256(raw).hexdigest()
    emit("INFO", "agentops/rfc8785",
         f"{match} of {total} hashes equal SHA-256 of the RFC 8785 bytes of the body ({empty} bodies are empty objects); "
         f"{no_form} bodies have no RFC 8785 form; {refused} sessions refused, {missing} refs with no body (not read)")


def edit_detection(results_dir):
    root = results_dir / "clean"
    try:
        events, ev = load(root / "events.json"), load(root / "evidence.json")
    except ValueError as exc:
        emit("DIFF", "agentops/edit-detection", f"the clean session is refused ({exc}); no edit was judged")
        return
    need = ("clean:e003", "clean:e004", "clean:e005", "clean:e008")
    at = {e.get("event_id"): i for i, e in enumerate(events)}
    absent = [n for n in need if n not in at] + ([] if "clean:e004:evidence" in ev else ["clean:e004:evidence"])
    if absent:
        emit("DIFF", "agentops/edit-detection", f"the clean session has no {absent}; no edit was judged")
        return
    edits = []
    a = copy.deepcopy(events)
    del a[at["clean:e005"]]
    edits.append(("drop event e005", a, ev))
    b = copy.deepcopy(events)
    b[at["clean:e008"]]["status"] = "error" if b[at["clean:e008"]].get("status") != "error" else "ok"
    edits.append(("flip e008 status", b, ev))
    c = copy.deepcopy(events)
    c[at["clean:e003"]]["parent_event_ids"] = ["clean:e000"]
    edits.append(("rewrite e003 parent_event_ids", c, ev))
    d = copy.deepcopy(ev)
    d["clean:e004:evidence"]["route"] = "A"
    edits.append(("edit evidence.json body of e004", events, d))
    f = copy.deepcopy(events)
    f[at["clean:e004"]].setdefault("attributes", {})["route"] = "A"
    edits.append(("edit inline attributes of e004 (the copy analysis.py reads)", f, ev))
    if own_rule(events, ev) or bound_rule(events, ev):
        emit("DIFF", "agentops/edit-detection", "the unedited session already fails a rule")
        return
    own = [name for name, x, y in edits if own_rule(x, y)]
    consumed = [name for name, x, y in edits[:3] + edits[4:] if own_rule(x, y)]
    bound = [name for name, x, y in edits if bound_rule(x, y)]
    emit("INFO", "agentops/edit-detection",
         f"the project's hash rule detects {len(own)} of {len(edits)} edits ({own}); {len(consumed)} of 4 edits to the "
         f"bytes the analyzer reads; the bound rule detects {len(bound)} of {len(edits)} ({bound})")


VOLATILE = {"timestamp", "trace_id", "span_id", "detected_at", "duration_ms", "latency_ms", "elapsed_ms", "duration",
            "started_at", "ended_at", "analysis_duration_ms"}


def norm(v):
    if isinstance(v, dict):
        return {k: norm(x) for k, x in v.items() if k not in VOLATILE}
    if isinstance(v, list):
        return [norm(x) for x in v]
    return v


def diffs(a, b, path="$"):
    """Every JSON path where two values differ, as path strings with list indices written [*]."""
    if type(a) is not type(b):
        return [path]
    if isinstance(a, dict):
        out = []
        for k in sorted(set(a) | set(b)):
            out += [f"{path}.{k}"] if (k not in a or k not in b) else diffs(a[k], b[k], f"{path}.{k}")
        return out
    if isinstance(a, list):
        if len(a) != len(b):
            return [path + "[length]"]
        return [d for x, y in zip(a, b) for d in diffs(x, y, f"{path}[*]")]
    return [] if a == b else [path]


def first_diff(a, b):
    """The distinct differing paths, or None when the values are equal."""
    found = sorted(set(diffs(a, b)))
    return ", ".join(found[:12]) if found else None


def regenerated(results_dir, regen):
    for fname in ("events.json", "evidence.json", "analysis.json"):
        same, differing, where = 0, [], {}
        for sess in sessions(results_dir):
            a, b = sess / fname, regen / sess.name / fname
            if not b.exists():
                differing.append(sess.name)
                where[sess.name] = "missing"
                continue
            d = first_diff(norm(load(a)), norm(load(b)))
            if d is None:
                same += 1
            else:
                differing.append(sess.name)
                where[sess.name] = d
        status = "PASS" if not differing else ("INFO" if fname == "analysis.json" else "DIFF")
        paths = sorted({p for w in where.values() for p in w.split(", ")})
        emit(status, f"agentops/{fname}-normalized",
             f"{same} of {same + len(differing)} sessions equal after dropping volatile fields; differing: {differing}"
             + (f"; differing paths: {paths[:20]}" if paths else ""))


def main(argv):
    if not argv or (len(argv) not in (1, 3)) or (len(argv) == 3 and argv[1] != "--regenerated"):
        sys.exit(__doc__)
    results_dir = Path(argv[0]) / "examples" / "results"
    evidence_hash(results_dir)
    rfc8785_reading(results_dir)
    edit_detection(results_dir)
    if len(argv) == 3:
        regenerated(results_dir, Path(argv[2]))
    print(f"SUMMARY pass={results.count('PASS')} diff={results.count('DIFF')} info={results.count('INFO')}")
    return 1 if "DIFF" in results else 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except Exception as exc:  # a crash is not a comparison result
        print(f"setup: {type(exc).__name__}: {exc}", file=sys.stderr)
        sys.exit(2)
