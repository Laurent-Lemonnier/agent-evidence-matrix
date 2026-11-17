"""Duplicates and invalid UTF-8 are refused before canonicalization, and every recorded canonicalizer agrees with its run.

A canonicalizer that takes a parsed value cannot see a duplicate member: the parse already kept one of the two values.
The matrix's own reader therefore has to refuse those inputs on the received bytes. These tests hold it to that, hold the
recorded `canonicalizer` fields of matrix.json to the probe lines of the runs they cite, and check that the scorer that
writes those runs can tell a canonicalizer that refuses from one that does not.
"""
import json
import pathlib
import re
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
NO_FORM = {
    "duplicate-member": b'{"a":1,"a":2}',
    "duplicate-member-name": b'{"name":"Good","name":"Evil"}',
    "surrogate-as-utf8-bytes": bytes.fromhex("7b2261223a22eda080227d"),
    "invalid-utf8-ff": bytes.fromhex("7b2261223a22ff227d"),
}
PROBE = re.compile(r"^PROBE (\S+) input=([0-9a-f]+) (refused|accepted [0-9a-f]+)$", re.M)


@pytest.mark.parametrize("name", sorted(NO_FORM))
def test_reference_reader_refuses_parse_layer_input_before_canonicalization(name, tmp_path):
    path = tmp_path / "in.json"
    path.write_bytes(NO_FORM[name])
    run = subprocess.run([sys.executable, str(ROOT / "adapters" / "rfc8785_cli.py"), "rfc8785", str(path)],
                         capture_output=True, text=True, check=False)
    assert run.returncode == 1, (name, run.returncode, run.stdout, run.stderr)
    # refused by the parse, which reads the bytes, never by the canonicalizer after a lenient parse kept one value
    assert run.stderr.startswith("refused-by-parser"), run.stderr
    assert run.stdout == ""


def _recorded():
    data = json.loads((ROOT / "matrix.json").read_text(encoding="utf-8"))
    return [(p["id"], p["canonicalizer"]) for p in data["projects"] if p.get("canonicalizer")]


HEADER_INPUT = {"JSON.parse of the bytes as UTF-8": "parsed value", "received bytes": "received bytes",
                "strict UTF-8 decode of the bytes": "text"}


def _run_probes(run: str):
    probes = {m.group(1): (m.group(2), m.group(3)) for m in PROBE.finditer(run)}
    header = re.search(r"^.* input (.+)$", run, re.M)
    return probes, HEADER_INPUT.get(header.group(1)) if header else None


@pytest.mark.parametrize("pid,rec", _recorded(), ids=lambda v: str(v) if isinstance(v, int) else "")
def test_recorded_parse_layer_matches_its_run(pid, rec):
    if rec["parse_layer"] == "not probed":
        assert not rec.get("evidence"), f"project {pid}: not probed cites a run"
        return
    probes, took = _run_probes((ROOT / rec["evidence"].split()[0]).read_text(encoding="utf-8"))
    assert set(probes) == set(NO_FORM), f"project {pid}: the run has probes {sorted(probes)}"
    for name, (hexin, _) in probes.items():
        assert bytes.fromhex(hexin) == NO_FORM[name], f"project {pid}: probe {name} ran on other bytes"
    assert took == rec["input"], f"project {pid}: recorded input {rec['input']!r}, the run gave the function {took!r}"
    outcomes = {o.split()[0] for _, o in probes.values()}
    want = {"parsed before it": rec["input"] == "parsed value",
            "refused": outcomes == {"refused"},
            "accepted": "accepted" in outcomes}[rec["parse_layer"]]
    assert want, f"project {pid}: recorded {rec['parse_layer']!r}, the run shows {sorted(outcomes)} on {took}"


@pytest.mark.parametrize("layer,outcomes,took,ok", [
    ("refused", ["refused"] * 4, "received bytes", True),
    # refusing both duplicates while a raw 0xFF byte is accepted is not refused: all four count, not two
    ("refused", ["refused", "refused", "refused", "accepted 7b7d"], "received bytes", False),
    ("accepted", ["refused", "refused", "refused", "accepted 7b7d"], "received bytes", True),
    ("parsed before it", ["accepted 7b7d"] * 4, "JSON.parse of the bytes as UTF-8", True),
    ("parsed before it", ["accepted 7b7d"] * 4, "received bytes", False),
])
def test_the_parse_layer_check_reads_all_four_probes_and_the_input(layer, outcomes, took, ok, tmp_path, monkeypatch):
    run = f"source sha256 {'0' * 64} entry f input {took}\n" + "".join(
        f"PROBE {n} input={NO_FORM[n].hex()} {o}\n" for n, o in zip(sorted(NO_FORM), outcomes))
    (tmp_path / "adapters").mkdir()
    (tmp_path / "adapters" / "run.txt").write_text(run, encoding="utf-8")
    monkeypatch.setattr(sys.modules[__name__], "ROOT", tmp_path)
    rec = {"input": HEADER_INPUT[took], "parse_layer": layer, "evidence": "adapters/run.txt"}
    if ok:
        test_recorded_parse_layer_matches_its_run(0, rec)
    else:
        with pytest.raises(AssertionError):
            test_recorded_parse_layer_matches_its_run(0, rec)


LENIENT = "function canon(v) { return JSON.stringify(v, Object.keys(v).sort()); }\n"
STRICT_BYTES = ("function canon(b) {\n"
                "  const t = new TextDecoder('utf-8', { fatal: true }).decode(b);\n"
                "  const seen = []; JSON.parse(t, function (k, v) { return v; });\n"
                "  if (/\"a\":1,\"a\"|\"name\":\"Good\",\"name\"/.test(t)) throw new Error('duplicate');\n"
                "  return t;\n"
                "}\n")


def _corpus(tmp_path):
    """A two-case corpus: one MUST-ACCEPT object and the bare-NaN MUST-REJECT, which is not JSON."""
    corpus = tmp_path / "corpus"
    (corpus / "a3-x").mkdir(parents=True, exist_ok=True)
    (corpus / "a3-x" / "A3-001.json").write_text(json.dumps({
        "id": "A3-001", "disposition": "MUST-ACCEPT", "input": {"b": 1, "a": 2},
        "expected": {"canonical_utf8_hex": b'{"a":2,"b":1}'.hex()}}), encoding="utf-8")
    (corpus / "a3-x" / "A5-REJECT-016.json").write_text(json.dumps({
        "id": "A5-REJECT-016", "disposition": "MUST-REJECT", "rejection_layer": "canonicalization",
        "input_raw": '{"n": NaN}'}), encoding="utf-8")
    return corpus


def _score(tmp_path, source, *flags, corpus=None, entry="canon"):
    src = tmp_path / "canon.mjs"
    src.write_text(source, encoding="utf-8")
    corpus = _corpus(tmp_path) if corpus is None else corpus
    return subprocess.run(["node", str(ROOT / "adapters" / "jcs_function_score.mjs"), "--source", str(src),
                           "--entry", entry, *flags, str(corpus)], capture_output=True, text=True, check=False)


@pytest.mark.parametrize("source,flags,want", [(LENIENT, [], "accepted"), (STRICT_BYTES, ["--bytes"], "refused")])
def test_scorer_tells_a_refusing_canonicalizer_from_a_lenient_one(source, flags, want, tmp_path):
    run = _score(tmp_path, source, *flags)
    assert run.returncode == 0, run.stdout + run.stderr
    outcomes = {m.group(1): m.group(3).split()[0] for m in PROBE.finditer(run.stdout)}
    assert outcomes["duplicate-member"] == want and outcomes["duplicate-member-name"] == want, run.stdout


SORTED = ("function canon(v) {\n"
          "  if (v === null || typeof v !== 'object') return JSON.stringify(v);\n"
          "  return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}';\n"
          "}\n")
FINITE = SORTED.replace("return JSON.stringify(v);",
                        "{ if (typeof v === 'number' && !Number.isFinite(v)) throw new Error('non-finite'); "
                        "return JSON.stringify(v); }")


def test_a_non_json_reject_is_given_to_the_function_not_refused_by_the_harness_parse(tmp_path):
    # JSON.parse cannot read {"n": NaN}. Before this was fixed the harness's SyntaxError counted as the function
    # refusing, so a function that writes NaN as null passed. It must now receive the number and fail.
    run = _score(tmp_path, SORTED)
    assert run.returncode == 0, run.stdout + run.stderr
    assert "FAIL A5-REJECT-016 MUST-REJECT got=" + b'{"n":null}'.hex() in run.stdout, run.stdout
    assert "scored=2 pass=1 fail=1 " in run.stdout, run.stdout
    fixed = _score(tmp_path, FINITE)
    assert "scored=2 pass=2 fail=0 " in fixed.stdout, fixed.stdout


def test_a_run_that_scores_nothing_is_a_setup_failure(tmp_path):
    empty = tmp_path / "empty"
    (empty / "a3-x").mkdir(parents=True)
    run = _score(tmp_path, SORTED, corpus=empty)
    assert run.returncode == 2 and "SETUP no rfc8785 case" in run.stdout, run.stdout + run.stderr


def test_the_entry_runs_in_strict_mode_and_a_promise_is_awaited(tmp_path):
    # Copied out of an ES module, the declarations keep its strict semantics: a write to a frozen object throws.
    frozen = ("function canon(v) {\n"
              "  const f = Object.freeze({});\n"
              "  if (typeof v.n === 'number' && !Number.isFinite(v.n)) f.x = 1;\n"
              "  return JSON.stringify(v, Object.keys(v).sort());\n"
              "}\n")
    run = _score(tmp_path, frozen)
    assert "scored=2 pass=2 fail=0 " in run.stdout, run.stdout
    later = ("async function canon(v) {\n"
             "  await null;\n"
             "  if (v === null || typeof v !== 'object') return JSON.stringify(v);\n"
             "  const parts = [];\n"
             "  for (const k of Object.keys(v).sort()) parts.push(JSON.stringify(k) + ':' + (await canon(v[k])));\n"
             "  return '{' + parts.join(',') + '}';\n"
             "}\n")
    run = _score(tmp_path, later)
    # awaited, the object comes out canonical (a promise written as text would fail A3-001) and NaN as null fails
    assert "FAIL A3-001" not in run.stdout and "scored=2 pass=1 fail=1 " in run.stdout, run.stdout


def test_an_entry_name_that_is_not_an_identifier_is_refused(tmp_path):
    run = _score(tmp_path, SORTED, entry="canon|x")
    assert run.returncode == 2 and "is not an identifier" in run.stdout, run.stdout


def test_the_python_scorer_reads_the_same_cases_and_bytes_as_the_javascript_one(tmp_path):
    sys.path.insert(0, str(ROOT / "adapters"))
    try:
        import py_jcs_score
    finally:
        sys.path.pop(0)
    corpus = _corpus(tmp_path)
    # a directory that starts with "a" but is not a case group, and the card-signing group, are both left out
    for other in ("archive", "a2-signatures-exclusion"):
        (corpus / other).mkdir()
        (corpus / other / "X.json").write_text(json.dumps({"id": other, "disposition": "MUST-ACCEPT", "input": {},
                                                           "expected": {"canonical_utf8_hex": "7b7d"}}), encoding="utf-8")
    assert [c["id"] for c, _, _ in py_jcs_score.cases(corpus)] == ["A3-001", "A5-REJECT-016"]
    # a lone surrogate in a parsed input comes out as the escape JSON.stringify writes, not a crash
    assert py_jcs_score.case_bytes({"input": {"a": "\ud800"}}) == b'{"a": "\\ud800"}'
    run = _score(tmp_path, SORTED, corpus=corpus)
    assert "scored=2 " in run.stdout, run.stdout
