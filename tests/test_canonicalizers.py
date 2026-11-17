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


@pytest.mark.parametrize("pid,rec", _recorded(), ids=lambda v: str(v) if isinstance(v, int) else "")
def test_recorded_duplicates_field_matches_its_run(pid, rec):
    if rec["duplicates"] == "not probed":
        assert "evidence" not in rec or not rec["evidence"], f"project {pid}: not probed cites a run"
        return
    run = (ROOT / rec["evidence"].split()[0]).read_text(encoding="utf-8")
    probes = {m.group(1): (m.group(2), m.group(3)) for m in PROBE.finditer(run)}
    assert set(probes) == set(NO_FORM), f"project {pid}: the run has probes {sorted(probes)}"
    for name, (hexin, outcome) in probes.items():
        assert bytes.fromhex(hexin) == NO_FORM[name], f"project {pid}: probe {name} ran on other bytes"
    dup = {probes[n][1].split()[0] for n in ("duplicate-member", "duplicate-member-name")}
    assert dup == {rec["duplicates"]}, f"project {pid}: recorded {rec['duplicates']}, the run shows {dup}"


LENIENT = "function canon(v) { return JSON.stringify(v, Object.keys(v).sort()); }\n"
STRICT_BYTES = ("function canon(b) {\n"
                "  const t = new TextDecoder('utf-8', { fatal: true }).decode(b);\n"
                "  const seen = []; JSON.parse(t, function (k, v) { return v; });\n"
                "  if (/\"a\":1,\"a\"|\"name\":\"Good\",\"name\"/.test(t)) throw new Error('duplicate');\n"
                "  return t;\n"
                "}\n")


@pytest.mark.parametrize("source,flags,want", [(LENIENT, [], "accepted"), (STRICT_BYTES, ["--bytes"], "refused")])
def test_scorer_tells_a_refusing_canonicalizer_from_a_lenient_one(source, flags, want, tmp_path):
    src = tmp_path / "canon.mjs"
    src.write_text(source, encoding="utf-8")
    corpus = tmp_path / "corpus"
    (corpus / "a3-x").mkdir(parents=True)
    run = subprocess.run(["node", str(ROOT / "adapters" / "jcs_function_score.mjs"), "--source", str(src),
                          "--entry", "canon", *flags, str(corpus)], capture_output=True, text=True, check=False)
    assert run.returncode == 0, run.stdout + run.stderr
    outcomes = {m.group(1): m.group(3).split()[0] for m in PROBE.finditer(run.stdout)}
    assert outcomes["duplicate-member"] == want and outcomes["duplicate-member-name"] == want, run.stdout
