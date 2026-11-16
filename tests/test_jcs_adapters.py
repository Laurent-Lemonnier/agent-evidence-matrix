"""The JCS adapters refuse input that has no RFC 8785 canonical form.

Counter-examples: a duplicate member (top level, nested and carrying a privilege, and spelled
with an escape) was canonicalized with exit 0 because json.loads keeps the last value. The
a2a-jcs corpus has no duplicate-member vector, so the corpus-jcs job could not see it.
"""
import json
import pathlib
import subprocess
import sys

import pytest

CLI = pathlib.Path(__file__).resolve().parents[1] / "adapters" / "rfc8785_cli.py"


def run(tmp_path, raw: bytes, target: str = "rfc8785"):
    path = tmp_path / "input.json"
    path.write_bytes(raw)
    return subprocess.run([sys.executable, str(CLI), target, str(path)], capture_output=True, text=True)


@pytest.mark.parametrize("raw", [
    b'{"a":1,"a":2}',
    b'{"a":1,"\\u0061":2}',
    b'{"grant":{"capabilities":["read"],"capabilities":["exec"]}}',
    b'{"capabilities":["db:read"],"capabilities":["system:exec"]}',
])
def test_a_duplicate_member_is_refused(tmp_path, raw):
    assert run(tmp_path, raw).returncode == 1


@pytest.mark.parametrize("raw", [b'{"a":"\xff"}', b'{"a":"\xed\xa0\x80"}', b'{"a":NaN}'])
def test_invalid_utf8_and_constants_are_refused(tmp_path, raw):
    assert run(tmp_path, raw).returncode == 1


def test_a_clean_object_still_canonicalizes(tmp_path):
    out = run(tmp_path, b'{"b":1,"a":[1.0,-0]}')
    assert out.returncode == 0
    assert json.loads(out.stdout)["canonical_utf8_hex"] == b'{"a":[1,0],"b":1}'.hex()


def test_a_target_the_adapter_does_not_implement_is_not_run(tmp_path):
    assert run(tmp_path, b'{"a":1}', "card-signing-input").returncode == 2


def test_a_crash_is_errored_not_a_refusal(tmp_path, monkeypatch):
    """A canonicalizer that raises an unexpected exception must exit 2, never score as a MUST-REJECT pass."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("rfc8785_cli", CLI)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    def boom(value):
        raise AttributeError("api changed")
    monkeypatch.setattr(mod.rfc8785, "dumps", boom)
    path = tmp_path / "input.json"
    path.write_bytes(b'{"a":1}')
    assert mod.main(["rfc8785_cli.py", "rfc8785", str(path)]) == 2


def test_the_eatf_adapter_separates_refusal_paths_from_crashes(tmp_path, monkeypatch):
    import importlib.util
    import types
    lib = tmp_path / "lib"
    (lib / "eatf_verifier").mkdir(parents=True)
    (lib / "eatf_verifier" / "__init__.py").write_text("")
    (lib / "eatf_verifier" / "canonical.py").write_text("import rfc8785\n\ndef jcs(v):\n    return rfc8785.dumps(v)\n")
    monkeypatch.setenv("EATF_LIB_PYTHON", str(lib))
    spec = importlib.util.spec_from_file_location("eatf_jcs_cli", CLI.parent / "eatf_jcs_cli.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert mod.outcome(b'{"a":1}')[0] == 0
    assert mod.outcome(b'{"a":')[1].startswith("refused-by-parser")
    assert mod.outcome(b'{"a":NaN}')[1].startswith("refused-by-profile")
    assert mod.outcome(b'{"\\ud800":1}')[1].startswith("refused-by-encoder")
    monkeypatch.setattr(mod, "jcs", lambda v: (_ for _ in ()).throw(AttributeError("api changed")))
    assert mod.outcome(b'{"a":1}') == (2, "errored AttributeError", None)


# Counter-examples: an input that cannot be read, and one that runs the parser out of stack, exited 1 and
# scored as "no canonical form" (a MUST-REJECT pass) in both adapters. Neither was judged.
DEEP = b"[" * 200000 + b"]" * 200000


def test_an_unreadable_input_is_errored_not_a_refusal(tmp_path):
    out = subprocess.run([sys.executable, str(CLI), "rfc8785", str(tmp_path / "missing.json")],
                         capture_output=True, text=True)
    assert out.returncode == 2 and "errored" in out.stderr


def test_a_parser_stack_overflow_is_errored_not_a_refusal(tmp_path):
    out = run(tmp_path, DEEP)
    assert out.returncode == 2 and "errored RecursionError" in out.stderr


def test_the_eatf_adapter_does_not_score_an_unread_or_unparsed_input_as_refused(tmp_path, monkeypatch):
    lib = tmp_path / "lib"
    (lib / "eatf_verifier").mkdir(parents=True)
    (lib / "eatf_verifier" / "__init__.py").write_text("")
    (lib / "eatf_verifier" / "canonical.py").write_text("import rfc8785\n\ndef jcs(v):\n    return rfc8785.dumps(v)\n")
    eatf = CLI.parent / "eatf_jcs_cli.py"
    env = {"EATF_LIB_PYTHON": str(lib), "EATF_CLASS_LOG": str(tmp_path / "classes.log"), "PATH": "/usr/bin:/bin"}
    missing = subprocess.run([sys.executable, str(eatf), "rfc8785", str(tmp_path / "missing.json")],
                             capture_output=True, text=True, env=env)
    assert missing.returncode == 2
    deep = tmp_path / "deep.json"
    deep.write_bytes(DEEP)
    out = subprocess.run([sys.executable, str(eatf), "rfc8785", str(deep)], capture_output=True, text=True, env=env)
    assert out.returncode == 2
    assert (tmp_path / "classes.log").read_text().splitlines() == [
        "missing.json\terrored FileNotFoundError", "deep.json\terrored RecursionError"]
