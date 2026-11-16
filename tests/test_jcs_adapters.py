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
