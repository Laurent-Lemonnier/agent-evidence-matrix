"""reader_cells.py refuses a mutation that names no file it reads.

Counter-example: `--mutation typo/x/r.jcs` left the run unmutated, every line supported and exit 0, so a
mutation step pointed at a renamed or misspelled file would pass while proving nothing. A stub reader on
PATH stands in for agent-evidence-verify (it judges RFC 8785 bytes with the rfc8785 package).
"""
import os
import pathlib
import subprocess
import sys

CELLS = pathlib.Path(__file__).resolve().parents[1] / "adapters" / "reader_cells.py"
STUB = """#!{python}
import json, pathlib, sys
import rfc8785
case = json.load(open(sys.argv[1]))
root = pathlib.Path(sys.argv[sys.argv.index("--artifact-root") + 1])
raw = (root / case["artifacts"]["input"]["path"]).read_bytes()
same = rfc8785.dumps(json.loads(raw)) == raw
print(json.dumps({{"decision": "supported" if same else "contradicted", "reason": "stub"}}))
"""


def run(tmp_path, *args):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    stub = bin_dir / "agent-evidence-verify"
    stub.write_text(STUB.format(python=sys.executable))
    stub.chmod(0o755)
    checkout = tmp_path / "co" / "x"
    checkout.mkdir(parents=True, exist_ok=True)
    (checkout / "r.jcs").write_bytes(b'{"a":1,"b":2}')
    env = dict(os.environ, PATH=f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")
    return subprocess.run([sys.executable, "-I", str(CELLS), *args, f"lab={tmp_path / 'co'}"],
                          capture_output=True, text=True, env=env)


def test_a_named_mutation_turns_its_line_and_exits_1(tmp_path):
    out = run(tmp_path, "--mutation", "lab/x/r.jcs")
    assert out.returncode == 1 and "lab/x/r.jcs\tcontradicted" in out.stdout


def test_a_mutation_that_names_no_file_is_a_setup_error(tmp_path):
    out = run(tmp_path, "--mutation", "typo/x/r.jcs")
    assert out.returncode == 2 and "names no file" in out.stderr


def test_the_unmutated_run_passes(tmp_path):
    assert run(tmp_path).returncode == 0
