"""The Tamarin adapter refuses retained bytes that changed and reports a transcript that disagrees."""
import pathlib
import shutil
import subprocess
import sys
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
ADAPTER = ROOT / "adapters" / "mcp_auth_tamarin_adapter.py"
RECORDS = ROOT / "records" / "mcp-auth-tamarin"


def run(*args):
    return subprocess.run([sys.executable, "-I", str(ADAPTER), *map(str, args)], capture_output=True, text=True)


def test_the_retained_records_match_their_table():
    out = run(RECORDS)
    assert out.returncode == 0 and "372 of 376 rows match" in out.stdout and "4 more match only vacuously" in out.stdout


def test_a_changed_retained_file_is_a_setup_error(tmp_path):
    copy = tmp_path / "r"
    shutil.copytree(RECORDS, copy)
    with open(copy / "prove.sh", "a") as f:
        f.write("\n")
    assert run(copy).returncode == 2


def test_a_flipped_verdict_in_a_transcript_is_a_mismatch(tmp_path):
    with zipfile.ZipFile(RECORDS / "tamarin-results.zip") as z:
        z.extractall(tmp_path / "x")
    texts = sorted((tmp_path / "x").rglob("01_as_selection.fixed.txt"))
    t = texts[0].read_text()
    head, _, tail = t.rpartition("summary of summaries:")
    texts[0].write_text(head + "summary of summaries:" + tail.replace("verified", "falsified", 1))
    flat = tmp_path / "flat"
    flat.mkdir()
    for p in (tmp_path / "x").rglob("*.txt"):
        shutil.copy(p, flat / p.name)
    out = run(RECORDS, flat)
    assert out.returncode == 1 and "1 mismatch" in out.stdout


def test_a_missing_transcript_is_not_a_match(tmp_path):
    with zipfile.ZipFile(RECORDS / "tamarin-results.zip") as z:
        z.extractall(tmp_path / "x")
    flat = tmp_path / "flat"
    flat.mkdir()
    for p in (tmp_path / "x").rglob("*.txt"):
        if p.name != "01_as_selection.fixed.txt":
            shutil.copy(p, flat / p.name)
    out = run(RECORDS, flat)
    assert out.returncode == 1 and "not reported" in out.stdout
