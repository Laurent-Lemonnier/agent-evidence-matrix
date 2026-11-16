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


# Counter-examples from the adversarial read: with the zip's line removed from DIGESTS (or DIGESTS empty)
# a re-zipped results file was read unverified and the run passed; a transcript cut before its summary
# still had its result-shaped lines counted.

def _copy_without_zip_digest(tmp_path, keep):
    copy = tmp_path / "r"
    shutil.copytree(RECORDS, copy)
    lines = [l for l in (RECORDS / "DIGESTS").read_text().splitlines() if keep(l)]
    (copy / "DIGESTS").write_text("\n".join(lines) + "\n")
    with zipfile.ZipFile(RECORDS / "tamarin-results.zip") as z, zipfile.ZipFile(copy / "tamarin-results.zip", "w") as o:
        for n in z.namelist():
            o.writestr(n, z.read(n))
    return copy


def test_a_file_read_with_no_digest_line_is_a_setup_error(tmp_path):
    copy = _copy_without_zip_digest(tmp_path, lambda l: "tamarin-results.zip" not in l)
    out = run(copy)
    assert out.returncode == 2 and "no digest" in out.stderr


def test_an_empty_digests_file_is_a_setup_error(tmp_path):
    copy = _copy_without_zip_digest(tmp_path, lambda l: False)
    assert run(copy).returncode == 2


def test_a_transcript_without_its_summary_reports_no_lemma(tmp_path):
    with zipfile.ZipFile(RECORDS / "tamarin-results.zip") as z:
        z.extractall(tmp_path / "x")
    flat = tmp_path / "flat"
    flat.mkdir()
    for p in (tmp_path / "x").rglob("*.txt"):
        text = p.read_text()
        if p.name == "01_as_selection.fixed.txt":
            text = text.replace("summary of summaries:", "")
        (flat / p.name).write_text(text)
    out = run(RECORDS, flat)
    assert out.returncode == 1 and "not reported" in out.stdout
