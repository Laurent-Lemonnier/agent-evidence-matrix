"""Adapter: the Tamarin proof transcript of a formal model of MCP authorization, read against its own table.

usage: mcp_auth_tamarin_adapter.py <records dir holding tamarin-results.zip, prove.sh and DIGESTS> [<transcript dir>]

The records are the project's own: the CI artifact of the pinned commit (one Tamarin transcript per model and
variant) and scripts/prove.sh, whose expectation table states for each model, variant and lemma whether
Tamarin must report verified or falsified. Both files are retained in records/mcp-auth-tamarin/ because the
artifact expires; each is checked against DIGESTS before it is read, and a mismatch refuses the run (exit 2).
A second argument reads a directory of transcripts instead of the zip (a re-proof run), with the same table.

Lines ("PASS|DIFF|INFO  case: detail"):
  retention/<file>       the retained bytes equal the recorded digest
  table/expectations     rows in the table, by expected outcome
  table/match            each row against the transcript's "summary of summaries"; a row the transcript does
                         not report is not run, never a match
  coverage/unpinned      lemmas the transcript reports that no table row pins
  vacuity/<model>/<var>  a variant whose executable lemma is falsified: its verified rows hold vacuously, so
                         they are counted as not run rather than as agreement
  model/<model>          per model: rows matched, mismatched, not run
Exit 0 when every table row is reported and matches, 1 when one differs or is missing, 2 on a setup error.
"""
import collections
import hashlib
import pathlib
import re
import sys
import zipfile

ROW = re.compile(r'"(models/[^"|]+\.spthy)\|([^"|]+)\|([^"|]+)\|(verified|falsified)"')
RESULT = re.compile(r"^\s+(\w+) \((?:all-traces|exists-trace)\): (verified|falsified)", re.M)


def variant(flags):
    return "fixed" if flags == "-" else "+".join(x.lower() for x in flags.split(","))


def transcripts(records, alt):
    if alt is not None:
        return {p.name: p.read_text(errors="replace") for p in pathlib.Path(alt).glob("*.txt")}
    with zipfile.ZipFile(records / "tamarin-results.zip") as z:
        return {pathlib.PurePosixPath(n).name: z.read(n).decode("utf-8", "replace")
                for n in z.namelist() if n.endswith(".txt")}


def main(argv):
    if len(argv) not in (1, 2):
        sys.exit(__doc__)
    records = pathlib.Path(argv[0])
    out = []

    def emit(status, case, detail):
        out.append(status)
        print(f"{status:4}  {case}: {detail}")

    for line in (records / "DIGESTS").read_text().splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        want, name = line.split()
        have = hashlib.sha256((records / name).read_bytes()).hexdigest()
        if have != want:
            print(f"setup: {name} sha256 {have} is not the recorded {want}", file=sys.stderr)
            return 2
        emit("PASS", f"retention/{name}", f"sha256 {want[:16]}... as recorded")
    rows = ROW.findall((records / "prove.sh").read_text())
    if not rows or len({r[:3] for r in rows}) != len(rows):
        print("setup: the expectation table is empty or names a lemma twice", file=sys.stderr)
        return 2
    exp = collections.Counter(r[3] for r in rows)
    emit("INFO", "table/expectations", f"{len(rows)} rows: {exp['verified']} expected verified, "
         f"{exp['falsified']} expected falsified (attacks the model is built to find)")
    got = {}
    for name, text in transcripts(records, argv[1] if len(argv) == 2 else None).items():
        if name == "timings.tsv" or "." not in name[:-4]:
            continue
        stem, var = name[:-4].split(".", 1)
        for lemma, verdict in RESULT.findall(text.split("summary of summaries:")[-1]):
            got[(stem, var, lemma)] = verdict
    vacuous = {k[:2] for k, v in got.items() if k[2] == "executable" and v != "verified"}
    per = collections.defaultdict(collections.Counter)
    total = collections.Counter()
    for model, flags, lemma, want in rows:
        key = (pathlib.PurePosixPath(model).stem, variant(flags), lemma)
        have = got.get(key)
        state = ("not run" if have is None else "match" if have == want else "mismatch")
        if state == "match" and key[:2] in vacuous and lemma != "executable" and want == "verified":
            state = "vacuous"
        per[key[0]][state] += 1
        total[state] += 1
    emit("PASS" if total["match"] + total["vacuous"] == len(rows) else "DIFF", "table/match",
         f"{total['match']} of {len(rows)} rows match the transcript, {total['vacuous']} more match only vacuously, "
         f"{total['mismatch']} mismatch, {total['not run']} not reported")
    pinned = {(pathlib.PurePosixPath(m).stem, variant(f), l) for m, f, l, _ in rows}
    extra = sorted(set(got) - pinned)
    emit("INFO", "coverage/unpinned", f"{len(extra)} of {len(got)} reported lemmas have no table row: "
         + ", ".join("/".join(k) for k in extra))
    for stem, var in sorted(vacuous):
        verified = sorted(k[2] for k in got if k[:2] == (stem, var) and k[2] != "executable" and got[k] == "verified")
        emit("INFO", f"vacuity/{stem}/{var}", f"executable is falsified, so the honest run cannot complete and "
             f"{len(verified)} verified lemmas hold vacuously: {verified}")
    for stem in sorted(per):
        c = per[stem]
        emit("INFO", f"model/{stem}", f"{c['match']} match, {c['vacuous']} vacuous, {c['mismatch']} mismatch, "
             f"{c['not run']} not reported")
    print(f"SUMMARY pass={out.count('PASS')} diff={out.count('DIFF')} info={out.count('INFO')}")
    return 1 if "DIFF" in out else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
