# b7n0de verifier results, 15 November 2026

Results of two verifiers written by b7n0de, run against two corpora of
[probityai/agent-evidence-vectors](https://github.com/probityai/agent-evidence-vectors) at commit
`250de75575a945d00211415d7af41894d15427fa`.

| File | What it holds |
|---|---|
| [RESULTS.md](RESULTS.md) | one table per verifier, and the members whose verdict differs |
| [results.json](results.json) | the same per member, with the SHA-256 of every member file |
| [contract/report.json](contract/report.json) | the report of `packaging/run_vectors.py` for the audit-record verifier under the external-verifier contract |
| [contract/runner.log](contract/runner.log) | the runner's output for that run |
| [LICENSE](LICENSE) | Apache License 2.0 |

The source code of both verifiers is in the accompanying archive `b7n0de-verifier-source-20261115.tar.gz`, SHA-256
`a81ab5af84a8da9cce6f64b65a911a83cc3a09973bb34bfce08da79f65cbd8fa`. How to recompute our verdicts with it is below.

## The two verifiers

The audit-record verifier read the 225 members of `corpora/vectors-agent-audit-record` and agrees with the verdict in
`MANIFEST.json` on 187. Of the 38 others, 15 name revision 01 in `draftRevision`, 22 name revision 04, and X6 names
none.

The restoration-evidence verifier read the 57 members of `corpora/vectors-restart-records` and agrees with
`MANIFEST.json` on verdict and reason for all 57.

## What you can check from the corpus alone

Everything about the corpus side of these results. Clone the corpus at the commit, then run the check below. It
confirms that `results.json` names every member of both corpora, that each member file has the SHA-256 given, that
each expected verdict is the one in `MANIFEST.json`, and that the counts follow from the rows.

```sh
git clone https://github.com/probityai/agent-evidence-vectors
git -C agent-evidence-vectors checkout 250de75575a945d00211415d7af41894d15427fa
python3 -I - agent-evidence-vectors results.json <<'PY'
import hashlib, json, os, sys
repo, results = sys.argv[1], sys.argv[2]
sha = lambda p: hashlib.sha256(open(p, "rb").read()).hexdigest()
bad = 0
for c in json.load(open(results))["verifiers"]:
    root = os.path.join(repo, c["corpus"])
    man = json.load(open(os.path.join(root, "MANIFEST.json")))
    bad += sha(os.path.join(root, "MANIFEST.json")) != c["manifestSha256"]
    rows = {r["id"]: r for r in c["results"]}
    bad += set(rows) != {v["id"] for v in man["vectors"]}
    for v in man["vectors"]:
        r = rows[v["id"]]
        if "files" in r:
            files = {v["path"] + "/" + f: h for f, h in v["files"].items()}
            bad += files != r["files"] or any(sha(os.path.join(root, f)) != h for f, h in files.items())
            want = (v["expected"]["verdict"], v["expected"]["reason"])
            bad += want != (r["expectedVerdict"], r["expectedReason"])
            bad += r["verdictMatch"] != (r["ourVerdict"] == want[0])
        else:
            bad += sha(os.path.join(root, v["file"])) != r["sha256"]
            want = v["expected"].get("verdict") or "any of " + "|".join(
                x["verdict"] if isinstance(x, dict) else x for x in v.get("readings", []))
            bad += want != r["expectedVerdict"]
            ok = r["ourVerdict"] in want[7:].split("|") if want.startswith("any of ") else r["ourVerdict"] == want
            bad += r["verdictMatch"] != ok
    n_eq = sum(r["verdictMatch"] for r in c["results"])
    bad += (len(rows), n_eq, len(rows) - n_eq) != (c["members"], c["equal"], c["different"])
    print(c["corpus"], "members", len(rows), "our verdict equal", n_eq, "different", len(rows) - n_eq)
print("mismatches", bad)
sys.exit(1 if bad else 0)
PY
```

It prints the two counts and `mismatches 0`, and exits 0. One changed byte in a member file makes it exit 1.

## Recomputing our verdicts

The source code of both verifiers comes with this package as a separate archive,
`b7n0de-verifier-source-20261115.tar.gz`, SHA-256
`a81ab5af84a8da9cce6f64b65a911a83cc3a09973bb34bfce08da79f65cbd8fa`, under the Apache License 2.0. Its `BUILD.md`
gives every command with its expected exit code. In short:

```sh
sha256sum b7n0de-verifier-source-20261115.tar.gz
tar -xzf b7n0de-verifier-source-20261115.tar.gz && cd b7n0de-verifier-source-20261115
python3 -m venv venv && venv/bin/pip install cryptography==50.0.2 pytest==9.2.0
git clone --bare https://github.com/probityai/agent-evidence-vectors aev.git
venv/bin/python -I audit-record/agent_evidence_01/tools/run_all.py --work ../agent-evidence-run --repository aev.git
```

`run_all.py` checks the 304 pinned corpus files, runs both verifiers and the planted faults, writes 286 result files
to `../agent-evidence-run/results` and exits 0 when they are byte-equal to the results stored in the source archive.
It needs no network once the clone exists. The check below then compares our verdicts in `results.json` with those
fresh files, the verdict for every member and for restoration evidence the reason as well. Run it from the folder that
holds results.json. Replace `<run>` with the working directory given to `run_all.py`.

```sh
python3 -I - <run>/results results.json <<'PY'
import json, os, sys
fresh, results = sys.argv[1], sys.argv[2]
bad = 0
for c in json.load(open(results))["verifiers"]:
    aar = c["corpus"].endswith("agent-audit-record")
    folder = os.path.join(fresh, "agent_audit_record" if aar else "restoration_evidence")
    names = [n for n in os.listdir(folder) if not n.startswith("_")]
    for r in c["results"]:
        f = json.load(open(os.path.join(folder, "%s__%s.json" % (r["draftId"], r["id"]) if aar else r["id"] + ".json")))
        bad += (f["own"]["verdict"], f["match"]) != (r["ourVerdict"], r["verdictMatch"])
        bad += (not aar) and f["own"]["reason"] != r["ourReason"]
    bad += len(names) != len(c["results"])
    print(c["corpus"], "rows", len(c["results"]), "result files", len(names))
print("mismatches", bad)
sys.exit(1 if bad else 0)
PY
```

It prints the row and file counts of both corpora and `mismatches 0`, and exits 0.

## What stays our statement

The way the verifiers were written. We state that they were written from the text of the two drafts alone,
without reading any code of the vector repository, and that the runs that produced these results had no network
access. The source archive lets you read the code against the drafts and rerun every verdict, but it cannot show how
the code came about.

## The external-verifier contract run

The audit-record verifier was also run through the external-verifier contract of agent-evidence-vectors, at the head
of pull request 575 (`34704695b763814f2f56d7926939131553465208`), with a thin adapter that reshapes its result into the
contract's output.

```sh
venv/bin/python ../pr575/packaging/run_vectors.py --vectors ../pr575/corpora/vectors-agent-audit-record \
  --verifier "venv/bin/python -I contract-adapter/contract_adapter.py audit-record/agent_evidence_01/tools" \
  --report ../contract-report.json
```

It runs from the root of the source archive, with `../pr575` a checkout of that head; the adapter is
`contract-adapter/contract_adapter.py` there.

The member files at that head are byte-equal to the commit above. The runner reports 180 of 225 members conforming
and exits 1. Of the 45 failing members, 38 are the verdict differences in `RESULTS.md`, one (CS32) has an equal
verdict and a different set verdict, and six (CS7, CS8, CS17, SQ5, X17, X18) fail only on `set.codes`, because our
verifier has no names for set results in the corpus vocabulary and passes its own check names instead. For those six,
the record and set verdicts match; the contract still reports failure because set.codes differs or is empty.

Assisted by little helpers.
