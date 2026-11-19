# Copyright 2026 Konrad Gruszka
# Licensed under the Apache License, Version 2.0; see LICENSE.
"""Runs every vector of corpora/vectors-restart-records through rer_verifier.

Usage: python -I run_rer.py <tools_dir> <corpus_dir> <result_dir>
From MANIFEST.json it reads only the file list, the file digests and the expected results.
"""
import hashlib
import importlib.util
import json
import os
import sys


def load_verifier(tools_dir):
    spec = importlib.util.spec_from_file_location("rer_verifier", os.path.join(tools_dir, "rer_verifier.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run(tools_dir, kdir, odir):
    R = load_verifier(tools_dir)
    man = R.parse(open(os.path.join(kdir, "MANIFEST.json"), "rb").read())  # the reader of the statements
    os.makedirs(odir, exist_ok=True)
    rows = []
    for v in man["vectors"]:
        d = os.path.join(kdir, v["path"])
        items = []
        hash_ok = True
        for fn in sorted(v["files"]):
            raw = open(os.path.join(d, fn), "rb").read()
            if hashlib.sha256(raw).hexdigest() != v["files"][fn]:
                hash_ok = False
            items.append((fn, raw))
        if v["shape"] == "record":
            own = R.check_record_bytes(items[0][1])
        else:
            own = R.check_bundle(items)
        exp = v["expected"]
        res = {"id": v["id"], "shape": v["shape"], "kind": v["kind"], "rule": v.get("rule"),
               "fileHashesMatchManifest": hash_ok, "expected": exp, "own": own,
               "match": own["verdict"] == exp["verdict"], "reasonMatch": own["reason"] == exp["reason"]}
        rows.append(res)
        with open(os.path.join(odir, v["id"] + ".json"), "w") as f:
            json.dump(res, f, indent=1, sort_keys=True)
    n = len(rows)
    m = sum(r["match"] for r in rows)
    rm = sum(r["match"] and r["reasonMatch"] for r in rows)
    print("restoration-evidence: %d vectors, verdict equal %d, not equal %d, verdict and reason equal %d"
          % (n, m, n - m, rm))
    print("file digests as in MANIFEST:", sum(r["fileHashesMatchManifest"] for r in rows), "of", n)
    for r in rows:
        if not (r["match"] and r["reasonMatch"]):
            print("DIFF %-55s exp=%s/%s own=%s/%s %s" % (
                r["id"], r["expected"]["verdict"], r["expected"]["reason"],
                r["own"]["verdict"], r["own"]["reason"], r["own"].get("text", "")[:90]))
    with open(os.path.join(odir, "_summary.json"), "w") as f:
        json.dump({"n": n, "match": m, "reasonMatch": rm}, f, indent=1)
    return rows


if __name__ == "__main__":
    run(*sys.argv[1:4])
