# Copyright 2026 Konrad Gruszka
# Licensed under the Apache License, Version 2.0; see LICENSE.
"""Runs every vector of corpora/vectors-agent-audit-record through aar_verifier.

Usage: python -I run_aar.py <tools_dir> <corpus_dir> <result_dir>
From MANIFEST.json it reads only the file list, the expected results, the pinned keys (keys) and the
anchor trust (anchorTrust). No semantics are taken from code of the corpus.
"""
import importlib.util
import json
import os
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def load_verifier(tools_dir):
    spec = importlib.util.spec_from_file_location("aar_verifier", os.path.join(tools_dir, "aar_verifier.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def same_instant(A, a, b):
    """Two dating times name the same instant, whatever their RFC 3339 spelling, or are both absent."""
    if a is None or b is None:
        return a is b
    try:
        return A.t(a, "datedAt") == A.t(b, "datedAt")
    except A.Fail:
        return a == b


def clean(o):
    return {k: v for k, v in o.items() if not k.startswith("_")}


def run(tools_dir, kdir, odir):
    A = load_verifier(tools_dir)
    man = A.read_json(open(os.path.join(kdir, "MANIFEST.json"), "rb").read())
    OBS = man["keys"]["observer"]
    PINNED = {OBS["keyid"]: Ed25519PublicKey.from_public_bytes(bytes.fromhex(OBS["publicKey"]))}
    TRUST = man["anchorTrust"]
    os.makedirs(odir, exist_ok=True)
    rows = []
    for v in man["vectors"]:
        fp = os.path.join(kdir, v["file"])
        raw = open(fp, "rb").read()
        try:
            obj = A.read_json(raw)  # the reader of the Statement, for the file and the entry in it (4.7)
        except A.Fail:
            obj = None
        exp = v["expected"]
        res = {"draftId": v["draftId"], "file": v["file"], "kind": v["kind"],
               "draftRevision": v.get("draftRevision"), "draftSection": v.get("draftSection"),
               "expected": exp}
        top = v["file"].split("/")[0]
        if top == "retained":
            rec, dat = A.check_retained(obj, PINNED, TRUST)
            res["own"] = {"verdict": rec["verdict"], "failure": rec.get("failure"),
                          "derivedTier": rec.get("derivedTier"), "dating": dat}
        elif top == "sets":
            outs = []
            okset = []
            for env in (obj or {}).get("records", []):
                o = A.verify_record(env, PINNED)
                outs.append(clean(o))
                if o["verdict"] == "valid":
                    okset.append((o, o["_statement"]))
            allvalid = bool(outs) and all(o["verdict"] == "valid" for o in outs)
            missing, conflicts = A.check_sequence_set(okset)
            cfails = A.check_consumption_set(okset)
            # Reading L-SET: a set without readable records or with a malformed record is malformed as a set
            setv = "valid" if (allvalid and not (conflicts or cfails)) else "malformed"
            res["own"] = {"verdict": "valid" if allvalid else "malformed", "records": outs,
                          "set": {"verdict": setv, "missing": missing, "conflicts": conflicts,
                                  "consumptionFailures": cfails,
                                  "withinLimit": [o.get("withinLimit") for o in outs]}}
            tiers = {o.get("derivedTier") for o in outs}
            if len(tiers) == 1:
                res["own"]["derivedTier"] = tiers.pop()
        else:
            o = A.verify_record(obj, PINNED)
            res["own"] = clean(o)
        ev = exp.get("verdict")
        own = res["own"]["verdict"]
        if v["kind"] == "indeterminate":
            # Only the verdict of each manifest reading is kept, not its rationale text (see NOTICE.md)
            readings = [r.get("verdict") if isinstance(r, dict) else r for r in v.get("readings", [])]
            res["readingVerdicts"] = readings
            res["ownVerdictAmongReadings"] = own in readings
            res["match"] = True if not readings else own in readings
        else:
            res["match"] = (own == ev)
        sub = {}
        if "derivedTier" in exp and own == "valid":
            sub["derivedTier"] = res["own"].get("derivedTier") == exp["derivedTier"]
        if "withinLimit" in exp and own == "valid":
            sub["withinLimit"] = res["own"].get("withinLimit") == exp["withinLimit"]
        if "dating" in exp:
            d, ed = res["own"]["dating"], exp["dating"]
            sub["dating.entry"] = d["entry"] == ed.get("entry")
            sub["dating.datedAt"] = same_instant(A, d["datedAt"], ed.get("datedAt"))
            sub["dating.delegationRoot"] = \
                d["delegationRoot"].get("result") == ed.get("delegationRoot", {}).get("result") and \
                d["delegationRoot"].get("algorithm") == ed.get("delegationRoot", {}).get("algorithm")
            if "receipt" in ed or d.get("receipt"):
                sub["dating.receipt"] = d.get("receipt") == ed.get("receipt")
        if "set" in exp:
            s, es = res["own"]["set"], exp["set"]
            sub["set.verdict"] = s["verdict"] == es.get("verdict")
            if "missing" in es:
                sub["set.missing"] = s["missing"] == es["missing"]
        res["subMatch"] = sub
        rows.append(res)
        with open(os.path.join(odir, "%s__%s.json" % (v["draftId"], v["id"])), "w") as f:
            json.dump(res, f, indent=1, sort_keys=True)

    n = len(rows)
    m = sum(r["match"] for r in rows)
    print("agent-audit-record: %d vectors, verdict equal %d, not equal %d" % (n, m, n - m))
    subt = {}
    for r in rows:
        for k, ok in r["subMatch"].items():
            a = subt.setdefault(k, [0, 0])
            a[0 if ok else 1] += 1
    print("secondary results (equal, not equal):", json.dumps(subt, sort_keys=True))
    for r in rows:
        if not r["match"] or not all(r["subMatch"].values()):
            o = r["own"]
            print("DIFF %-6s kind=%s exp=%s own=%s fail=%s rev=%s sec=%s sub=%s" % (
                r["draftId"], r["kind"], r["expected"].get("verdict"), o["verdict"],
                (o.get("failure") or {}).get("code"), (r["draftRevision"] or "")[-2:], r["draftSection"],
                {k: v for k, v in r["subMatch"].items() if not v}))
    with open(os.path.join(odir, "_summary.json"), "w") as f:
        json.dump({"n": n, "match": m, "sub": subt}, f, indent=1)
    by_revision(A, man, odir)
    return rows


def by_revision(A, man, odir):
    """Matches per draft revision that a vector names (draftRevision, else the manifest's draft)."""
    table = {}
    per = []
    for v in man["vectors"]:
        rev = v.get("draftRevision", man["draft"])
        r = A.read_json(open(os.path.join(odir, "%s__%s.json" % (v["draftId"], v["id"])), "rb").read())
        a = table.setdefault(rev, {"n": 0, "match": 0})
        a["n"] += 1
        a["match"] += int(r["match"])
        per.append({"draftId": v["draftId"], "revision": rev, "section": v.get("draftSection"),
                    "expected": v["expected"].get("verdict", "indeterminate"), "own": r["own"]["verdict"],
                    "match": r["match"]})
    with open(os.path.join(odir, "_by_revision.json"), "w") as f:
        json.dump({"table": table, "vectors": per}, f, indent=1)
    print("matches per named draft revision (agent-audit-record): " + json.dumps(table, sort_keys=True))


if __name__ == "__main__":
    run(*sys.argv[1:4])
