# Copyright 2026 Konrad Gruszka
# Licensed under the Apache License, Version 2.0; see LICENSE.
"""Thin adapter: answers one member of corpora/vectors-agent-audit-record under the external-verifier
contract (agent-audit-record/v1) with the b7n0de audit-record verifier (tools/aar_verifier.py).

Usage: python -I contract_adapter.py <tools_dir> <member file> --json
It walks up from the member file to the first MANIFEST.json and takes only keys.observer and anchorTrust
from it, as tools/run_aar.py does. Nothing under "expected" is read. The verification branches are the
ones of tools/run_aar.py, unchanged; this file only reshapes the verifier's own result:
  verdict            own verdict
  codes              the code of each failure the verifier reports (it reports at most one per record)
  derivedTier        own derivedTier where the verifier gives one
  withinLimit        own withinLimit where the verifier gives one
  set                verdict, missing, withinLimit; codes = the verifier's own check names of
                     conflicts and consumption failures, verbatim (it has no code vocabulary for sets)
  dating             entry, datedAt, receipt (omitted when none), delegationRoot, codes from its failure
Exit 0 for valid, 1 for malformed, 2 when the member cannot be answered.
"""
import importlib.util
import json
import os
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def load(tools_dir):
    spec = importlib.util.spec_from_file_location("aar_verifier", os.path.join(tools_dir, "aar_verifier.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def manifest_above(A, path):
    here = os.path.dirname(os.path.realpath(path))
    while True:
        cand = os.path.join(here, "MANIFEST.json")
        if os.path.isfile(cand):
            return here, A.read_json(open(cand, "rb").read())
        parent = os.path.dirname(here)
        if parent == here:
            raise FileNotFoundError("no MANIFEST.json above %s" % path)
        here = parent


def code(failure):
    return [failure["code"]] if isinstance(failure, dict) and failure.get("code") else []


def answer(tools_dir, path):
    A = load(tools_dir)
    kdir, man = manifest_above(A, path)
    obs = man["keys"]["observer"]
    pinned = {obs["keyid"]: Ed25519PublicKey.from_public_bytes(bytes.fromhex(obs["publicKey"]))}
    trust = man["anchorTrust"]
    raw = open(path, "rb").read()
    try:
        obj = A.read_json(raw)
    except A.Fail:
        obj = None
    top = os.path.relpath(os.path.realpath(path), kdir).split(os.sep)[0]
    if top == "retained":
        rec, dat = A.check_retained(obj, pinned, trust)
        out = {"verdict": rec["verdict"], "codes": code(rec.get("failure"))}
        if rec.get("derivedTier") is not None:
            out["derivedTier"] = rec["derivedTier"]
        dating = {"entry": dat.get("entry"), "codes": code(dat.get("failure")), "datedAt": dat.get("datedAt"),
                  "delegationRoot": dat.get("delegationRoot")}
        if dat.get("receipt") is not None:
            dating["receipt"] = dat["receipt"]
        out["dating"] = dating
        return out
    if top == "sets":
        outs, okset = [], []
        for env in (obj or {}).get("records", []):
            o = A.verify_record(env, pinned)
            outs.append(o)
            if o["verdict"] == "valid":
                okset.append((o, o["_statement"]))
        allvalid = bool(outs) and all(o["verdict"] == "valid" for o in outs)
        missing, conflicts = A.check_sequence_set(okset)
        cfails = A.check_consumption_set(okset)
        setv = "valid" if (allvalid and not (conflicts or cfails)) else "malformed"
        setcodes = (["conflicts"] if conflicts else []) + sorted({c.get("check") for c in cfails if c.get("check")})
        out = {"verdict": "valid" if allvalid else "malformed",
               "codes": [c for o in outs for c in code(o.get("failure"))],
               "set": {"verdict": setv, "codes": setcodes, "missing": missing,
                       "withinLimit": [o.get("withinLimit") for o in outs]}}
        tiers = {o.get("derivedTier") for o in outs}
        if len(tiers) == 1:
            t = tiers.pop()
            if t is not None:
                out["derivedTier"] = t
        return out
    o = A.verify_record(obj, pinned)
    out = {"verdict": o["verdict"], "codes": code(o.get("failure"))}
    if o.get("derivedTier") is not None:
        out["derivedTier"] = o["derivedTier"]
    if "withinLimit" in o:
        out["withinLimit"] = o["withinLimit"]
    return out


def main():
    args = [a for a in sys.argv[1:] if a != "--json"]
    if len(args) != 2:
        print("usage: contract_adapter.py <tools_dir> <member file> --json", file=sys.stderr)
        return 2
    try:
        out = answer(args[0], args[1])
    except Exception as exc:  # reported, never turned into a verdict
        print("adapter could not answer: %s: %s" % (type(exc).__name__, exc), file=sys.stderr)
        return 2
    print(json.dumps(out, sort_keys=True))
    return {"valid": 0, "malformed": 1}.get(out["verdict"], 2)


if __name__ == "__main__":
    sys.exit(main())
