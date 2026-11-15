"""Adapter: map agent-audit-record corpus members to normalized Core-02 inputs and run both WEXP appraisers.

usage: wexp_aar_adapter.py <wexp-ref root> <wexp-check root> <vectors-agent-audit-record dir> [--reading tier|uniform]

Their method (WEXP-dev/wexp-interop docs/proposals/README.md and the scitt-receipt-boundary-001 MAPPING.md):
pinned bytes, a written mapping to the normalized input of draft-sergeev-wexp-core-02 section 6, expectations
derived from the Core text before any appraiser runs, then both appraisers (wexp_ref.core02 and wexp_check)
on the same input. The mapping is ours (profile `agent-evidence-matrix/wexp-aar-001/mapping-1`); the
expectations come from `oracle()`, a transcription of the section 8.4 algorithm and section 8.6 matrix
restricted to the input shapes this mapping emits. Neither appraiser is imported by the mapper or the oracle.

Per member the adapter prints: the corpus kind, our reader's verdict and the mapping stage, the asserted claim,
each appraiser's verdict, whether the two appraisers' full twenty-component results are equal, whether each equals
the oracle on the decisive components, and whether the Core verdict is consistent with the corpus expectation.
The appraisers run in separate interpreter processes with only their own code on the path (the run that IS the replay).
Revision 2 (after the first run of revision 1, whose record is run1.txt): Core-02 section 6.2 says a carrier parse failure
gives no Core result, and section 12 requires evaluation-scope consistency; revision 1 mapped parse failures to not-evaluated
findings and signature failures to an unsupported boundary beside "evaluated" scope values, and both appraisers rejected those
inputs with E_PROFILE_MAPPING_INVALID. Revision 2 gives parse failures no input and signature failures the supplied fatal
E_INTEGRITY_INVALID (section 6.2).
Exit 0 only when both appraisers agree with each other and with the oracle on every member, and every member is
consistent with the corpus expectation.
"""
import base64
import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile

from agent_evidence_vectors import auditrecord as ar

PROFILE = "agent-evidence-matrix/wexp-aar-001/mapping-1"
CTX = "C-aar-001"
TRUST = "wexp-aar-001-trust-1"
EVALUATED_AT = "2026-11-14T00:00:00Z"
CAPS = ["carrier-mapping", "authenticity", "target-binding", "boundary-grounding", "observation-support",
        "intent-support", "invocation-support", "execution-support", "provenance-support",
        "independent-verification", "composition", "counter-evidence"]
ORDER = {"observation": 0, "intent": 1, "invocation": 2, "execution": 3}
SET_FIELDS = {'qualifiers', 'profile_identifiers', 'basis_refs', 'reasons', 'limitations', 'base_findings',
              'qualifier_findings', 'recorder_relations', 'counter_evidence', 'evaluation_scope',
              'profile_evaluation_gaps', 'inherited_limitations', 'fatal_conditions', 'affected_claims',
              'fatal_reasons', 'substantive_reasons', 'evaluation_gaps', 'evaluation_gap_entries',
              'supported_claims', 'maximal_supported_claims', 'support_entries', 'support_relations'}
DECISIVE = ["verdict", "asserted_claim_supported", "supported_claims", "maximal_supported_claims",
            "support_relations", "support_entries", "boundary_ceiling", "boundary_grounding",
            "substantive_reasons", "evaluation_gaps", "inherited_limitations", "fatal_reasons"]
NOT_BOUND_CODES = {"request-digest-mismatch", "subject-request-mismatch"}


def enc(v):
    return json.dumps(v, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False)


def logical(v, f=None):
    if isinstance(v, dict):
        return {k: logical(x, k) for k, x in v.items()}
    if isinstance(v, list):
        items = [logical(x) for x in v]
        return sorted(items, key=enc) if f in SET_FIELDS else items
    return v


def same(a, b):
    return enc(logical(a)) == enc(logical(b))


def same_field(k, a, b):
    return same({k: a}, {k: b})


# ---------------------------------------------------------------- our reader and the mapping stage

def decode_predicate(raw):
    try:
        env = json.loads(raw)
        st = json.loads(base64.b64decode(env["payload"]))
        pred = st.get("predicate")
        return pred if isinstance(pred, dict) else None
    except Exception:
        return None


def stage_of(raw, policy, wrong_policy):
    """V valid; B signature did not verify; A failed before the signature was checked; C signature verified, a draft rule failed."""
    r = ar.verify(raw, policy)
    if r.verdict == "valid":
        return "V", r
    if r.codes == ["signature-invalid"]:
        return "B", r
    probe = ar.verify(raw, wrong_policy)
    return ("C" if probe.codes == ["signature-invalid"] else "A"), r


def asserted_claim_of(pred):
    """execution when the record reports effect.observed = occurred, otherwise observation (mapping rule M2)."""
    occurred = isinstance(pred, dict) and isinstance(pred.get("effect"), dict) and pred["effect"].get("observed") == "occurred"
    return {"base": "execution" if occurred else "observation", "qualifiers": []}


def ceiling_of(tier, reading):
    if reading == "uniform":
        return "execution"
    return "execution" if tier == "authoritative" else "observation"


def map_member(fid, raw, policy, wrong_policy, reading):
    """The normalized Core-02 input for one corpus member, with the mapping stage and reader report (rules M1 to M8 in MAPPING.md)."""
    stage, report = stage_of(raw, policy, wrong_policy)
    if stage == "A":
        return None, stage, report, "-"
    pred = decode_predicate(raw)
    claim = asserted_claim_of(pred)
    target = "wexp-interop:agent-audit-record-001:" + fid
    boundary_ref = [PROFILE, "envelope-" + fid]
    base_ref = [PROFILE, "predicate-" + fid]
    tier = report.derived_tier or "voluntary"
    if stage in "VC":
        boundary = {"status": "supported", "grounding": "attributed", "target_binding": "supported",
                    "ceiling_base": ceiling_of(tier, reading),
                    "limitations": [[PROFILE, "L-voluntary-self-vantage"]] if tier != "authoritative" else []}
    else:
        boundary = {"status": "unsupported", "grounding": "asserted-only", "target_binding": "unsupported", "limitations": []}
    boundary.update({"basis_refs": [boundary_ref], "evaluation_context_ref": CTX, "reasons": [], "target": target})
    if stage == "V":
        tb, sv = "supported", "supported"
    elif stage == "C":
        tb = "unsupported" if (report.codes and report.codes[0] in NOT_BOUND_CODES) else "supported"
        sv = "unsupported"
    else:
        tb, sv = "unsupported", "unsupported"
    bases = ["observation"] + (["execution"] if claim["base"] == "execution" else [])
    findings = [{"base": b, "basis_refs": [base_ref], "evaluation_context_ref": CTX, "limitations": [], "reasons": [],
                 "semantic_validation": sv, "target": target, "target_binding": tb} for b in bases]
    inp = {"asserted_claim": claim, "base_findings": findings, "boundary_finding": boundary,
           "counter_evidence": [{"affected_claims": [], "basis_refs": [], "limitations": [], "reasons": [], "status": "not-supplied"}],
           "evaluation_context": {"evaluated_at": EVALUATED_AT, "id": CTX, "profile_identifiers": [PROFILE], "trust_configuration": TRUST},
           "evaluation_scope": [{"capability": c, "status": "evaluated"} for c in CAPS],
           "fatal_conditions": ["E_INTEGRITY_INVALID"] if stage == "B" else [], "inherited_limitations": [], "profile_evaluation_gaps": [], "qualifier_findings": [],
           "recorder_relations": [], "semantics_version": "wexp-core-2", "target": target}
    return inp, stage, report, tier


# ---------------------------------------------------------------- the oracle (section 8.4 and 8.6, restricted)

def oracle(inp):
    """Expected decisive components from the Core-02 text alone; valid for inputs with no qualifiers, counter-evidence or profile gaps."""
    if inp["fatal_conditions"]:
        return {"verdict": "reject", "asserted_claim_supported": False, "supported_claims": [], "maximal_supported_claims": [],
                "support_relations": [], "support_entries": [], "boundary_ceiling": None, "boundary_grounding": None,
                "substantive_reasons": [], "evaluation_gaps": [], "inherited_limitations": None,
                "fatal_reasons": list(inp["fatal_conditions"])}
    bf, asserted, tgt = inp["boundary_finding"], inp["asserted_claim"], inp["target"]
    ctx = inp["evaluation_context"]["id"]
    usable = bf["status"] == "supported" and bf["target_binding"] == "supported" and bf["target"] == tgt and bf["evaluation_context_ref"] == ctx
    ceiling = bf.get("ceiling_base") if usable else None
    B = []
    for f in inp["base_findings"]:
        if (f["target"] == tgt and f["evaluation_context_ref"] == ctx and f["target_binding"] == "supported"
                and f["semantic_validation"] == "supported" and usable and ORDER[f["base"]] <= ORDER[ceiling]):
            B.append(f)
    claims = [{"base": f["base"], "qualifiers": []} for f in B]
    entries = [{"claim": {"base": f["base"], "qualifiers": []},
                "basis_refs": sorted(bf["basis_refs"] + f["basis_refs"], key=enc),
                "limitations": sorted(bf["limitations"] + f["limitations"], key=enc)} for f in B]
    maximal = [c for c in claims if not any(d != c and ORDER[d["base"]] >= ORDER[c["base"]] for d in claims)]

    def rel(c):
        if c == asserted:
            return "equal"
        return "support-below-claim" if ORDER[c["base"]] < ORDER[asserted["base"]] else "support-above-claim"
    reasons, gaps = set(), set()
    if bf["status"] == "unsupported":
        reasons.add("E_BOUNDARY_NOT_SUPPORTED")
    if bf["status"] == "not-evaluated":
        gaps.add("E_BOUNDARY_NOT_EVALUATED")
    if bf["target_binding"] == "unsupported":
        reasons.add("E_EVIDENCE_NOT_BOUND")
    if bf["target_binding"] == "not-evaluated":
        gaps.add("E_BOUNDARY_NOT_EVALUATED")
    af = [f for f in inp["base_findings"] if f["base"] == asserted["base"]]
    if usable and af and ORDER[asserted["base"]] > ORDER[ceiling]:
        reasons.add("E_BASE_EXCEEDS_BOUNDARY")
    if not af:
        reasons.add("E_MISSING_REQUIRED_EVIDENCE")
    for f in af:
        if f["target_binding"] == "unsupported":
            reasons.add("E_EVIDENCE_NOT_BOUND")
        if f["target_binding"] == "not-evaluated":
            gaps.add("E_BASE_NOT_EVALUATED")
        if f["semantic_validation"] == "unsupported":
            reasons.add("E_EXACT_CLAIM_NOT_SUPPORTED")
        if f["semantic_validation"] == "not-evaluated":
            gaps.add("E_BASE_NOT_EVALUATED")
    inherited = {enc(x): x for x in bf["limitations"] + [l for e in entries for l in e["limitations"]]}
    return {"verdict": "accept" if asserted in claims else "downgrade", "asserted_claim_supported": asserted in claims,
            "supported_claims": claims, "maximal_supported_claims": maximal,
            "support_relations": [{"supported_claim": c, "relation": rel(c)} for c in maximal],
            "support_entries": entries, "boundary_ceiling": ceiling, "boundary_grounding": bf["grounding"],
            "substantive_reasons": sorted(reasons), "evaluation_gaps": sorted(gaps),
            "inherited_limitations": list(inherited.values()), "fatal_reasons": []}


# ---------------------------------------------------------------- running the appraisers

DRIVER = r'''
import json, sys
mod, cases_path, prof_path = sys.argv[1:4]
if mod == 'wexp_check':
    from wexp_check import appraise
else:
    from wexp_ref.core02.appraiser import appraise
profiles = json.load(open(prof_path))
out = []
for case in json.load(open(cases_path)):
    try:
        out.append({"id": case["id"], "result": appraise(case["input"], profiles)})
    except Exception as exc:
        out.append({"id": case["id"], "error": type(exc).__name__ + ": " + str(exc)[:200]})
print(json.dumps(out))
'''


def run_appraiser(mod, path, cases, tmp):
    cpath, ppath = tmp / (mod + "-cases.json"), tmp / "profiles.json"
    cpath.write_text(json.dumps(cases))
    ppath.write_text(json.dumps({PROFILE: {"relation_tokens": [], "scope_names": [], "tokens": {}}}))
    r = subprocess.run([sys.executable, "-B", "-c", DRIVER, mod, str(cpath), str(ppath)],
                       env={"PYTHONPATH": str(path), "PATH": "/usr/bin:/bin"}, capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit(mod + " driver failed: " + r.stderr[-400:])
    return {row["id"]: row for row in json.loads(r.stdout)}


# ---------------------------------------------------------------- consistency with the corpus expectation (rules C1 to C4)

def consistent(kind, stage, tier, claim, verdict, supported, reading="tier"):
    """C1 corpus accept, authoritative or no execution claim: Core accept. C2 corpus accept, voluntary with an execution claim:
    Core downgrade to observation (vector A5: a voluntary record is not evidence of an independently observed fact).
    C3 corpus reject: Core never accepts and supports no claim. C4 indeterminate: judged by the reference reader's verdict
    (it is inside the member's listed readings), then C1 to C3."""
    if stage == "V":
        if reading == "uniform" or tier == "authoritative" or claim["base"] == "observation":
            return verdict == "accept"
        return verdict == "downgrade" and supported == [{"base": "observation", "qualifiers": []}]
    return verdict != "accept" and supported == []


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    reading = "tier"
    if "--reading" in sys.argv:
        reading = sys.argv[sys.argv.index("--reading") + 1]
        args = [a for a in args if a != reading]
    ref_root, chk_root, corpus = (pathlib.Path(a).resolve() for a in args[:3])
    manifest = json.loads((corpus / "MANIFEST.json").read_text())
    wrong = ar.Policy(manifest["predicateType"], manifest["keys"]["agent"]["publicKey"])
    members = []
    for entry in manifest["vectors"]:
        if not entry["file"].startswith("statements/"):
            continue
        raw = (corpus / entry["file"]).read_bytes()
        policy = ar.policy_for(manifest, entry)
        inp, stage, report, tier = map_member(entry["id"], raw, policy, wrong, reading)
        members.append((entry, inp, stage, report, tier))
    cases = [{"id": e["id"], "input": inp} for e, inp, _, _, _ in members if inp is not None]
    with tempfile.TemporaryDirectory() as tmp:
        res = {"wexp_ref": run_appraiser("wexp_ref", ref_root / "src", cases, pathlib.Path(tmp)),
               "wexp_check": run_appraiser("wexp_check", chk_root, cases, pathlib.Path(tmp))}
    tally = {"members": 0, "appraisers_equal": 0, "ref_eq_oracle": 0, "check_eq_oracle": 0, "consistent": 0}
    by = {}
    differ = []
    print("reading", reading, "corpus", manifest["corpusDigest"][:16], "members", len(members))
    for entry, inp, stage, report, tier in members:
        if inp is None:
            tally["members"] += 1
            tally["no_core_input"] = tally.get("no_core_input", 0) + 1
            nkey = (entry["kind"], stage, "-", "-", "no-core-result")
            by[nkey] = by.get(nkey, 0) + 1
            print(entry["draftId"], entry["kind"], "reader=" + report.verdict, report.codes[0],
                  "stage=A no Core input (section 6.2: an upstream parse failure gives no Core result)")
            continue
        a, b = res["wexp_ref"][entry["id"]], res["wexp_check"][entry["id"]]
        exp = oracle(inp)
        ok_ref = "result" in a and all(same_field(k, a["result"].get(k), exp[k]) for k in DECISIVE)
        ok_chk = "result" in b and all(same_field(k, b["result"].get(k), exp[k]) for k in DECISIVE)
        eq = "result" in a and "result" in b and same(a["result"], b["result"])
        va = a["result"]["verdict"] if "result" in a else "error"
        vb = b["result"]["verdict"] if "result" in b else "error"
        cons = consistent(entry["kind"], stage, tier, inp["asserted_claim"], va, a["result"]["supported_claims"] if "result" in a else None, reading)
        tally["members"] += 1
        tally["appraisers_equal"] += eq
        tally["ref_eq_oracle"] += ok_ref
        tally["check_eq_oracle"] += ok_chk
        tally["consistent"] += cons
        key = (entry["kind"], stage, tier if stage == "V" else "-", inp["asserted_claim"]["base"], va)
        by[key] = by.get(key, 0) + 1
        if not (eq and ok_ref and ok_chk and cons):
            differ.append(entry["draftId"])
        print(entry["draftId"], entry["kind"], "reader=" + report.verdict, "stage=" + stage, "tier=" + (tier if stage in "VC" else "-"),
              "asserted=" + inp["asserted_claim"]["base"], "ref=" + va, "check=" + vb, "appraisers_equal=" + str(eq).lower(),
              "ref_eq_oracle=" + str(ok_ref).lower(), "check_eq_oracle=" + str(ok_chk).lower(), "consistent=" + str(cons).lower())
    for key in sorted(by):
        print("CLASS kind=%s stage=%s tier=%s asserted=%s core=%s n=%d" % (key + (by[key],)))
    print("TALLY", json.dumps(tally, sort_keys=True))
    print("DIFFER", ",".join(differ) if differ else "none")
    # second angle: one signed byte flipped in a valid record, signature left as it was
    base = next(e for e in manifest["vectors"] if e["draftId"] == "A1")
    raw = (corpus / base["file"]).read_bytes()
    env = json.loads(raw)
    payload = base64.b64decode(env["payload"])
    digest = json.loads(payload)["predicate"]["decision"]["policyDigest"].encode()
    flipped = digest[:1].replace(digest[:1], b"4" if digest[:1] != b"4" else b"5") + digest[1:]
    env["payload"] = base64.b64encode(payload.replace(digest, flipped, 1)).decode()
    tampered = json.dumps(env).encode()
    policy = ar.policy_for(manifest, base)
    for label, data in (("A1", raw), ("A1-policyDigest-byte-flipped", tampered)):
        inp, stage, report, tier = map_member(label, data, policy, wrong, reading)
        with tempfile.TemporaryDirectory() as tmp:
            ra = run_appraiser("wexp_ref", ref_root / "src", [{"id": label, "input": inp}], pathlib.Path(tmp))[label]["result"]
            rb = run_appraiser("wexp_check", chk_root, [{"id": label, "input": inp}], pathlib.Path(tmp))[label]["result"]
        print("TAMPER", label, "reader=" + report.verdict, report.codes, "stage=" + stage, "ref=" + ra["verdict"], "check=" + rb["verdict"],
              "fatal=" + ",".join(ra["fatal_reasons"]) + " reasons=" + ",".join(ra["substantive_reasons"]) + ("" if not ra["evaluation_gaps"] else " gaps=" + ",".join(ra["evaluation_gaps"])),
              "equal=" + str(same(ra, rb)).lower())
    sys.exit(1 if differ else 0)


if __name__ == "__main__":
    main()
