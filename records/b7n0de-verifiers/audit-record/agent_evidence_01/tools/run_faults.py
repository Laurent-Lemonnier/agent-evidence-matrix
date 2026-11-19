# Copyright 2026 Konrad Gruszka
# Licensed under the Apache License, Version 2.0; see LICENSE.
"""Planted faults at every valid vector (expected valid AND own verdict valid).

Usage: python -I run_faults.py <tools_dir> <aar_corpus> <rer_corpus> <aar_result_dir> <fault_dir> <summary_file>
A throwaway test key is generated in memory and never written. It serves only to re-sign changed
statements, so that membership and recomputation behind the signature are exercised (control: the
unchanged statement re-signed must stay valid). One JSON file per case goes to <fault_dir>; the counts
per data type and fault kind go to <summary_file>.
"""
import base64
import copy
import hashlib
import importlib.util
import json
import os
import re
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def load(tools_dir, name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(tools_dir, name + ".py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def flip(h):
    return ("0" if h[0] != "0" else "1") + h[1:]


def run(tools_dir, akdir, rkdir, aar_results, odir, summary_file):
    A = load(tools_dir, "aar_verifier")
    R = load(tools_dir, "rer_verifier")
    os.makedirs(odir, exist_ok=True)

    TEST = Ed25519PrivateKey.generate()
    TEST_KID = "testkey-" + hashlib.sha256(TEST.public_key().public_bytes_raw()).hexdigest()[:16]
    PIN_TEST = {TEST_KID: TEST.public_key()}
    OTHER = Ed25519PrivateKey.generate().public_key()

    man = A.read_json(open(os.path.join(akdir, "MANIFEST.json"), "rb").read())
    OBS = man["keys"]["observer"]
    AG = man["keys"]["agent"]
    PIN = {OBS["keyid"]: Ed25519PublicKey.from_public_bytes(bytes.fromhex(OBS["publicKey"]))}
    PIN_OTHER = {OBS["keyid"]: OTHER}
    PIN_AGENT = {OBS["keyid"]: Ed25519PublicKey.from_public_bytes(bytes.fromhex(AG["publicKey"]))}
    TRUST = man["anchorTrust"]

    stats = {}
    rows = []

    def record(dtype, vid, fault, expect, got, detail=None):
        ok = (got == expect)
        rows.append({"data_type": dtype, "vector": vid, "fault": fault, "expected": expect, "own": got,
                     "ok": ok, "detail": detail})
        s = stats.setdefault(dtype, {}).setdefault(fault.split(":")[0], [0, 0])
        s[0 if ok else 1] += 1
        fn = "%s__%s__%s.json" % (dtype, vid, fault.replace(":", "_").replace("/", "_"))
        with open(os.path.join(odir, fn), "w") as f:
            json.dump(rows[-1], f, indent=1, sort_keys=True)

    def sign(st, key=TEST, kid=TEST_KID):
        body = A.jcs(st)
        sig = key.sign(A.pae(A.PAYLOAD_TYPE, body))
        return {"payload": base64.b64encode(body).decode(), "payloadType": A.PAYLOAD_TYPE,
                "signatures": [{"keyid": kid, "sig": base64.b64encode(sig).decode()}]}

    def v(e, pin=PIN):
        return A.verify_record(e, pin)["verdict"]

    def v_code(e, pin=PIN_TEST):
        out = A.verify_record(e, pin)
        return out["verdict"] + ":" + (out["failure"] or {}).get("code", "")

    def stage(e, pin=PIN_TEST):
        """Whether the signature held over the RFC 8785 bytes the verifier derives."""
        out = A.verify_record(e, pin)
        return "signature-invalid" if (out["failure"] or {}).get("code") == "signature-invalid" else "signature-held"

    def sign_bytes(body, key=TEST, kid=TEST_KID):
        sig = key.sign(A.pae(A.PAYLOAD_TYPE, body))
        return {"payload": base64.b64encode(body).decode(), "payloadType": A.PAYLOAD_TYPE,
                "signatures": [{"keyid": kid, "sig": base64.b64encode(sig).decode()}]}

    PROBE = "__probe__"
    # JSON profile faults: the probe text replaces one string member in the canonical bytes
    PROFILE_FAULTS = [("number-overflow", b"1e400"), ("number-underflow", b"1e-400"),
                      ("unsafe-integer", b"9007199254740992"), ("unsafe-integer-4301-digits", b"1" * 4301),
                      ("lone-surrogate", b'"\\ud800"'),
                      ("depth", b"[" * 127 + b"]" * 127)]
    TIME_FAULTS = [("out-of-range", "2026-99-99T99:99:99Z"), ("calendar", "2026-02-30T00:00:00Z"),
                   ("trailing-newline", "2026-01-01T00:00:00Z\n"), ("leap-second", "2026-01-01T12:00:60Z"),
                   ("no-leap-second", "2026-02-28T23:59:60Z"), ("after-list-expiry", "2027-06-30T23:59:60Z")]

    UTC_Z = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?Z")

    def respelled(st, zone):
        """The statement with every time of the predicate that ends in Z written with zone instead, the same
        instant under RFC 3339 4.3; returns the copy and the number of times changed."""
        s2 = copy.deepcopy(st)
        n = [0]

        def walk(o):
            items = o.items() if isinstance(o, dict) else enumerate(o) if isinstance(o, list) else ()
            for k, x in items:
                if isinstance(x, str) and UTC_Z.fullmatch(x):
                    o[k] = x[:-1] + zone
                    n[0] += 1
                else:
                    walk(x)
        walk(s2["predicate"])
        return s2, n[0]

    LONG = 4301  # one digit more than Python 3.11 converts with int() by default

    def zero_padded(st):
        """The statement with LONG zeros appended to the fraction of every time of the predicate that ends in
        Z, the same instant under RFC 3339 5.6; returns the copy and the number of times changed."""
        s2 = copy.deepcopy(st)
        n = [0]

        def walk(o):
            items = o.items() if isinstance(o, dict) else enumerate(o) if isinstance(o, list) else ()
            for k, x in items:
                if isinstance(x, str) and UTC_Z.fullmatch(x):
                    o[k] = x[:-1] + ("" if "." in x else ".") + "0" * LONG + "Z"
                    n[0] += 1
                else:
                    walk(x)
        walk(s2["predicate"])
        return s2, n[0]

    def probed(st, path, m):
        s2 = copy.deepcopy(st)
        o = s2
        for k in path[:-1]:
            o = o[k]
        o[path[-1]] = PROBE
        body = m.jcs(s2)
        assert body.count(b'"' + PROBE.encode() + b'"') == 1
        return body

    def aar_faults(vid, env):
        """One envelope."""
        st = A.read_json(base64.b64decode(env["payload"]))
        # 1 signature byte flipped
        e = copy.deepcopy(env)
        sb = bytearray(base64.b64decode(e["signatures"][0]["sig"]))
        sb[0] ^= 0x01
        e["signatures"][0]["sig"] = base64.b64encode(bytes(sb)).decode()
        record("aar", vid, "signature-byte", "malformed", v(e))
        # 2 signed field changed, signature kept
        for path in (("predicate", "recordId"), ("predicate", "decision", "reportedAt"),
                     ("predicate", "agreement")):
            s2 = copy.deepcopy(st)
            o = s2
            for k in path[:-1]:
                o = o[k]
            old = o[path[-1]]
            o[path[-1]] = (old + "x") if path[-1] != "agreement" else ("disagree" if old != "disagree" else "agree")
            e = dict(env, payload=base64.b64encode(A.jcs(s2)).decode())
            record("aar", vid, "field:" + ".".join(path[1:]), "malformed", v(e))
        # 2b payload bytes reformatted (same content, other bytes): the signature is over JCS, so it stays valid
        e = dict(env, payload=base64.b64encode(json.dumps(st, indent=2).encode()).decode())
        record("aar", vid, "control:reformatted", "valid", v(e))
        # 3 another pinned key
        record("aar", vid, "key:foreign", "malformed", v(env, PIN_OTHER))
        record("aar", vid, "key:agent", "malformed", v(env, PIN_AGENT))
        record("aar", vid, "key:empty", "malformed", v(env, {}))
        # control: unchanged, re-signed with the test key
        ctrl = v(sign(st), PIN_TEST)
        record("aar", vid, "control:re-signed", "valid", ctrl)
        if ctrl != "valid":
            return
        # 4 required member removed, re-signed
        for k in A.REQUIRED_17:
            s2 = copy.deepcopy(st)
            del s2["predicate"][k]
            record("aar", vid, "required:" + k, "malformed", v(sign(s2), PIN_TEST))
        for k in ("_type", "subject", "predicateType"):
            s2 = copy.deepcopy(st)
            del s2[k]
            record("aar", vid, "required:statement." + k, "malformed", v(sign(s2), PIN_TEST))
        for sub, key in (("decision", "requestDigest"), ("decision", "reported"), ("evaluation", "inputs"),
                         ("effect", "writes"), ("observation", "coverage"), ("agent", "id")):
            s2 = copy.deepcopy(st)
            del s2["predicate"][sub][key]
            record("aar", vid, "required:%s.%s" % (sub, key), "malformed", v(sign(s2), PIN_TEST))
        # 5 reference broken, re-signed
        s2 = copy.deepcopy(st)
        s2["subject"][0]["digest"]["sha256"] = flip(s2["subject"][0]["digest"]["sha256"])
        record("aar", vid, "reference:subject0-request", "malformed", v(sign(s2), PIN_TEST))
        s2 = copy.deepcopy(st)
        s2["predicate"]["decision"]["action"] += "x"
        record("aar", vid, "reference:action-requestDigest", "malformed", v(sign(s2), PIN_TEST))
        if len(st["subject"]) == 2:
            s2 = copy.deepcopy(st)
            s2["subject"][1]["digest"]["sha256"] = flip(s2["subject"][1]["digest"]["sha256"])
            record("aar", vid, "reference:subject1-afterRoot", "malformed", v(sign(s2), PIN_TEST))
            s2 = copy.deepcopy(st)
            iv = s2["predicate"]["effect"]["interval"]
            iv["beforeRoot"] = flip(iv["beforeRoot"])
            record("aar", vid, "reference:beforeRoot-chain", "malformed", v(sign(s2), PIN_TEST))
        pc = st["predicate"]["observation"].get("priorCommitment")
        if pc and "witnessNonce" in pc:
            s2 = copy.deepcopy(st)
            s2["predicate"]["observation"]["priorCommitment"]["witnessNonce"] = flip(pc["witnessNonce"])
            record("aar", vid, "reference:commitmentDigest", "malformed", v(sign(s2), PIN_TEST))
        if st["predicate"]["effect"]["writes"]:
            s2 = copy.deepcopy(st)
            w = s2["predicate"]["effect"]["writes"][0]
            w["postStateDigest"] = flip(w["postStateDigest"])
            record("aar", vid, "reference:write-postState", "malformed", v(sign(s2), PIN_TEST))
        # 6 JSON profile of 4.1, re-signed; the profile comes first (4.6), so the code names it
        body = probed(st, ("predicate", "recordId"), A)
        for name, lit in PROFILE_FAULTS:
            code = {"unsafe-integer": "unsafe-integer", "unsafe-integer-4301-digits": "unsafe-integer",
                    "depth": "nesting-too-deep"}.get(name, "not-i-json")
            e = sign_bytes(body.replace(b'"' + PROBE.encode() + b'"', lit))
            record("aar", vid, "profile:" + name, "malformed:" + code, v_code(e))
        e = sign_bytes(b'{"_type":"x",' + A.jcs(st)[1:])
        record("aar", vid, "profile:duplicate-member", "malformed:duplicate-member", v_code(e))
        e = sign_bytes(b'{"\\udc00":1,' + A.jcs(st)[1:])
        record("aar", vid, "profile:lone-surrogate-name", "malformed:not-i-json", v_code(e))
        # RFC 7493 2.1 through RFC 8785 3.1: noncharacters in a value and in a name
        e = sign_bytes(body.replace(b'"' + PROBE.encode() + b'"', b'"\\ufdd0"'))
        record("aar", vid, "profile:noncharacter", "malformed:not-i-json", v_code(e))
        e = sign_bytes(b'{"\\uffff":1,' + A.jcs(st)[1:])
        record("aar", vid, "profile:noncharacter-name", "malformed:not-i-json", v_code(e))
        # 7 RFC 3339 times of 4.3, re-signed
        for name, val in TIME_FAULTS:
            s2 = copy.deepcopy(st)
            s2["predicate"]["issuedAt"] = val
            record("aar", vid, "time:" + name, "malformed:timestamp-malformed", v_code(sign(s2)))
        # a leap second is its own instant: issued half a second before a sealedAt of 23:59:60 is earlier
        if st["predicate"]["effect"].get("interval"):
            s2 = copy.deepcopy(st)
            s2["predicate"]["effect"]["interval"]["sealedAt"] = "2016-12-31T23:59:60Z"
            s2["predicate"]["issuedAt"] = "2016-12-31T23:59:59.5Z"
            record("aar", vid, "time:leap-order", "malformed:issued-before-sealed", v_code(sign(s2)))
            # one nanosecond before the leap second and one before the midnight after it: distinct instants that
            # a binary float would merge with the sealedAt
            for name, issued, sealed in (
                    ("leap-order-ns-before-sixty", "2016-12-31T23:59:59.999999999Z", "2016-12-31T23:59:60Z"),
                    ("leap-order-ns-before-midnight", "2016-12-31T23:59:60.999999999Z", "2017-01-01T00:00:00Z"),
                    # a fraction longer than int() converts by default keeps its exact value (RFC 3339 5.6)
                    ("leap-order-4301-nines-before-sixty", "2016-12-31T23:59:59." + "9" * LONG + "Z",
                     "2016-12-31T23:59:60Z"),
                    ("leap-order-4301-nines-before-midnight", "2016-12-31T23:59:60." + "9" * LONG + "Z",
                     "2017-01-01T00:00:00Z")):
                s2 = copy.deepcopy(st)
                s2["predicate"]["effect"]["interval"]["sealedAt"] = sealed
                s2["predicate"]["issuedAt"] = issued
                record("aar", vid, "time:" + name, "malformed:issued-before-sealed", v_code(sign(s2)))
        # every Z time of the predicate written with +00:00 or -00:00 names the same instants (RFC 3339 4.3);
        # the verdict is that of the unchanged statement, re-signed
        base = v_code(sign(st))
        for name, zone in (("utc-offset-plus", "+00:00"), ("utc-offset-minus", "-00:00")):
            s2, n = respelled(st, zone)
            if n:
                record("aar", vid, "time:" + name, base, v_code(sign(s2)), {"times": n})
        s2, n = zero_padded(st)
        if n:
            record("aar", vid, "time:fraction-4301-zeros", base, v_code(sign(s2)), {"times": n})
        # 8 RFC 8785 numbers: signed over the ECMAScript form the signature holds, over another form it fails
        body = probed(st, ("predicate", "recordId"), A)
        for name, lit, exp in (("number-ecmascript-form", b"1e-7", "signature-held"),
                               ("number-other-form", b"1e-07", "signature-invalid")):
            e = sign_bytes(body.replace(b'"' + PROBE.encode() + b'"', lit))
            record("aar", vid, "jcs:" + name, exp, stage(e))

    def retained_root_faults(vid, obj):
        """4.6 and 4.7 (reading L-ROOTMAT): an unused number added to the delegation-root key set, rootDigest
        and envelopeDigest recomputed and the statement re-signed with the test key. The material is read
        under the profile of 4.1, so a number of LONG digits, with or without a sign, makes the material
        unreadable and the root not established, whatever limit the interpreter sets on int(); the control
        re-signs the unchanged material and keeps the root established."""
        for name, lit, expect in (("delegation-root-re-signed", None, "well-formed:established"),
                                  ("delegation-root-number-4301-digits", b"1" * LONG,
                                   "malformed:entry-delegation-root-unreadable"),
                                  ("delegation-root-signed-number-4301-digits", b"-" + b"1" * LONG,
                                   "malformed:entry-delegation-root-unreadable")):
            o2 = copy.deepcopy(obj)
            ent = o2["retention"]
            dr = [x for x in ent["validationData"] if isinstance(x, dict) and x.get("for") == "delegation-root"][0]
            mat = base64.b64decode(dr["value"]).rstrip()
            if lit is not None:
                mat = mat[:-1] + b',"plantedNumber":' + lit + b"}"
            dr["value"] = base64.b64encode(mat).decode()
            st = A.read_json(base64.b64decode(o2["envelope"]["payload"]))
            H = A.hfun(st["predicate"].get("hashAlgorithm", "sha256"))
            st["predicate"]["delegation"]["rootDigest"] = H(mat)
            o2["envelope"] = sign(st)
            ent["envelopeDigest"] = H(A.jcs(o2["envelope"]))
            _rec, dat = A.check_retained(o2, PIN_TEST, TRUST)
            got = dat["entry"] + ":" + (dat["delegationRoot"]["result"] if dat["entry"] == "well-formed"
                                        else (dat["failure"] or {}).get("code", ""))
            record("aar", vid, "retained:" + name, expect, got)

    # ---------------- agent-audit-record
    own_aar = {}
    for f in os.listdir(aar_results):
        if f.startswith("_"):
            continue
        r = A.read_json(open(os.path.join(aar_results, f), "rb").read())
        own_aar[r["draftId"]] = r
    for vec in man["vectors"]:
        r = own_aar[vec["draftId"]]
        if vec["expected"].get("verdict") != "valid" or r["own"]["verdict"] != "valid":
            continue
        obj = A.read_json(open(os.path.join(akdir, vec["file"]), "rb").read())
        top = vec["file"].split("/")[0]
        vid = vec["draftId"]
        if top == "statements":
            aar_faults(vid, obj)
        elif top == "retained":
            aar_faults(vid, obj["envelope"])
            if vec["expected"]["dating"]["entry"] == "well-formed":
                o2 = copy.deepcopy(obj)
                o2["retention"]["envelopeDigest"] = flip(o2["retention"]["envelopeDigest"])
                _rec, dat = A.check_retained(o2, PIN, TRUST)
                record("aar", vid, "reference:retention-envelopeDigest", "malformed", dat["entry"])
                if obj["retention"]["anchors"] and vec["expected"]["dating"].get("datedAt"):
                    o2 = copy.deepcopy(obj)
                    pb = bytearray(base64.b64decode(o2["retention"]["anchors"][-1]["proof"]))
                    pb[-1] ^= 0x01
                    o2["retention"]["anchors"][-1]["proof"] = base64.b64encode(bytes(pb)).decode()
                    _rec, dat = A.check_retained(o2, PIN, TRUST)
                    _r0, dat0 = A.check_retained(obj, PIN, TRUST)
                    # datedAt compared as an instant, so another spelling of the same time is no change
                    same_time = (dat["datedAt"] is None) == (dat0["datedAt"] is None) and (
                        dat["datedAt"] is None or A.t(dat["datedAt"], "after") == A.t(dat0["datedAt"], "before"))
                    changed = not same_time or (dat["entry"] != dat0["entry"]) or \
                        (dat.get("receipt") != dat0.get("receipt"))
                    record("aar", vid, "reference:anchor-proof-last-byte", "changed",
                           "changed" if changed else "unchanged",
                           {"before": dat0["datedAt"], "after": dat["datedAt"], "entryAfter": dat["entry"]})
            if vec["expected"]["dating"].get("delegationRoot", {}).get("result") == "established":
                retained_root_faults(vid, obj)
        elif top == "sets":
            aar_faults(vid + "-rec0", obj["records"][0])

    # ---------------- restoration-evidence
    rman = R.parse(open(os.path.join(rkdir, "MANIFEST.json"), "rb").read())
    REQ = {
        "incident-action-authorization": R.COMMON + ["action", "parties", "authorizedAt", "notAfter",
                                                     "intentBinding"],
        "revocation-sweep": R.COMMON + ["predecessors", "population", "partition", "revocations", "coverage"],
        "re-enable-decision": R.COMMON + ["predecessors", "restoration", "approvers", "setSufficiency",
                                          "evidence"],
        "joint-authority": R.COMMON + ["sharedIndicators", "parties"],
        "revocation-boundary": R.COMMON + ["sink", "observer", "revocation", "window", "counts", "exclusions",
                                           "result"],
    }

    def rer_env_faults(vid, st):
        body = R.jcs(st)
        env = {"payload": base64.b64encode(body).decode(), "payloadType": R.PAYLOAD_TYPE,
               "signatures": [{"keyid": TEST_KID,
                               "sig": base64.b64encode(TEST.sign(R.pae(R.PAYLOAD_TYPE, body))).decode()}]}

        def ver(e, pin):
            try:
                raw, s = R.open_envelope(e, pin)
                return R.check_record_bytes(raw)["verdict"]
            except R.Rej:
                return "reject"
        record("rer", vid, "control:dsse-re-signed", "accept", ver(env, PIN_TEST))
        e = copy.deepcopy(env)
        sb = bytearray(base64.b64decode(e["signatures"][0]["sig"]))
        sb[0] ^= 0x01
        e["signatures"][0]["sig"] = base64.b64encode(bytes(sb)).decode()
        record("rer", vid, "signature-byte", "reject", ver(e, PIN_TEST))
        s2 = copy.deepcopy(st)
        s2["predicate"]["issuedAt"] = s2["predicate"]["issuedAt"].replace("Z", "Z")[:-3] + "59Z" \
            if not s2["predicate"]["issuedAt"].endswith("59Z") else s2["predicate"]["issuedAt"][:-3] + "58Z"
        e = dict(env, payload=base64.b64encode(R.jcs(s2)).decode())
        record("rer", vid, "field:issuedAt", "reject", ver(e, PIN_TEST))
        record("rer", vid, "key:foreign", "reject", ver(env, {TEST_KID: OTHER}))

        def rer_stage(body):
            e = {"payload": base64.b64encode(body).decode(), "payloadType": R.PAYLOAD_TYPE,
                 "signatures": [{"keyid": TEST_KID,
                                 "sig": base64.b64encode(TEST.sign(R.pae(R.PAYLOAD_TYPE, body))).decode()}]}
            try:
                R.open_envelope(e, PIN_TEST)
                return "signature-held"
            except R.Rej as r:
                return "signature-invalid" if r.code == "signature-invalid" else "reject:" + r.code
        pb = probed(st, ("predicate", "incident"), R)
        for name, lit, exp in (("number-ecmascript-form", b"1e-7", "signature-held"),
                               ("number-other-form", b"1e-07", "signature-invalid")):
            record("rer", vid, "jcs:" + name, exp, rer_stage(pb.replace(b'"' + PROBE.encode() + b'"', lit)))

    def rer_record_faults(vid, st):
        """JSON profile and times of 4.1 on the statement bytes."""
        def got(raw):
            r = R.check_record_bytes(raw)
            return r["verdict"] + ":" + r["reason"]
        pb = probed(st, ("predicate", "incident"), R)
        for name, lit in PROFILE_FAULTS + [("noncharacter", b'"\\ufdd0"')]:
            record("rer", vid, "profile:" + name, "reject:statement-malformed",
                   got(pb.replace(b'"' + PROBE.encode() + b'"', lit)))
        record("rer", vid, "profile:duplicate-member", "reject:statement-malformed",
               got(b'{"_type":"x",' + R.jcs(st)[1:]))
        record("rer", vid, "profile:lone-surrogate-name", "reject:statement-malformed",
               got(b'{"\\udc00":1,' + R.jcs(st)[1:]))
        record("rer", vid, "profile:noncharacter-name", "reject:statement-malformed",
               got(b'{"\\uffff":1,' + R.jcs(st)[1:]))
        for name, val in TIME_FAULTS:
            s2 = copy.deepcopy(st)
            s2["predicate"]["issuedAt"] = val
            record("rer", vid, "time:" + name, "reject:predicate-malformed", got(R.jcs(s2)))
        # 4.1 "to whole seconds": a fraction is refused at any length, also one longer than int() converts
        s2 = copy.deepcopy(st)
        s2["predicate"]["issuedAt"] = s2["predicate"]["issuedAt"][:-1] + "." + "0" * (LONG - 1) + "1Z"
        record("rer", vid, "time:fraction-4301-digits", "reject:predicate-malformed", got(R.jcs(s2)))
        # restoration-evidence-00 4.1 "UTC times": "+00:00" and "-00:00" name UTC as "Z" does (RFC 3339 4.3),
        # so the verdict and the reason stay those of the unchanged statement
        base = got(R.jcs(st))
        for name, zone in (("utc-offset-plus", "+00:00"), ("utc-offset-minus", "-00:00")):
            s2, n = respelled(st, zone)
            if n:
                record("rer", vid, "time:" + name, base, got(R.jcs(s2)), {"times": n})

    for vec in rman["vectors"]:
        if vec["expected"]["verdict"] != "accept":
            continue
        d = os.path.join(rkdir, vec["path"])
        files = sorted(vec["files"])
        if vec["shape"] == "record":
            raw = open(os.path.join(d, files[0]), "rb").read()
            if R.check_record_bytes(raw)["verdict"] != "accept":
                continue
            st = R.parse(raw)
            name = st["predicateType"].rsplit("/", 1)[1]
            rer_env_faults(vec["id"], st)
            rer_record_faults(vec["id"], st)
            for k in REQ[name]:
                s2 = copy.deepcopy(st)
                del s2["predicate"][k]
                record("rer", vec["id"], "required:" + k, "reject", R.check_record_bytes(R.jcs(s2))["verdict"])
            for k in ("_type", "subject", "predicateType"):
                s2 = copy.deepcopy(st)
                del s2[k]
                record("rer", vec["id"], "required:statement." + k, "reject",
                       R.check_record_bytes(R.jcs(s2))["verdict"])
        else:
            items = [(fn, open(os.path.join(d, fn), "rb").read()) for fn in files]
            if R.check_bundle(items)["verdict"] != "accept":
                continue
            # reference: predecessor digest flipped
            for i, (fn, raw) in enumerate(items):
                st = R.parse(raw)
                if st["predicate"].get("predecessors"):
                    s2 = copy.deepcopy(st)
                    h = s2["predicate"]["predecessors"][0]["digest"]["sha256"]
                    s2["predicate"]["predecessors"][0]["digest"]["sha256"] = flip(h)
                    it2 = list(items)
                    it2[i] = (fn, json.dumps(s2).encode())
                    record("rer", vec["id"], "reference:predecessor-digest:" + fn, "reject",
                           R.check_bundle(it2)["verdict"], R.check_bundle(it2))
            # reference: content of a predecessor changed, so its digest moves
            named = set()
            for fn, raw in items:
                for pr in R.parse(raw)["predicate"].get("predecessors", []):
                    named.add(pr["digest"]["sha256"])
            for i, (fn, raw) in enumerate(items):
                if hashlib.sha256(raw).hexdigest() in named:
                    st = R.parse(raw)
                    st["predicate"]["doesNotAssert"] = st["predicate"]["doesNotAssert"] + ["planted change"]
                    it2 = list(items)
                    it2[i] = (fn, json.dumps(st).encode())
                    record("rer", vec["id"], "reference:predecessor-content:" + fn, "reject",
                           R.check_bundle(it2)["verdict"], R.check_bundle(it2))
            # required member removed in the R3
            for i, (fn, raw) in enumerate(items):
                st = R.parse(raw)
                if st["predicateType"].endswith("re-enable-decision"):
                    for k in ("evidence", "approvers", "incident"):
                        s2 = copy.deepcopy(st)
                        del s2["predicate"][k]
                        it2 = list(items)
                        it2[i] = (fn, json.dumps(s2).encode())
                        record("rer", vec["id"], "required:r3." + k, "reject", R.check_bundle(it2)["verdict"])
                    rer_env_faults(vec["id"] + "-" + fn, st)

    tot = len(rows)
    bad = [r for r in rows if not r["ok"]]
    print("planted cases in total %d, as expected %d, deviating %d" % (tot, tot - len(bad), len(bad)))
    print(json.dumps(stats, sort_keys=True))
    print("throwaway test key of this run, held in memory only:", TEST_KID)
    for r in bad[:40]:
        print("DEVIATION", r["data_type"], r["vector"], r["fault"], "expected", r["expected"], "own", r["own"],
              r.get("detail"))
    with open(summary_file, "w") as f:
        json.dump({"total": tot, "deviating": len(bad), "by_kind": stats,
                   "note": "counts per data type and fault kind as [as expected, deviating]; the test key "
                           "exists only in memory during the run and is not recorded here"},
                  f, indent=1, sort_keys=True)
    return rows


if __name__ == "__main__":
    run(*sys.argv[1:7])
