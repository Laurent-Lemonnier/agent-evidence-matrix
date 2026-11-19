# Copyright 2026 Konrad Gruszka
# Licensed under the Apache License, Version 2.0; see LICENSE.
"""Clean-room verifier for revision 03 of the agent audit record draft.

Written from the text of the draft alone (sha256 c5d0b74686b62b5d1fd954b2dae0cf02b402c87a06efa6fc82abf8fa847ed786).
Every check names the section of the draft it rests on. Pinned keys and anchor trust are input from
the caller, never taken from the record.

Result per record: verdict in {valid, malformed, no-verdict}, failure = (code, section, text),
derivedTier, and withinLimit per consumption entry.
"""
import base64
import datetime as _dt
import hashlib
import json
import math
import re
import importlib.util
import os

def _sibling(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                                     name + ".py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


LEAP = _sibling("leap_seconds")  # pinned leap-seconds.list, RFC 3339 5.7 (reading L-LEAP)

PT_V1 = "https://probityai.github.io/agent-evidence-vectors/predicate/v1/agent-audit-record"  # 4
PT_V2 = "https://probityai.github.io/agent-evidence-vectors/predicate/v2/agent-audit-record"  # 8
PAYLOAD_TYPE = "application/vnd.in-toto+json"  # 4.4
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"  # 4, [IN-TOTO] (reading L-STYPE)
SKEW = 300  # 3 Skew tolerance
OTS_TOL = 7200  # 4.7.2
EMPTY_TREE = {"sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}  # 5.3
MAX_DEPTH = 128  # 4.1.2
SAFE_INT = 2 ** 53  # 4.1.1

REQUIRED_17 = [  # 4 and the example in 5
    "recordId", "tier", "hashAlgorithm", "agent", "delegation", "resource", "decision",
    "evaluation", "effect", "agreement", "correlation", "posture", "remediation",
    "observation", "fieldEvidence", "doesNotAssert", "issuedAt",
]
OPTIONAL_2 = ["oversight", "sequence"]  # 4, 5.5, 5.10

V_AUTH = {"wimse-wpt", "http-message-signature", "mtls", "oauth-access-token", "api-key", "none"}  # 5.2
V_SUBJKIND = {"user", "system", "none"}  # 5.2
V_RKIND = {"path", "uri", "tool"}  # 5.2
V_BINDING = {"digest-bound", "not-bindable"}  # 5.2
V_REPORTED = {"permit", "deny", "permit-with-conditions"}  # 5.3
V_OBSERVED = {"occurred", "none", "unknown"}  # 5.3
V_AGREEMENT = {"agree", "disagree", "not-exercised", "indeterminate", "one-sided"}  # 5.3
V_STATUS = {"evaluated", "not-evaluated"}  # 5.4
V_INPUT_V1 = {"standing-source", "key-source", "consumption-state", "policy-source"}  # 5.4, 8
V_INPUT_V2 = V_INPUT_V1 | {"principal-standing-source"}  # 5.4 table 3, 8
V_ACT = {"observation", "check", "decision", "release"}  # 5.5
V_SCOPE = {"producer", "cross-party"}  # 5.6
V_TIMEBASIS = {"beacon-anchored", "asserted"}  # 5.6 (reading L-TB)
V_ANCHOR = {"rfc3161", "transparency-log", "opentimestamps"}  # 5.6
V_POSTURE = {"no_network", "allowlist", "sinkhole", "unsafe_bypass_egress"}  # 5.6
V_CAUSE = {"session-revoked", "risk-elevated", "subject-disabled", "token-replay-suspected",
           "policy-changed", "operator-action"}  # 5.6
V_ENFORCEMENT = {"access-attenuated", "session-terminated", "tokens-discarded",
                 "privileges-reduced", "reevaluated", "not-enforced"}  # 5.6
V_VANTAGE = {"below-observed", "peer", "self"}  # 5.7
V_FE = {"substrate-covered", "producer-asserted"}  # 5.7 table 4
FE_KEYS = {"agent", "delegation", "resource", "decision", "correlation", "posture", "remediation"}  # 4.5, 5.7
V_TIER = {"voluntary", "authoritative"}  # 5.7
V_ORIGIN = {"retainer", "received"}  # 4.7
GLOB_CHARS = set("*?[]{}")  # 5.3 (reading L-GLOB)

HEX = {"sha256": re.compile(r"^[0-9a-f]{64}$")}
RFC3339 = re.compile(  # applied with fullmatch, ASCII digits only
    r"([0-9]{4})-([0-9]{2})-([0-9]{2})[Tt]([0-9]{2}):([0-9]{2}):([0-9]{2})(\.[0-9]+)?([Zz]|[+-][0-9]{2}:[0-9]{2})")


class Fail(Exception):
    def __init__(self, code, section, text=""):
        super().__init__(code)
        self.code, self.section, self.text = code, section, text


class NoVerdict(Exception):
    pass


# ---------------------------------------------------------------- JSON profile, 4.1
def _no_dupes(pairs):
    seen = set()
    for k, _ in pairs:
        if k in seen:
            raise Fail("duplicate-member", "4.1.2", "member name repeated: %r" % k)
        seen.add(k)
    return dict(pairs)


def _bad_const(name):
    raise Fail("not-i-json", "4.1.1", "non-finite number %s" % name)


def _int(s):
    # 2^53 has 16 digits and JSON allows no leading zero (RFC 8259 6), so a longer literal is unsafe; it is
    # refused by its length before int(), which converts at most 16 digits here and so stays below every
    # limit on integer string conversion the interpreter allows (640 digits at the least)
    if len(s.lstrip("-")) > 16:
        raise Fail("unsafe-integer", "4.1.1", "integer magnitude >= 2^53")
    v = int(s)
    if abs(v) >= SAFE_INT:
        raise Fail("unsafe-integer", "4.1.1", "integer magnitude >= 2^53")
    return v


def _float(s):
    v = float(s)
    if math.isinf(v) or math.isnan(v):
        raise Fail("not-i-json", "4.1.1", "number not representable as IEEE double")
    if v == 0 and any(c in "123456789" for c in s.lower().split("e")[0]):
        raise Fail("not-i-json", "4.1.1", "non-zero number underflows IEEE double")
    if v == int(v) and abs(v) >= SAFE_INT:
        raise Fail("unsafe-integer", "4.1.1", "integral number magnitude >= 2^53")
    return v


def _walk_depth(o, d=1):
    if d > MAX_DEPTH and isinstance(o, (dict, list)):
        raise Fail("nesting-too-deep", "4.1.2", "nesting deeper than 128")
    if isinstance(o, dict):
        for v in o.values():
            _walk_depth(v, d + 1)
    elif isinstance(o, list):
        for v in o:
            _walk_depth(v, d + 1)
    elif isinstance(o, str):
        if any(_bad_char(ord(c)) for c in o):
            raise Fail("not-i-json", "4.1.1", "string not I-JSON (surrogate or noncharacter, RFC 7493 2.1)")


def _bad_char(o):
    # RFC 8785 3.1 and 5 make the input I-JSON; RFC 7493 2.1 bars surrogate code points and noncharacters
    # (U+FDD0..U+FDEF and the last two code points of each plane) from names and string values
    return 0xD800 <= o <= 0xDFFF or 0xFDD0 <= o <= 0xFDEF or (o & 0xFFFE) == 0xFFFE


def _walk_keys(o):
    if isinstance(o, dict):
        for k, v in o.items():
            if any(_bad_char(ord(c)) for c in k):
                raise Fail("not-i-json", "4.1.1", "member name not I-JSON (surrogate or noncharacter)")
            _walk_keys(v)
    elif isinstance(o, list):
        for v in o:
            _walk_keys(v)


def parse_profile(raw: bytes):
    """4.1 and the first step of 4.6: the profile is enforced while parsing."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise Fail("not-parseable", "4.6", "payload not UTF-8")
    # Rough depth check first, so that the parser does not fail on recursion
    depth = maxd = 0
    in_str = esc = False
    for ch in text:
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
        elif ch in "[{":
            depth += 1
            maxd = max(maxd, depth)
        elif ch in "]}":
            depth -= 1
    if maxd > MAX_DEPTH:
        raise Fail("nesting-too-deep", "4.1.2", "nesting deeper than 128")
    try:
        obj = json.loads(text, object_pairs_hook=_no_dupes, parse_constant=_bad_const,
                         parse_int=_int, parse_float=_float)
    except Fail:
        raise
    except (ValueError, RecursionError) as e:
        raise Fail("not-parseable", "4.6", "payload is not JSON: %s" % str(e)[:80])
    _walk_depth(obj)
    _walk_keys(obj)
    return obj


# ---------------------------------------------------------------- RFC 8785 JCS, 4.1.1
def _jcs_str(s):
    out = ['"']
    for c in s:
        o = ord(c)
        if c == '"':
            out.append('\\"')
        elif c == "\\":
            out.append("\\\\")
        elif c == "\b":
            out.append("\\b")
        elif c == "\t":
            out.append("\\t")
        elif c == "\n":
            out.append("\\n")
        elif c == "\f":
            out.append("\\f")
        elif c == "\r":
            out.append("\\r")
        elif o < 0x20:
            out.append("\\u%04x" % o)
        else:
            out.append(c)
    out.append('"')
    return "".join(out)


def _jcs_num(v):
    if isinstance(v, bool):
        raise TypeError
    if isinstance(v, int):
        return str(v)
    if v == 0:
        return "0"
    if v == int(v) and abs(v) < 2 ** 53:  # exact, and the shortest digits too
        return str(int(v))
    # ECMAScript Number::toString from the shortest representation
    r = repr(v)
    sign = "-" if v < 0 else ""
    r = r.lstrip("-")
    if "e" in r or "E" in r:
        mant, exp = r.lower().split("e")
        exp = int(exp)
    else:
        mant, exp = r, 0
    if "." in mant:
        ip, fp = mant.split(".")
    else:
        ip, fp = mant, ""
    digits = (ip + fp).lstrip("0")
    lead_zeros = len(ip + fp) - len((ip + fp).lstrip("0"))
    n = len(ip) + exp - lead_zeros  # position of the decimal point relative to digits
    digits = digits.rstrip("0") or "0"
    k = len(digits)
    if k <= n <= 21:
        s = digits + "0" * (n - k)
    elif 0 < n <= 21:
        s = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        s = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        es = ("+" if e >= 0 else "-") + str(abs(e))
        s = digits[0] + ("." + digits[1:] if k > 1 else "") + "e" + es
    return sign + s


def jcs(o) -> bytes:
    def enc(x):
        if x is None:
            return "null"
        if x is True:
            return "true"
        if x is False:
            return "false"
        if isinstance(x, (int, float)):
            return _jcs_num(x)
        if isinstance(x, str):
            return _jcs_str(x)
        if isinstance(x, list):
            return "[" + ",".join(enc(i) for i in x) + "]"
        if isinstance(x, dict):
            ks = sorted(x.keys(), key=lambda s: s.encode("utf-16-be"))
            return "{" + ",".join(_jcs_str(k) + ":" + enc(x[k]) for k in ks) + "}"
        raise TypeError(type(x))
    return enc(o).encode("utf-8")


def pae(payload_type: str, body: bytes) -> bytes:  # 4.4
    t = payload_type.encode("utf-8")
    return b"DSSEv1 " + str(len(t)).encode() + b" " + t + b" " + str(len(body)).encode() + b" " + body


# ---------------------------------------------------------------- Helpers
def b64d(s):
    if not isinstance(s, str):
        raise ValueError("not a string")
    try:
        return base64.b64decode(s, validate=True)
    except Exception:
        return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def t(v, where, allow_none=False):
    """4.3: RFC 3339 date-time."""
    if allow_none and v == "none":
        return None
    if not isinstance(v, str):
        raise Fail("timestamp-malformed", "4.3", "%s is not a string" % where)
    m = RFC3339.fullmatch(v)
    if not m:
        raise Fail("timestamp-malformed", "4.3", "%s not RFC 3339: %r" % (where, v))
    y, mo, d, hh, mm, ss, frac, off = m.groups()
    try:
        if off in ("Z", "z"):
            shift = 0
        else:
            oh, om = int(off[1:3]), int(off[4:6])
            if oh > 23 or om > 59:  # RFC 3339 5.6 time-numoffset
                raise ValueError(off)
            shift = (1 if off[0] == "+" else -1) * (oh * 3600 + om * 60)
        yy, mo_, dd, h_, mi_, sec = (int(g) for g in (y, mo, d, hh, mm, ss))
        # RFC 3339 5.6 and 5.7: the day exists in its month and year, hour 00-23, minute 00-59
        if not LEAP.date_exists(yy, mo_, dd) or h_ > 23 or mi_ > 59 or sec > 60:
            raise ValueError(v)
        p = LEAP.posix(yy, mo_, dd, h_, mi_, 59 if sec == 60 else sec) - shift
        last = (p + 1) % 86400 == 0  # 23:59:59 UTC, so p + 1 is a UTC midnight
        if sec == 60:
            # RFC 3339 5.7: 60 only where a leap second occurs, the point shifted by the zone offset; the
            # pinned list says where, and refuses what it cannot confirm (reading L-LEAP)
            if not (last and LEAP.covered(p + 1) and LEAP.inserted(p + 1)):
                raise ValueError(v)
        elif last and LEAP.removed(p + 1):
            raise ValueError(v)  # RFC 3339 5.7: after a subtracted leap second the maximum is 58
    except ValueError:
        raise Fail("timestamp-malformed", "4.3", "%s invalid date-time %r" % (where, v))
    # The exact instant as a Fraction of elapsed seconds on the UTC scale: a second 60 is its own instant
    # after 23:59:59 and before the midnight, differences count the leap seconds between two times, and
    # the fraction is decimal, so 23:59:59.999999999 stays before 23:59:60 (reading L-LEAP). Every spelling
    # of one instant (offset, "Z" or "+00:00", case, trailing zeros) gives the same value.
    return LEAP.instant(p, sec == 60, frac[1:] if frac else "")


def need(obj, key, where, sect):
    if not isinstance(obj, dict) or key not in obj:
        raise Fail("member-missing", sect, "%s.%s absent" % (where, key))
    return obj[key]


def closed(v, vocab, where, sect):
    if not isinstance(v, str) or v not in vocab:
        raise Fail("value-outside-vocabulary", sect, "%s=%r outside closed set" % (where, v))
    return v


def hexd(v, alg, where, sect="1"):
    rx = HEX.get(alg)
    if rx is None or not isinstance(v, str) or not rx.match(v):
        raise Fail("digest-malformed", sect, "%s is not lowercase hex under %s" % (where, alg))
    return v


def is_str(v, where, sect, nonempty=False):
    if not isinstance(v, str) or (nonempty and v == ""):
        raise Fail("member-malformed", sect, "%s not a %sstring" % (where, "non-empty " if nonempty else ""))
    return v


def is_nonneg_int(v):
    return isinstance(v, int) and not isinstance(v, bool) and v >= 0


def under_scope(path, scope):
    """5.3/5.7: whether path lies under a member of pathScope (reading L-UNDER)."""
    for s in scope:
        if s == "/":
            return True
        if path == s:
            return True
        pre = s if s.endswith("/") else s + "/"
        if path.startswith(pre):
            return True
    return False


def hfun(alg):
    if alg == "sha256":
        return lambda b: hashlib.sha256(b).hexdigest()
    raise NoVerdict(alg)


# ---------------------------------------------------------------- Envelope and signature, 4.4, 4.6
def verify_envelope(env, pinned):
    """pinned: dict keyid -> cryptography Ed25519PublicKey (the caller's trust)."""
    from cryptography.exceptions import InvalidSignature
    if not isinstance(env, dict):
        raise Fail("envelope-unreadable", "4.4", "envelope not an object")
    for k in ("payload", "payloadType", "signatures"):
        if k not in env:
            raise Fail("envelope-unreadable", "4.4", "envelope.%s absent" % k)
    if env["payloadType"] != PAYLOAD_TYPE:
        raise Fail("envelope-unreadable", "4.4", "payloadType is not %s" % PAYLOAD_TYPE)
    try:
        raw = b64d(env["payload"])
    except Exception:
        raise Fail("envelope-unreadable", "4.4", "payload not base64")
    st = parse_profile(raw)  # 4.6 step 1
    canon = jcs(st)  # 4.1.1
    msg = pae(PAYLOAD_TYPE, canon)
    sigs = env["signatures"]
    if not isinstance(sigs, list) or not sigs:
        raise Fail("signature-invalid", "4.6", "no signature")
    ok_keys = []
    for s in sigs:
        if not isinstance(s, dict):
            continue
        kid = s.get("keyid")
        cands = [(kid, pinned[kid])] if kid in pinned else ([] if kid else list(pinned.items()))
        try:
            sig = b64d(s.get("sig"))
        except Exception:
            continue
        for k, pk in cands:
            try:
                pk.verify(sig, msg)
                ok_keys.append(k)
            except (InvalidSignature, ValueError):
                pass
    if not ok_keys:
        raise Fail("signature-invalid", "4.6",
                   "no signature verifies under a pinned key over the RFC 8785 bytes")
    return st, raw, ok_keys


# ---------------------------------------------------------------- Record
def check_statement(st, out):
    if not isinstance(st, dict):
        raise Fail("statement-shape", "4", "statement not an object")
    for k in ("_type", "subject", "predicateType", "predicate"):
        if k not in st:
            raise Fail("statement-shape", "4", "statement.%s absent" % k)
    if st["_type"] != STATEMENT_TYPE:
        raise Fail("statement-type-unexpected", "4", "_type is not in-toto Statement v1")
    pt = st["predicateType"]
    if pt not in (PT_V1, PT_V2):
        raise Fail("predicate-type-mismatch", "4", "predicateType not the v1 or v2 URI")
    out["predicateType"] = pt
    p = st["predicate"]
    if not isinstance(p, dict):
        raise Fail("statement-shape", "4", "predicate not an object")
    subj = st["subject"]
    if not isinstance(subj, list) or not (1 <= len(subj) <= 2):
        raise Fail("statement-shape", "4.2", "subject is not one or two entries")
    for i, e in enumerate(subj):
        if not isinstance(e, dict) or not isinstance(e.get("digest"), dict) or "name" not in e:
            raise Fail("statement-shape", "4.2", "subject[%d] lacks name or digest map" % i)
    return pt, p, subj


def membership(p, pt, out):
    """4 and step 3 of 4.6, with the member rules of 5."""
    for k in REQUIRED_17:
        if k not in p:
            raise Fail("member-missing", "4", "required predicate member %s absent" % k)
    closed(p["tier"], V_TIER, "tier", "5.7")
    alg = p["hashAlgorithm"]
    if not isinstance(alg, str):
        raise Fail("member-malformed", "5.1", "hashAlgorithm not a string")
    if alg not in HEX:
        raise NoVerdict(alg)  # 5.1: no verdict over an unknown algorithm
    is_str(p["recordId"], "recordId", "5.1")
    t(p["issuedAt"], "issuedAt")

    a = p["agent"]
    if not isinstance(a, dict):
        raise Fail("member-malformed", "5.2", "agent not an object")
    is_str(need(a, "id", "agent", "5.2"), "agent.id", "5.2")
    hexd(need(a, "credentialDigest", "agent", "5.2"), alg, "agent.credentialDigest")
    closed(need(a, "authentication", "agent", "5.2"), V_AUTH, "agent.authentication", "5.2")
    sg = need(a, "signers", "agent", "5.2")
    if not isinstance(sg, list) or not all(isinstance(x, str) for x in sg):
        raise Fail("member-malformed", "5.2", "agent.signers not an array of key identifiers")

    d = p["delegation"]
    if not isinstance(d, dict):
        raise Fail("member-malformed", "5.2", "delegation not an object")
    is_str(need(d, "subject", "delegation", "5.2"), "delegation.subject", "5.2")
    closed(need(d, "subjectKind", "delegation", "5.2"), V_SUBJKIND, "delegation.subjectKind", "5.2")
    hexd(need(d, "authorityDigest", "delegation", "5.2"), alg, "delegation.authorityDigest")
    if "rootDigest" in d:
        hexd(d["rootDigest"], alg, "delegation.rootDigest")

    r = p["resource"]
    if not isinstance(r, dict):
        raise Fail("member-malformed", "5.2", "resource not an object")
    closed(need(r, "kind", "resource", "5.2"), V_RKIND, "resource.kind", "5.2")
    is_str(need(r, "id", "resource", "5.2"), "resource.id", "5.2")
    closed(need(r, "binding", "resource", "5.2"), V_BINDING, "resource.binding", "5.2")

    dc = p["decision"]
    if not isinstance(dc, dict):
        raise Fail("member-malformed", "5.3", "decision not an object")
    is_str(need(dc, "action", "decision", "5.3"), "decision.action", "5.3")
    hexd(need(dc, "requestDigest", "decision", "5.3"), alg, "decision.requestDigest")
    closed(need(dc, "reported", "decision", "5.3"), V_REPORTED, "decision.reported", "5.3")
    is_str(need(dc, "decisionPointId", "decision", "5.3"), "decision.decisionPointId", "5.3")
    hexd(need(dc, "policyDigest", "decision", "5.4"), alg, "decision.policyDigest")
    t(need(dc, "reportedAt", "decision", "5.4"), "decision.reportedAt")

    ev = p["evaluation"]
    if not isinstance(ev, dict):
        raise Fail("member-malformed", "5.4", "evaluation not an object")
    closed(need(ev, "status", "evaluation", "5.4"), V_STATUS, "evaluation.status", "5.4")
    inputs = need(ev, "inputs", "evaluation", "5.4")
    for k in ev:
        if k not in ("status", "inputs", "unavailableInput"):
            raise Fail("evaluation-malformed", "5.4", "evaluation carries undefined member %s" % k)
    if not isinstance(inputs, list):
        raise Fail("evaluation-entry-malformed", "5.4", "evaluation.inputs not an array")
    vin = V_INPUT_V2 if pt == PT_V2 else V_INPUT_V1
    for i, e in enumerate(inputs):
        if not isinstance(e, dict):
            raise Fail("evaluation-entry-malformed", "5.4", "inputs[%d] not an object" % i)
        for k in ("input", "lastResult", "maxAge"):
            if k not in e:
                raise Fail("member-missing", "5.4", "inputs[%d].%s absent" % (i, k))
        for k in e:
            if k not in ("input", "lastResult", "maxAge", "consumption"):
                raise Fail("evaluation-entry-malformed", "5.4", "inputs[%d] carries %s" % (i, k))
        closed(e["input"], vin, "inputs[%d].input" % i, "5.4")
        t(e["lastResult"], "inputs[%d].lastResult" % i, allow_none=True)
        if not is_nonneg_int(e["maxAge"]):
            raise Fail("evaluation-entry-malformed", "5.4", "inputs[%d].maxAge not a non-negative integer" % i)
    if "unavailableInput" in ev:
        ua = ev["unavailableInput"]
        if isinstance(ua, list):
            for x in ua:
                closed(x, vin, "unavailableInput[]", "5.4")

    ef = p["effect"]
    if not isinstance(ef, dict):
        raise Fail("member-malformed", "5.3", "effect not an object")
    closed(need(ef, "observed", "effect", "5.3"), V_OBSERVED, "effect.observed", "5.3")
    ps = need(ef, "pathScope", "effect", "5.3")
    if not isinstance(ps, list) or not all(isinstance(x, str) and x for x in ps):
        raise Fail("member-malformed", "5.3", "pathScope not an array of paths")
    ws = need(ef, "writes", "effect", "5.3")
    if not isinstance(ws, list):
        raise Fail("member-malformed", "5.3", "writes not an array")
    for i, w in enumerate(ws):
        for k in ("path", "preStateDigest", "postStateDigest", "requestDigest", "inScope"):
            need(w, k, "writes[%d]" % i, "5.3")
        is_str(w["path"], "writes[%d].path" % i, "5.3")
        hexd(w["preStateDigest"], alg, "writes[%d].preStateDigest" % i)
        hexd(w["postStateDigest"], alg, "writes[%d].postStateDigest" % i)
        if w["requestDigest"] != "unattributed":
            hexd(w["requestDigest"], alg, "writes[%d].requestDigest" % i)
        if not isinstance(w["inScope"], bool):
            raise Fail("member-malformed", "5.3", "writes[%d].inScope not boolean" % i)
    if "interval" in ef:
        iv = ef["interval"]
        for k in ("beforeRoot", "afterRoot", "baseResolution", "openedAt", "sealedAt"):
            need(iv, k, "effect.interval", "5.3")
        hexd(iv["beforeRoot"], alg, "interval.beforeRoot")
        hexd(iv["afterRoot"], alg, "interval.afterRoot")
        is_str(iv["baseResolution"], "interval.baseResolution", "5.3", True)
        t(iv["openedAt"], "interval.openedAt")
        t(iv["sealedAt"], "interval.sealedAt")

    closed(p["agreement"], V_AGREEMENT, "agreement", "5.3")

    c = p["correlation"]
    if not isinstance(c, dict):
        raise Fail("member-malformed", "5.6", "correlation not an object")
    is_str(need(c, "id", "correlation", "5.6"), "correlation.id", "5.6")
    closed(need(c, "scope", "correlation", "5.6"), V_SCOPE, "correlation.scope", "5.6")
    closed(need(c, "timeBasis", "correlation", "5.6"), V_TIMEBASIS, "correlation.timeBasis", "5.6")
    if "externalAnchor" in c:
        xa = c["externalAnchor"]
        closed(need(xa, "kind", "externalAnchor", "5.6"), V_ANCHOR, "externalAnchor.kind", "5.6")
        hexd(need(xa, "digest", "externalAnchor", "5.6"), alg, "externalAnchor.digest")

    po = p["posture"]
    if not isinstance(po, dict):
        raise Fail("member-malformed", "5.6", "posture not an object")
    closed(need(po, "reported", "posture", "5.6"), V_POSTURE, "posture.reported", "5.6")
    closed(need(po, "observed", "posture", "5.6"), V_POSTURE, "posture.observed", "5.6")
    hexd(need(po, "reportedDigest", "posture", "5.6"), alg, "posture.reportedDigest")
    hexd(need(po, "observedDigest", "posture", "5.6"), alg, "posture.observedDigest")
    t(need(po, "assessedAt", "posture", "5.6"), "posture.assessedAt")
    closed(need(po, "agreement", "posture", "5.3"), V_AGREEMENT, "posture.agreement", "5.3")

    rm = p["remediation"]
    if not isinstance(rm, list):
        raise Fail("member-malformed", "5.6", "remediation not an array")
    for i, e in enumerate(rm):
        closed(need(e, "cause", "remediation[%d]" % i, "5.6"), V_CAUSE, "remediation.cause", "5.6")
        closed(need(e, "enforcement", "remediation[%d]" % i, "5.6"), V_ENFORCEMENT,
               "remediation.enforcement", "5.6")
        t(need(e, "signalReceivedAt", "remediation[%d]" % i, "5.6"), "signalReceivedAt")
        t(need(e, "enforcedAt", "remediation[%d]" % i, "5.6"), "enforcedAt")

    ob = p["observation"]
    if not isinstance(ob, dict):
        raise Fail("member-malformed", "5.7", "observation not an object")
    closed(need(ob, "vantage", "observation", "5.7"), V_VANTAGE, "observation.vantage", "5.7")
    cv = need(ob, "coverage", "observation", "5.7")
    if not isinstance(need(cv, "scopeComplete", "coverage", "5.7"), bool):
        raise Fail("member-malformed", "5.7", "scopeComplete not boolean")
    gaps = need(cv, "gaps", "coverage", "5.7")
    if not isinstance(gaps, list) or not all(isinstance(x, str) for x in gaps):
        raise Fail("member-malformed", "5.7", "gaps not an array of paths")
    if "priorCommitment" in ob:
        pc = ob["priorCommitment"]
        if not isinstance(pc, dict):
            raise Fail("member-malformed", "5.7", "priorCommitment not an object")
        if "committedAt" in pc:
            t(pc["committedAt"], "priorCommitment.committedAt")
        if "commitmentDigest" in pc:
            hexd(pc["commitmentDigest"], alg, "priorCommitment.commitmentDigest")

    fe = p["fieldEvidence"]
    if not isinstance(fe, dict):
        raise Fail("field-evidence-keys", "5.7", "fieldEvidence not an object")
    if set(fe.keys()) != FE_KEYS:
        raise Fail("field-evidence-keys", "5.7", "fieldEvidence does not carry exactly the seven keys")
    for k, v in fe.items():
        closed(v, V_FE, "fieldEvidence.%s" % k, "5.7")

    dna = p["doesNotAssert"]
    if not isinstance(dna, list) or not all(isinstance(x, str) for x in dna):
        raise Fail("member-malformed", "5.7", "doesNotAssert not an array of statements")

    if "oversight" in p:
        ov = p["oversight"]
        if not isinstance(ov, dict):
            raise Fail("oversight-malformed", "5.5", "oversight not an object")
        for k in ov:
            if k not in ("act", "recordDigest"):
                raise Fail("oversight-malformed", "5.5", "oversight carries undefined member %s" % k)
        closed(need(ov, "act", "oversight", "5.5"), V_ACT, "oversight.act", "5.5")
        if "recordDigest" in ov:
            hexd(ov["recordDigest"], alg, "oversight.recordDigest", "5.5")
    if "sequence" in p:
        sq = p["sequence"]
        if not isinstance(sq, dict) or set(sq.keys()) != {"boundary", "seq"}:
            raise Fail("sequence-malformed", "5.10", "sequence must carry exactly boundary and seq")
        if not isinstance(sq["boundary"], str):
            raise Fail("sequence-malformed", "5.10", "boundary not a string")
        if not (isinstance(sq["seq"], int) and not isinstance(sq["seq"], bool) and sq["seq"] >= 1):
            raise Fail("sequence-malformed", "5.10", "seq not a positive integer")
    return alg


def derive_observed(p):
    ef, dc = p["effect"], p["decision"]
    rd = dc["requestDigest"]
    if any(w["requestDigest"] == rd for w in ef["writes"]):
        return "occurred"
    if not any(w["requestDigest"] == "unattributed" and under_scope(w["path"], ef["pathScope"])
               for w in ef["writes"]):
        return "none"
    return "unknown"


AGREE_TABLE = {  # 5.3 table 2
    ("permit", "occurred"): "agree", ("permit-with-conditions", "occurred"): "agree",
    ("deny", "none"): "agree", ("deny", "occurred"): "disagree",
    ("permit", "none"): "not-exercised", ("permit-with-conditions", "none"): "not-exercised",
}


def recomputes(st, p, subj, alg, out):
    H = hfun(alg)
    ef, dc, r = p["effect"], p["decision"], p["resource"]

    # 5.2 conditions
    d = p["delegation"]
    if d["subjectKind"] == "none" and d["subject"] != "none":
        raise Fail("delegation-subject-inconsistent", "5.2", "subjectKind none beside a named subject")
    if r["binding"] == "digest-bound":
        if "argumentsDigest" not in r:
            raise Fail("arguments-digest-missing", "5.2", "digest-bound without argumentsDigest")
        hexd(r["argumentsDigest"], alg, "resource.argumentsDigest")
    elif "argumentsDigest" in r:
        raise Fail("arguments-digest-forbidden", "5.2", "not-bindable carries argumentsDigest")
    # 5.6 timeBasis
    c = p["correlation"]
    if c["timeBasis"] == "beacon-anchored" and "externalAnchor" not in c:
        raise Fail("external-anchor-inconsistent", "5.6", "beacon-anchored without externalAnchor")
    if c["timeBasis"] == "asserted" and "externalAnchor" in c:
        raise Fail("external-anchor-inconsistent", "5.6", "asserted carries externalAnchor")
    # 4.2 subject binding to the digest map
    for i, e in enumerate(subj):
        if alg not in e["digest"]:
            raise Fail("subject-digest-missing", "4.2", "subject[%d] has no %s digest" % (i, alg))
        hexd(e["digest"][alg], alg, "subject[%d].digest" % i, "4.2")

    # 4.4 / 5.3 recompute 1: request digest
    pre = {"action": dc["action"], "resourceId": r["id"], "resourceKind": r["kind"]}
    if r["binding"] == "digest-bound":
        pre["argumentsDigest"] = r["argumentsDigest"]
    req = H(jcs(pre))
    out["recomputedRequestDigest"] = req
    if dc["requestDigest"] != req:
        raise Fail("request-digest-mismatch", "5.3", "decision.requestDigest is not the RFC 8785 digest")
    if subj[0]["digest"][alg] != dc["requestDigest"]:
        raise Fail("subject-request-mismatch", "5.3", "first subject digest is not decision.requestDigest")

    # 4.2 second subject if and only if there is an interval
    has_iv = "interval" in ef
    if has_iv != (len(subj) == 2):
        raise Fail("subject-interval-mismatch", "4.2", "second subject present iff interval violated")

    # 5.3 pathScope without glob, inScope derived
    for s in ef["pathScope"]:
        if any(ch in GLOB_CHARS for ch in s):
            raise Fail("path-scope-glob", "5.3", "pathScope member %r carries a glob metacharacter" % s)
    for i, w in enumerate(ef["writes"]):
        if w["inScope"] != under_scope(w["path"], ef["pathScope"]):
            raise Fail("write-scope-mismatch", "5.3", "writes[%d].inScope not derived from path" % i)

    # 4.4 / 5.3 recompute 2: write chain
    if has_iv:
        iv = ef["interval"]
        if iv["baseResolution"] == "empty-tree" and iv["beforeRoot"] != EMPTY_TREE.get(alg):
            raise Fail("empty-tree-constant-mismatch", "5.3",
                       "empty-tree without the empty-tree constant of %s" % alg)
        run = iv["beforeRoot"]
        for i, w in enumerate(ef["writes"]):
            if w["preStateDigest"] != run:
                raise Fail("write-chain-broken", "5.3", "writes[%d].preStateDigest is not the running root" % i)
            run = w["postStateDigest"]
        if run != iv["afterRoot"]:
            raise Fail("write-chain-broken", "5.3", "running root after last write is not afterRoot")
        if subj[1]["digest"][alg] != iv["afterRoot"]:
            raise Fail("subject-after-root-mismatch", "4.2", "second subject digest is not afterRoot")
        # 5.1 issuedAt not before sealedAt (new in -03)
        if t(p["issuedAt"], "issuedAt") < t(iv["sealedAt"], "sealedAt"):
            raise Fail("issued-before-sealed", "5.1", "issuedAt earlier than effect.interval.sealedAt")
    elif ef["writes"]:
        raise Fail("write-chain-broken", "5.3", "writes without an interval to replay from (reading L-IV)")

    # 5.3 recompute 3: effect.observed and agreement
    obs = derive_observed(p)
    out["derivedObserved"] = obs
    if ef["observed"] != obs:
        raise Fail("effect-observed-underivable", "5.3", "effect.observed %s, derived %s" % (ef["observed"], obs))
    if p["agreement"] == "one-sided":
        raise Fail("agreement-reserved-value", "5.3", "one-sided is never produced by this version")
    ag = "indeterminate" if obs == "unknown" else AGREE_TABLE[(dc["reported"], obs)]
    out["derivedAgreement"] = ag
    if p["agreement"] != ag:
        raise Fail("agreement-underivable", "5.3", "agreement %s, derived %s" % (p["agreement"], ag))
    po = p["posture"]
    pag = "agree" if po["reported"] == po["observed"] else "disagree"
    if po["agreement"] != pag:
        raise Fail("posture-agreement-underivable", "5.3", "posture.agreement %s, derived %s" % (po["agreement"], pag))

    # 5.6 remediation order
    for i, e in enumerate(p["remediation"]):
        if t(e["enforcedAt"], "enforcedAt") < t(e["signalReceivedAt"], "signalReceivedAt"):
            raise Fail("remediation-order", "5.6", "remediation[%d].enforcedAt before signalReceivedAt" % i)

    # 5.7 recompute 4: prior commitment
    ob = p["observation"]
    pc = ob.get("priorCommitment")
    pc_complete = isinstance(pc, dict) and all(
        k in pc for k in ("committedAt", "witnessNonce", "commitmentDigest", "keyid", "sig"))
    if isinstance(pc, dict):
        if "commitmentDigest" in pc:
            if not has_iv:
                raise Fail("commitment-digest-mismatch", "5.7", "no beforeRoot to recompute the commitment from")
            for k in ("witnessNonce",):
                need(pc, k, "priorCommitment", "5.7")
            cd = H(jcs({"authorityDigest": p["delegation"]["authorityDigest"],
                        "beforeRoot": ef["interval"]["beforeRoot"],
                        "recordId": p["recordId"], "witnessNonce": pc["witnessNonce"]}))
            if cd != pc["commitmentDigest"]:
                raise Fail("commitment-digest-mismatch", "5.7", "commitmentDigest does not recompute")
        if "committedAt" in pc and has_iv:
            if not t(pc["committedAt"], "committedAt") < t(ef["interval"]["openedAt"], "openedAt"):
                raise Fail("commitment-order", "5.7", "committedAt not strictly before openedAt")
        if "keyid" in pc and pc["keyid"] in p["agent"]["signers"]:
            raise Fail("commitment-key-is-agent-signer", "5.7", "commitment keyid appears in agent.signers")

    # 5.4 recompute 5: evaluation
    evaluation(p, out)

    # 5.9 consumption
    consumption(p, alg, out)

    # 5.7 coverage
    cv = ob["coverage"]
    gap_inside = any(under_scope(g, ef["pathScope"]) for g in cv["gaps"])
    if cv["scopeComplete"] and gap_inside:
        raise Fail("coverage-inconsistent", "5.7", "gap inside pathScope beside scopeComplete true")
    # 5.7 fieldEvidence against vantage
    if ob["vantage"] == "self" and any(v == "substrate-covered" for v in p["fieldEvidence"].values()):
        raise Fail("field-evidence-self-substrate", "5.7", "substrate-covered declared while vantage is self")

    # 5.7 Tier
    clauses = {
        "vantage": ob["vantage"] == "below-observed",
        "commitment": pc_complete,
        "scope": len(ef["pathScope"]) > 0,
        "coverage": cv["scopeComplete"] is True,
        "binding": r["binding"] == "digest-bound",
    }
    tier = "authoritative" if all(clauses.values()) else "voluntary"
    out["derivedTier"] = tier
    if p["tier"] == "authoritative" and tier != "authoritative":
        bad = [k for k, v in clauses.items() if not v][0]
        raise Fail("tier-overclaim-" + bad, "5.7", "authoritative declared, clause %s fails" % bad)


def evaluation(p, out):
    ev, dc = p["evaluation"], p["decision"]
    rep = t(dc["reportedAt"], "reportedAt")
    names = [e["input"] for e in ev["inputs"]]
    if len(names) != len(set(names)):
        raise Fail("evaluation-input-repeated", "5.4", "one input named in two entries")
    unavail = []
    for e in ev["inputs"]:
        lr = t(e["lastResult"], "lastResult", allow_none=True)
        if lr is None:
            unavail.append(e["input"])
            continue
        if lr > rep + SKEW:
            raise Fail("evaluation-result-after-decision", "5.4",
                       "%s lastResult later than reportedAt by more than skew" % e["input"])
        if rep - lr > e["maxAge"]:
            unavail.append(e["input"])
    out["derivedUnavailable"] = sorted(unavail)
    if ev["status"] == "evaluated":
        if "unavailableInput" in ev:
            raise Fail("evaluation-inconsistent", "5.4", "evaluated carries unavailableInput")
        if unavail:
            raise Fail("evaluation-inconsistent", "5.4", "evaluated beside stale or never established input")
    else:
        if "unavailableInput" not in ev:
            raise Fail("evaluation-inconsistent", "5.4", "not-evaluated without unavailableInput")
        ua = ev["unavailableInput"]
        if not isinstance(ua, list) or not ua:
            raise Fail("evaluation-inconsistent", "5.4", "unavailableInput not a non-empty array")
        if len(ua) != len(set(ua)):
            raise Fail("evaluation-inconsistent", "5.4", "unavailableInput names an input twice")
        if set(ua) != set(unavail):
            raise Fail("evaluation-inconsistent", "5.4",
                       "unavailableInput %s, derived %s" % (sorted(ua), sorted(unavail)))


def consumption(p, alg, out):
    dc = p["decision"]
    entries = [e for e in p["evaluation"]["inputs"] if "consumption" in e]
    wl = []
    for e in entries:
        if e["input"] != "consumption-state":
            raise Fail("consumption-misplaced", "5.9", "consumption on input %s" % e["input"])
        c = e["consumption"]
        keys = {"limitDigest", "unit", "limit", "consumed", "reserved", "requested", "held", "stateRevision"}
        if not isinstance(c, dict):
            raise Fail("consumption-malformed", "5.9", "consumption not an object")
        for k in keys:
            if k not in c:
                raise Fail("member-missing", "5.9", "consumption.%s absent" % k)
        for k in c:
            if k not in keys:
                raise Fail("consumption-malformed", "5.9", "consumption carries %s" % k)
        is_str(c["limitDigest"], "limitDigest", "5.9", True)
        is_str(c["unit"], "unit", "5.9", True)
        for k in ("limit", "consumed", "reserved", "requested", "stateRevision"):
            if not is_nonneg_int(c[k]):
                raise Fail("consumption-value-invalid", "5.9", "consumption.%s not a non-negative integer" % k)
        held = c["held"]
        if not isinstance(held, list):
            raise Fail("consumption-malformed", "5.9", "held not an array")
        keys_seen = set()
        tot = 0
        for i, h in enumerate(held):
            for k in ("operationKey", "requestDigest", "amount"):
                need(h, k, "held[%d]" % i, "5.9")
            if not is_nonneg_int(h["amount"]):
                raise Fail("consumption-value-invalid", "5.9", "held[%d].amount not a non-negative integer" % i)
            if h["operationKey"] in keys_seen:
                raise Fail("consumption-held-key-repeated", "5.9", "two held entries share an operationKey")
            keys_seen.add(h["operationKey"])
            tot += h["amount"]
        if tot != c["reserved"]:
            raise Fail("consumption-reserved-mismatch", "5.9", "held amounts do not sum to reserved")
        if "operationKey" not in dc:
            raise Fail("member-missing", "5.9", "decision.operationKey absent beside consumption")
        if not isinstance(dc["operationKey"], str) or not dc["operationKey"]:
            raise Fail("operation-key-invalid", "5.9", "decision.operationKey not a non-empty string")
        own = [h for h in held if h["operationKey"] == dc["operationKey"]]
        if own:
            h = own[0]
            if h["requestDigest"] != dc["requestDigest"] or h["amount"] != c["requested"]:
                raise Fail("consumption-key-reused", "5.9",
                           "held entry under the request's operationKey differs in requestDigest or amount")
            total = c["consumed"] + c["reserved"]
        else:
            total = c["consumed"] + c["reserved"] + c["requested"]
        wl.append(total <= c["limit"])
    if entries:
        out["withinLimit"] = wl[0] if len(wl) == 1 else wl


def verify_record(env, pinned):
    """Returns a dict with verdict, failure, derivedTier and the other recomputed values."""
    out = {"verdict": None, "failure": None}
    try:
        st, raw, keys = verify_envelope(env, pinned)
        out["signedBy"] = keys
        out["payloadSha256"] = hashlib.sha256(raw).hexdigest()
        pt, p, subj = check_statement(st, out)
        alg = membership(p, pt, out)
        recomputes(st, p, subj, alg, out)
        out["verdict"] = "valid"
        out["_statement"] = st
    except NoVerdict as e:
        out["verdict"] = "no-verdict"
        out["failure"] = {"code": "hash-algorithm-not-implemented", "section": "5.1", "text": str(e)}
    except Fail as f:
        out["verdict"] = "malformed"
        out["failure"] = {"code": f.code, "section": f.section, "text": f.text}
    except (KeyError, TypeError, AttributeError) as e:
        out["verdict"] = "malformed"
        out["failure"] = {"code": "member-malformed", "section": "5", "text": "shape error: %r" % (e,)}
    return out


# ---------------------------------------------------------------- Set checks, 5.9 and 5.10
def check_sequence_set(results):
    """5.10: results is a list of (out, statement). Missing numbers and numbers used twice."""
    series = {}
    for out, st in results:
        sq = st["predicate"].get("sequence")
        if not sq:
            continue
        key = (sq["boundary"], tuple(sorted(out.get("signedBy", []))))
        series.setdefault(key, []).append((sq["seq"], out["payloadSha256"]))
    missing, conflicts = [], []
    for (b, _k), lst in series.items():
        seqs = {}
        for s, ident in lst:
            seqs.setdefault(s, set()).add(ident)
        hi = max(seqs)
        for n in range(1, hi):
            if n not in seqs:
                missing.append({"boundary": b, "seq": n})
        for s, ids in seqs.items():
            if len(ids) > 1:
                conflicts.append({"boundary": b, "seq": s})
    return missing, conflicts


def check_consumption_set(results):
    """5.9: two checks over the records under one limitDigest."""
    recs = []
    for out, st in results:
        p = st["predicate"]
        for e in p["evaluation"]["inputs"]:
            if "consumption" in e:
                c = e["consumption"]
                recs.append({"lim": c["limitDigest"], "rev": c["stateRevision"],
                             "key": p["decision"].get("operationKey"),
                             "reported": p["decision"]["reported"],
                             "observed": p["effect"]["observed"],
                             "held": {h["operationKey"] for h in c["held"]}})
    fails = []
    by = {}
    for r in recs:
        by.setdefault(r["lim"], []).append(r)
    for lim, lst in by.items():
        settled = {r["key"] for r in lst if r["observed"] in ("none", "occurred")}
        # check 1: a permit read an older revision than a record that already held an unsettled permit
        for b in lst:
            if b["reported"] == "deny":
                continue
            for a in lst:
                if a["rev"] > b["rev"]:
                    for k in a["held"]:
                        if k != b["key"] and k not in b["held"]:
                            fails.append({"check": "stale-revision", "limitDigest": lim, "permit": b["key"], "omitted": k})
        # check 2: release from held without a settling record
        for a in lst:
            for b in lst:
                if b["rev"] > a["rev"]:
                    for k in a["held"]:
                        if k not in b["held"] and k not in settled and k != b["key"]:
                            fails.append({"check": "release-without-settlement", "limitDigest": lim, "key": k})
    return fails


# ---------------------------------------------------------------- 4.7 Retained records and dating
class EntryBad(Exception):
    def __init__(self, code, section, text=""):
        super().__init__(code)
        self.code, self.section, self.text = code, section, text


def _rd(buf, i, n):
    if i + n > len(buf):
        raise ValueError("truncated")
    return buf[i:i + n], i + n


def tl_validate(proof, env_digest_hex, trust):
    """4.7.2 transparency-log as a hash commitment: RFC 9162 TransItem inclusion_proof_v2.
    Leaf SHA-256(0x00 || envelopeDigest) (reading L-LEAF: envelopeDigest as 32 raw bytes).
    Returns (time, info) or None."""
    b = proof
    i = 0
    vt, i = _rd(b, i, 2)
    if vt != b"\x01\x06":  # RFC 9162 4.5 inclusion_proof_v2 = 0x0106
        return None
    ln, i = _rd(b, i, 1)
    log_id, i = _rd(b, i, ln[0])
    ts, i = _rd(b, i, 8)
    li, i = _rd(b, i, 8)
    tree_size = int.from_bytes(ts, "big")
    leaf_index = int.from_bytes(li, "big")
    pl, i = _rd(b, i, 2)
    end = i + int.from_bytes(pl, "big")
    path = []
    while i < end:
        n, i = _rd(b, i, 1)
        h, i = _rd(b, i, n[0])
        path.append(h)
    if i != len(b):
        return None
    leaf = hashlib.sha256(b"\x00" + bytes.fromhex(env_digest_hex)).digest()
    # RFC 9162 2.1.3.2
    if leaf_index >= tree_size:
        return None
    fn, sn, r = leaf_index, tree_size - 1, leaf
    for p in path:
        if sn == 0:
            return None
        if fn & 1 or fn == sn:
            r = hashlib.sha256(b"\x01" + p + r).digest()
            if not fn & 1:
                while True:
                    fn >>= 1
                    sn >>= 1
                    if fn & 1 or fn == 0:
                        break
        else:
            r = hashlib.sha256(b"\x01" + r + p).digest()
        fn >>= 1
        sn >>= 1
    if sn != 0:
        return None
    for th in trust.get("treeHeads", []):
        if th["logId"] == log_id.hex() and th["treeSize"] == tree_size and th["rootHash"] == r.hex():
            return t(th["timestamp"], "treeHead.timestamp"), {"kind": "transparency-log", "time": th["timestamp"]}
    return None


OTS_MAGIC = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"
OTS_BTC = bytes.fromhex("0588960d73d71901")
OTS_PENDING = bytes.fromhex("83dfe30d2ef90c8e")


def _varuint(b, i):
    v = s = 0
    while True:
        c, i = _rd(b, i, 1)
        v |= (c[0] & 0x7f) << s
        s += 7
        if not c[0] & 0x80:
            return v, i


def _varbytes(b, i):
    n, i = _varuint(b, i)
    return _rd(b, i, n)


def _ots_walk(b, i, msg, found):
    while True:
        tag, i = _rd(b, i, 1)
        tag = tag[0]
        if tag == 0xff:  # fork: branch, then continue
            i = _ots_walk(b, i, msg, found)
            continue
        if tag == 0x00:  # Attestation
            at, i = _rd(b, i, 8)
            payload, i = _varbytes(b, i)
            if at == OTS_BTC:
                h, _ = _varuint(payload, 0)
                found.append(("bitcoin", h, msg))
            elif at == OTS_PENDING:
                found.append(("pending", None, msg))
            else:
                found.append(("unknown", None, msg))
            return i
        if tag == 0xf0:
            a, i = _varbytes(b, i)
            msg = msg + a
        elif tag == 0xf1:
            a, i = _varbytes(b, i)
            msg = a + msg
        elif tag == 0x08:
            msg = hashlib.sha256(msg).digest()
        elif tag == 0x02:
            msg = hashlib.sha1(msg).digest()
        elif tag == 0x03:
            msg = hashlib.new("ripemd160", msg).digest()
        elif tag == 0xf2:
            msg = msg[::-1]
        elif tag == 0xf3:
            msg = msg.hex().encode()
        else:
            raise ValueError("unknown OTS op 0x%02x" % tag)


def ots_validate(proof, env_digest_hex, trust):
    """4.7.2 opentimestamps: the proof computes from envelopeDigest to the Merkle root of a held block
    header. The time is the header's time field. Returns (time, info) or None."""
    d = bytes.fromhex(env_digest_hex)
    b = proof
    i = 0
    if b.startswith(OTS_MAGIC):
        i = len(OTS_MAGIC)
        _v, i = _varuint(b, i)
        op, i = _rd(b, i, 1)
        if op != b"\x08":
            return None
        fd, i = _rd(b, i, 32)
        if fd != d:
            return None
    found = []
    try:
        _ots_walk(b, i, d, found)
    except ValueError:
        return None
    best = None
    for kind, h, msg in found:
        if kind != "bitcoin":
            continue
        for bh in trust.get("blockHeaders", []):
            if bh["height"] == h:
                hdr = bytes.fromhex(bh["header"])
                if len(hdr) == 80 and hdr[36:68] == msg:
                    tm = int.from_bytes(hdr[68:72], "little")
                    if best is None or h < best[1]["height"]:
                        best = (LEAP.instant(tm), {"kind": "opentimestamps", "height": h,
                                            "time": _dt.datetime.fromtimestamp(tm, _dt.timezone.utc)
                                            .strftime("%Y-%m-%dT%H:%M:%SZ")})
    return best


def _earliest(cands):
    """4.7.1, 4.7.2: the earliest time; two OTS times are compared by block height."""
    best = None
    for c in cands:
        if best is None:
            best = c
            continue
        a, b = best[1], c[1]
        if a["kind"] == "opentimestamps" and b["kind"] == "opentimestamps":
            if b["height"] < a["height"]:
                best = c
        elif c[0] < best[0]:
            best = c
    return best


def anchor_times(ent, ed, trust):
    """4.7.2: validate every anchor offline, over the recomputed envelopeDigest (reading L-DATE)."""
    vals = []
    for idx, a in enumerate(ent["anchors"]):
        try:
            pr = b64d(a["proof"])
        except Exception:
            continue
        res = None
        if a["kind"] == "transparency-log":
            try:
                res = tl_validate(pr, ed, trust)
            except ValueError:
                res = None
        elif a["kind"] == "opentimestamps":
            res = ots_validate(pr, ed, trust)
        # rfc3161: no case in the corpus, not implemented (NOT MEASURED)
        if res:
            vals.append((res[0], dict(res[1], origin=a["origin"], index=idx)))
    return vals


def jwk_alg(raw):
    """4.6 and 4.7: derive the algorithm the delegation chain's root rested on from the material, a key set of
    media type application/jwk-set+json (reading L-ROOTMAT).

    The material is read with parse_profile(), the same reader as the Statement and under the profile of
    4.1, which also governs the entry that carries it: UTF-8, no repeated member name, no surrogate or
    noncharacter, no nesting past 128 levels, every number an IEEE 754 double and every integer below 2^53.
    No number is converted beyond 16 digits, so the result does not depend on the interpreter's limit on
    integer string conversion. Then the key set must be an object whose member keys is a non-empty array of
    objects, each with a string kty; the algorithm is read off the first key. Anything else raises Fail or
    ValueError, and the caller reports the material as unreadable and the root as not established.
    """
    ks = parse_profile(raw)
    keys = ks.get("keys") if isinstance(ks, dict) else None
    if not isinstance(keys, list) or not keys:
        raise ValueError("no keys")
    if not all(isinstance(k, dict) and isinstance(k.get("kty"), str) for k in keys):
        raise ValueError("a key is not an object with a string kty")
    k = keys[0]
    if k["kty"] in ("OKP", "EC") and not isinstance(k.get("crv"), str):
        raise ValueError("crv absent or not a string")
    if k["kty"] == "OKP":
        return k["crv"]
    if k["kty"] == "EC":
        return "ECDSA-" + k["crv"]
    if k["kty"] == "RSA":
        return "RSA"
    return k.get("alg") if isinstance(k.get("alg"), str) else k["kty"]


def read_json(raw):
    """Any JSON text a runner hands to this verifier or reads beside it (vector files, the retained file with
    its entry, MANIFEST.json, pins.json), read with parse_profile() as the Statement is. 4.7 puts the entry
    under the profile of 4.1; for the containers around it the same reader keeps every number independent of
    the interpreter's limit and refuses a repeated member instead of keeping one occurrence."""
    return parse_profile(raw if isinstance(raw, bytes) else raw.encode("utf-8"))


def check_retained(obj, pinned, trust):
    """Returns (record_out, dating); dating stands beside the verdict (4.6)."""
    dating = {"entry": None, "datedAt": None, "receipt": None, "delegationRoot": {"result": "not-established"},
              "failure": None}
    if not isinstance(obj, dict) or "envelope" not in obj or "retention" not in obj:
        dating["entry"] = "malformed"
        dating["failure"] = {"code": "retained-unreadable", "section": "4.7", "text": "no envelope beside entry"}
        return {"verdict": "malformed", "failure": dating["failure"]}, dating
    env, ent = obj["envelope"], obj["retention"]
    rec = verify_record(env, pinned)
    try:
        if not isinstance(ent, dict):
            raise EntryBad("entry-shape-malformed", "4.7", "entry not an object")
        for k in ("envelopeDigest", "received", "anchorWithin", "anchors", "validationData"):
            if k not in ent:
                raise EntryBad("entry-shape-malformed", "4.7", "entry.%s absent" % k)
        allowed = {"envelopeDigest", "received", "receivedAt", "anchorWithin", "anchors", "validationData"}
        for k in ent:
            if k not in allowed:
                raise EntryBad("entry-shape-malformed", "4.7", "entry carries %s (reading L-ENTRY)" % k)
        st = rec.get("_statement")
        if st is None:
            # Without a readable record the entry cannot be checked
            try:
                raw = b64d(env["payload"])
                st = parse_profile(raw)
                st["predicate"]["hashAlgorithm"]
            except Exception:
                raise EntryBad("entry-record-unreadable", "4.7", "record payload not readable")
        p = st["predicate"]
        alg = p.get("hashAlgorithm", "sha256")
        H = hfun(alg)
        if not isinstance(ent["received"], bool):
            raise EntryBad("entry-shape-malformed", "4.7", "received not boolean")
        if not is_nonneg_int(ent["anchorWithin"]):
            raise EntryBad("entry-shape-malformed", "4.7", "anchorWithin not a non-negative integer")
        if not isinstance(ent["anchors"], list) or not isinstance(ent["validationData"], list):
            raise EntryBad("entry-shape-malformed", "4.7", "anchors or validationData not arrays")
        for a in ent["anchors"]:
            if not isinstance(a, dict) or set(a.keys()) != {"kind", "origin", "proof"}:
                raise EntryBad("entry-shape-malformed", "4.7", "anchor not {kind, origin, proof}")
            if a["kind"] not in V_ANCHOR or a["origin"] not in V_ORIGIN:
                raise EntryBad("entry-shape-malformed", "4.7", "anchor kind or origin outside closed set")
        # envelopeDigest over the RFC 8785 bytes of the envelope object
        ed = H(jcs(env))
        vals = anchor_times(ent, ed, trust)
        e = _earliest(vals)
        if e:
            dating["datedAt"] = e[1]["time"]
        if ent["envelopeDigest"] != ed:
            raise EntryBad("entry-envelope-digest-mismatch", "4.7", "envelopeDigest is not the digest of the envelope")
        # validationData
        dr = [v for v in ent["validationData"] if isinstance(v, dict) and v.get("for") == "delegation-root"]
        for v in ent["validationData"]:
            if not isinstance(v, dict) or not {"for", "mediaType", "value"} <= set(v.keys()):
                raise EntryBad("entry-shape-malformed", "4.7", "validationData element malformed")
            f = v["for"]
            if not (f in ("envelope", "delegation-root") or (is_nonneg_int(f) and f < len(ent["anchors"]))):
                raise EntryBad("entry-shape-malformed", "4.7", "validationData.for %r" % (f,))
        if len(dr) > 1:
            raise EntryBad("entry-delegation-root-unexpected", "4.7", "more than one delegation-root element")
        if dr and "rootDigest" not in p.get("delegation", {}):
            raise EntryBad("entry-delegation-root-unexpected", "4.7", "delegation-root without delegation.rootDigest")
        # received / receivedAt
        if ent["received"] != ("receivedAt" in ent):
            raise EntryBad("entry-received-at-inconsistent", "4.7", "receivedAt present iff received violated")
        if ent["received"] and not any(a["origin"] == "retainer" for a in ent["anchors"]):
            raise EntryBad("entry-retainer-anchor-missing", "4.7.1", "received true and no anchor of origin retainer")
        ret = _earliest([v for v in vals if v[1]["origin"] == "retainer"])
        issued = t(p["issuedAt"], "issuedAt")
        if ret:
            tol = OTS_TOL if ret[1]["kind"] == "opentimestamps" else SKEW
            if ent["received"]:
                ra = t(ent["receivedAt"], "receivedAt")
                if ra < issued - SKEW:
                    raise EntryBad("entry-received-before-issued", "4.7.1", "receivedAt earlier than issuedAt by more than skew")
                if ra > ret[0] + tol:
                    raise EntryBad("entry-received-after-anchor", "4.7.1", "receivedAt later than retention time by more than tolerance")
                if ret[0] > ra + ent["anchorWithin"] + tol:
                    raise EntryBad("entry-anchor-late", "4.7.1", "retention time later than receivedAt + anchorWithin + tolerance")
            else:
                if ret[0] > issued + ent["anchorWithin"] + tol:
                    raise EntryBad("entry-anchor-late", "4.7.1", "retention time later than issuedAt + anchorWithin + tolerance")
        elif ent["received"]:
            ra = t(ent["receivedAt"], "receivedAt")
            if ra < issued - SKEW:
                raise EntryBad("entry-received-before-issued", "4.7.1", "receivedAt earlier than issuedAt by more than skew")
        # delegation root (4.6)
        if dr:
            try:
                mat = b64d(dr[0]["value"])
            except Exception:
                raise EntryBad("entry-delegation-root-unreadable", "4.7", "delegation-root value not base64")
            if H(mat) != p["delegation"]["rootDigest"]:
                raise EntryBad("entry-delegation-root-mismatch", "4.6", "delegation-root digest differs from rootDigest")
            try:
                algn = jwk_alg(mat)
            except Fail as f:
                raise EntryBad("entry-delegation-root-unreadable", "4.7",
                               "delegation-root material outside the profile of 4.1, %s" % f.code)
            except Exception:
                raise EntryBad("entry-delegation-root-unreadable", "4.7", "delegation-root material unreadable")
            dating["delegationRoot"] = {"result": "established", "algorithm": algn}
        dating["entry"] = "well-formed"
        if ent["received"] and ret:
            dating["receipt"] = "asserted-consistent"
    except EntryBad as b:
        dating["entry"] = "malformed"
        dating["failure"] = {"code": b.code, "section": b.section, "text": b.text}
        dating["delegationRoot"] = {"result": "not-established"}
    except NoVerdict:
        dating["entry"] = "not-checked"
    except (Fail, KeyError, TypeError, ValueError) as e:
        dating["entry"] = "malformed"
        dating["failure"] = {"code": "entry-shape-malformed", "section": "4.7", "text": repr(e)[:120]}
    return rec, dating
