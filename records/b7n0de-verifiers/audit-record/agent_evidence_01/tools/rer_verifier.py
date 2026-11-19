# Copyright 2026 Konrad Gruszka
# Licensed under the Apache License, Version 2.0; see LICENSE.
"""Clean-room verifier for revision 00 of the restoration evidence draft.

Written from the text of the draft alone (sha256 0ae1b94c226cf85b006dfb34abf2180e9dcbda34ad30b9933067df37eafec745)
and, where it refers to [AUDIT-RECORD], from revision 03 of the agent audit record draft (4.1).
Result: verdict accept or reject, reason is the type verdict or the first failing code (4.4).
"""
import base64
import hashlib
import importlib.util
import json
import math
import os
import re

def _sibling(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                                     name + ".py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


LEAP = _sibling("leap_seconds")  # pinned leap-seconds.list, RFC 3339 5.7 (reading L-RLEAP)

PREFIX = "https://probityai.github.io/agent-evidence-vectors/predicate/v1/"  # 5
TYPES = {
    "incident-action-authorization": ("R1", "authorization-recorded"),
    "revocation-sweep": ("R2", "sweep-recorded"),
    "re-enable-decision": ("R3", "decision-recorded"),
    "joint-authority": ("R4", "assignment-recorded"),
    "revocation-boundary": ("RB", "boundary-recorded"),
}
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"  # 4.1
PAYLOAD_TYPE = "application/vnd.in-toto+json"  # 4.1 via [AUDIT-RECORD] 4.4
# 4.1 UTC, whole seconds. RFC 3339 4.3 says "Z" and "+00:00" both name UTC, and "-00:00" states the time in
# UTC with no local offset known; 5.6 allows a lower-case t and z (reading L-RLEAP)
TIME = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})[Tt]([0-9]{2}):([0-9]{2}):([0-9]{2})(?:[Zz]|[+-]00:00)")
HEX64 = re.compile(r"^[0-9a-f]{64}$")

# 4.3 registry values (rule 3); the draft lists the values in its own text
REG = {
    "response_function": {"monitoring_increase", "restriction", "isolation", "pause", "remediation", "restoration"},
    "restoration_decision": {"resume_full", "resume_staged", "remain_restricted", "not_established"},
    "revocation_state": {"issued", "enforced_observed", "use_after_revocation", "not_established"},
    "intent_binding": {"committed_before_execution", "asserted_after_execution"},
    "independence_basis": {"independent_sources", "subject_supplied", "undeclared"},
    "set_sufficiency": {"sufficient", "insufficient", "not_assessed"},
    "pause_hold": None,  # the draft lists no values: NOT CHECKABLE (reading L-PH)
}
# values the draft closes itself (rule 2, reading L-R23 after Section 10)
ROLES = {"advised", "authorized", "executed", "accountable"}
AUTH_BASIS = {"role_grant", "policy_preauthorized", "contract_third_party", "executive_approval", "unknown"}
PART_STATE = {"revoked", "retained", "unassessed"}
CLAIM = {"complete_verified", "issued_after_only", "partial", "unknown"}
SINK_KIND = {"database", "filesystem", "http_endpoint", "subprocess", "queue", "other"}
VANTAGE = {"sink_side", "agent_side"}
RESULT = {"no_post_revocation_commit_observed", "post_revocation_commit_observed", "not_established"}
SLOTS = ["actorObjective", "persistence", "rootCause", "affectedScope", "assetIntegrity",
         "restoredAssetsClean", "containmentReproof", "incidentReplay", "restoreOrder",
         "postRestartMonitoring", "exclusiveControl", "controlsNotDegraded", "residualRisk",
         "seniorApproval", "multiPartyAuthorization", "ownerConfirmation"]  # 5.3 table 4
COMMON = ["incident", "producer", "issuedAt", "registryDigest", "doesNotAssert"]  # 4.2


class Rej(Exception):
    def __init__(self, code, section, text=""):
        super().__init__(code)
        self.code, self.section, self.text = code, section, text


# ------------------------------------------------ JSON profile and JCS after [AUDIT-RECORD] 4.1
def _no_dupes(pairs):
    seen = set()
    for k, _ in pairs:
        if k in seen:
            raise Rej("statement-malformed", "4.1", "duplicate member %r" % k)
        seen.add(k)
    return dict(pairs)


def _int(s):
    # 2^53 has 16 digits and JSON allows no leading zero (RFC 8259 6), so a longer literal is unsafe; it is
    # refused by its length before int(), which converts at most 16 digits here and so stays below every
    # limit on integer string conversion the interpreter allows (640 digits at the least)
    if len(s.lstrip("-")) > 16:
        raise Rej("statement-malformed", "4.1", "integer outside I-JSON")
    v = int(s)
    if abs(v) >= 2 ** 53:
        raise Rej("statement-malformed", "4.1", "integer outside I-JSON")
    return v


def _float(s):
    # RFC 8785 3.1 via 4.1: a number must be expressible as an IEEE 754 double. A literal that overflows to
    # infinity or a non-zero literal that underflows to zero is not.
    v = float(s)
    if math.isinf(v) or math.isnan(v):
        raise Rej("statement-malformed", "4.1", "number outside IEEE 754 double")
    if v == 0 and any(c in "123456789" for c in s.lower().split("e")[0]):
        raise Rej("statement-malformed", "4.1", "non-zero number underflows IEEE 754 double")
    if v == int(v) and abs(v) >= 2 ** 53:
        raise Rej("statement-malformed", "4.1", "integral number outside I-JSON")
    return v


def _const(n):
    raise Rej("statement-malformed", "4.1", "non-finite number")


def _bad_char(o):
    # RFC 7493 2.1: names and string values hold no surrogate code point and no noncharacter
    return 0xD800 <= o <= 0xDFFF or 0xFDD0 <= o <= 0xFDEF or (o & 0xFFFE) == 0xFFFE


def _walk(o, d=1):
    # [AUDIT-RECORD] 4.1.2: no nesting past 128 levels; RFC 7493 2.1 for every name and string
    if isinstance(o, (dict, list)) and d > 128:
        raise Rej("statement-malformed", "4.1", "nesting deeper than 128")
    if isinstance(o, dict):
        for k, v in o.items():
            if any(_bad_char(ord(c)) for c in k):
                raise Rej("statement-malformed", "4.1", "member name not I-JSON (surrogate or noncharacter)")
            _walk(v, d + 1)
    elif isinstance(o, list):
        for v in o:
            _walk(v, d + 1)
    elif isinstance(o, str):
        if any(_bad_char(ord(c)) for c in o):
            raise Rej("statement-malformed", "4.1", "string not I-JSON (surrogate or noncharacter)")


def parse(raw):
    try:
        st = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_dupes, parse_int=_int,
                        parse_float=_float, parse_constant=_const)
    except Rej:
        raise
    except Exception as e:
        raise Rej("statement-malformed", "4.1", "not JSON: %s" % str(e)[:60])
    _walk(st)
    return st


def _s(x):
    out = ['"']
    for c in x:
        o = ord(c)
        if c == '"':
            out.append('\\"')
        elif c == "\\":
            out.append("\\\\")
        elif c in "\b\t\n\f\r":
            out.append({"\b": "\\b", "\t": "\\t", "\n": "\\n", "\f": "\\f", "\r": "\\r"}[c])
        elif o < 0x20:
            out.append("\\u%04x" % o)
        else:
            out.append(c)
    return "".join(out) + '"'


def _num(v):
    """RFC 8785 3.2.2.3: the ECMAScript Number::toString form of the shortest round-trip digits."""
    if v == 0:
        return "0"
    if v == int(v) and abs(v) < 2 ** 53:  # exact, and the shortest digits too
        return str(int(v))
    sign = "-" if v < 0 else ""
    r = repr(abs(v))  # shortest digits that round-trip
    mant, _, exp = r.partition("e")
    ip, _, fp = mant.partition(".")
    raw = ip + fp
    lead = len(raw) - len(raw.lstrip("0"))
    digits = raw.strip("0")
    n = len(ip) + int(exp or 0) - lead  # decimal point position relative to the digits
    k = len(digits)
    if k <= n <= 21:
        s = digits + "0" * (n - k)
    elif 0 < n <= 21:
        s = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        s = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        s = digits[0] + ("." + digits[1:] if k > 1 else "") + "e" + ("+" if e >= 0 else "-") + str(abs(e))
    return sign + s


def jcs(o):
    def e(x):
        if x is None:
            return "null"
        if x is True:
            return "true"
        if x is False:
            return "false"
        if isinstance(x, int):
            return str(x)
        if isinstance(x, float):
            return _num(x)
        if isinstance(x, str):
            return _s(x)
        if isinstance(x, list):
            return "[" + ",".join(e(i) for i in x) + "]"
        ks = sorted(x, key=lambda k: k.encode("utf-16-be"))
        return "{" + ",".join(_s(k) + ":" + e(x[k]) for k in ks) + "}"
    return e(o).encode("utf-8")


def pae(pt, body):
    t = pt.encode()
    return b"DSSEv1 " + str(len(t)).encode() + b" " + t + b" " + str(len(body)).encode() + b" " + body


def open_envelope(env, pinned):
    """4.1: DSSE envelope, signature over the RFC 8785 bytes. Returns (raw_payload, statement)."""
    from cryptography.exceptions import InvalidSignature
    if not isinstance(env, dict) or env.get("payloadType") != PAYLOAD_TYPE:
        raise Rej("statement-malformed", "4.1", "not a DSSE envelope of in-toto JSON")
    raw = base64.b64decode(env["payload"], validate=True)
    st = parse(raw)
    msg = pae(PAYLOAD_TYPE, jcs(st))
    for s in env.get("signatures") or []:
        pk = pinned.get(s.get("keyid"))
        if pk is None:
            continue
        try:
            pk.verify(base64.b64decode(s["sig"]), msg)
            return raw, st
        except (InvalidSignature, ValueError):
            pass
    raise Rej("signature-invalid", "4.1", "no signature verifies under a pinned key (reading L-SIGC)")


# ------------------------------------------------ Helpers
def obj(v, keys_req, keys_opt, where, code="predicate-malformed", sect="5"):
    if not isinstance(v, dict):
        raise Rej(code, sect, "%s not an object" % where)
    for k in keys_req:
        if k not in v:
            raise Rej(code, sect, "%s.%s absent" % (where, k))
    for k in v:
        if k not in keys_req and k not in keys_opt:
            raise Rej(code, sect, "%s carries undefined member %s" % (where, k))
    return v


def nestr(v, where, sect="5"):
    if not isinstance(v, str) or not v:
        raise Rej("predicate-malformed", sect, "%s not a non-empty string" % where)
    return v


def https(v, where):
    if not isinstance(v, str) or not v.startswith("https://") or len(v) <= len("https://"):
        raise Rej("predicate-malformed", "4.2", "%s not an https URL" % where)
    return v


def _instant(v):
    """The exact instant of an RFC 3339 UTC time to whole seconds, or None if v is not one."""
    m = TIME.fullmatch(v) if isinstance(v, str) else None
    if not m:
        return None
    y, mo, d, hh, mi, ss = (int(g) for g in m.groups())
    # RFC 3339 5.6 and 5.7: the day exists in its month and year, hour 00-23, minute 00-59; second 60
    # only where a leap second occurs, which the pinned list confirms, and 23:59:59 does not exist
    # before a subtracted one (reading L-RLEAP)
    if not (LEAP.date_exists(y, mo, d) and hh <= 23 and mi <= 59 and ss <= 60):
        return None
    p = LEAP.posix(y, mo, d, hh, mi, 59 if ss == 60 else ss)
    if ss == 60:
        if not ((hh, mi) == (23, 59) and LEAP.covered(p + 1) and LEAP.inserted(p + 1)):
            return None
    elif (hh, mi, ss) == (23, 59, 59) and LEAP.removed(p + 1):
        return None
    return LEAP.instant(p, ss == 60)


def tm(v, where, sect="4.1"):
    """4.1: RFC 3339 UTC time to whole seconds, with a calendar date and a clock time that exist."""
    if _instant(v) is None:
        raise Rej("predicate-malformed", sect, "%s not an RFC 3339 UTC time to whole seconds" % where)
    return v


def sha(v, where, sect="4.1"):
    obj(v, ["sha256"], [], where, sect=sect)
    if not isinstance(v["sha256"], str) or not HEX64.match(v["sha256"]):
        raise Rej("predicate-malformed", sect, "%s.sha256 not lowercase hex" % where)
    return v


def lst(v, where, nonempty=False, sect="5"):
    if not isinstance(v, list) or (nonempty and not v):
        raise Rej("predicate-malformed", sect, "%s not a %slist" % (where, "non-empty " if nonempty else ""))
    return v


def sorted_strs(v, where, nonempty=False, nodup=False, sect="5"):
    lst(v, where, nonempty, sect)
    if not all(isinstance(x, str) for x in v):
        raise Rej("predicate-malformed", sect, "%s holds a non-string" % where)
    if v != sorted(v):
        raise Rej("predicate-malformed", sect, "%s not sorted" % where)
    if nodup and len(set(v)) != len(v):
        raise Rej("predicate-malformed", sect, "%s carries a duplicate" % where)
    return v


def inset(v, vocab, where, sect="5"):
    if v not in vocab:
        raise Rej("predicate-malformed", sect, "%s=%r outside the set this document lists" % (where, v))


def descriptor(v, where):
    """in-toto ResourceDescriptor {digest:{sha256}, uri?, mediaType?} (5.2, 5.3)."""
    obj(v, ["digest"], ["uri", "mediaType"], where)
    sha(v["digest"], where + ".digest", "5")
    for k in ("uri", "mediaType"):
        if k in v and not isinstance(v[k], str):
            raise Rej("predicate-malformed", "5", "%s.%s not a string" % (where, k))


def ts(v):
    """4.1 "compared as instants": the exact instant of a time tm() accepted, as elapsed seconds that count
    the leap seconds of the pinned list, so every spelling of one instant compares equal and 23:59:60
    lies between 23:59:59 and the midnight (reading L-RLEAP)."""
    i = _instant(v)
    if i is None:
        raise Rej("predicate-malformed", "4.1", "time not an RFC 3339 UTC time to whole seconds")
    return i


# ------------------------------------------------ Rules 1 to 3 and the type rules
def check_statement(st):
    """Returns (type_name, predicate) or raises Rej. Rule 1."""
    if not isinstance(st, dict) or set(st.keys()) != {"_type", "subject", "predicateType", "predicate"}:
        raise Rej("statement-malformed", "4.1", "statement members are not exactly _type, subject, predicateType, predicate")
    if st["_type"] != STATEMENT_TYPE:
        raise Rej("statement-malformed", "4.1", "_type is not Statement v1")
    pt = st["predicateType"]
    if not isinstance(pt, str) or not pt.startswith(PREFIX) or pt[len(PREFIX):] not in TYPES:
        raise Rej("statement-malformed", "4.1", "predicateType not one of the five URIs")
    name = pt[len(PREFIX):]
    sub = st["subject"]
    if not isinstance(sub, list) or not sub:
        raise Rej("statement-malformed", "4.1", "subject not a non-empty list")
    for i, s in enumerate(sub):
        if not isinstance(s, dict) or "digest" not in s:
            raise Rej("statement-malformed", "4.1", "subject[%d] carries no digest" % i)
        d = s["digest"]
        if not isinstance(d, dict) or set(d.keys()) != {"sha256"} or not isinstance(d["sha256"], str) \
                or not HEX64.match(d["sha256"]):
            raise Rej("statement-malformed", "4.1", "subject[%d].digest holds not only sha256" % i)
        for k in s:
            if k not in ("name", "digest", "uri", "annotations", "downloadLocation", "mediaType"):
                raise Rej("statement-malformed", "4.1", "subject[%d] carries %s" % (i, k))
    if name in ("revocation-sweep", "joint-authority", "revocation-boundary") and len(sub) != 1:
        raise Rej("statement-malformed", "5", "%s subject is one member" % name)
    if not isinstance(st["predicate"], dict):
        raise Rej("predicate-malformed", "4.4", "predicate not an object")
    return name, st["predicate"]


def common(p, extra_req, extra_opt):
    obj(p, COMMON + extra_req, extra_opt, "predicate", sect="4.2")
    inc = obj(p["incident"], ["issuer", "id"], ["related"], "incident", sect="4.2")
    https(inc["issuer"], "incident.issuer")
    nestr(inc["id"], "incident.id", "4.2")
    if "related" in inc:
        for i, r in enumerate(lst(inc["related"], "incident.related", sect="4.2")):
            obj(r, ["issuer", "id"], [], "incident.related[%d]" % i, sect="4.2")
            https(r["issuer"], "related.issuer")
            nestr(r["id"], "related.id", "4.2")
    https(obj(p["producer"], ["id"], [], "producer", sect="4.2")["id"], "producer.id")
    tm(p["issuedAt"], "issuedAt")
    sha(p["registryDigest"], "registryDigest", "4.2")
    for i, s in enumerate(lst(p["doesNotAssert"], "doesNotAssert", sect="4.2")):
        nestr(s, "doesNotAssert[%d]" % i, "4.2")
    if "predecessors" in p:
        for i, pr in enumerate(lst(p["predecessors"], "predecessors", sect="4.2")):
            obj(pr, ["predicateType", "digest"], [], "predecessors[%d]" % i, sect="4.2")
            if not isinstance(pr["predicateType"], str) or not pr["predicateType"].startswith(PREFIX) \
                    or pr["predicateType"][len(PREFIX):] not in TYPES:
                raise Rej("predicate-malformed", "4.2", "predecessors[%d].predicateType unknown" % i)
            sha(pr["digest"], "predecessors[%d].digest" % i, "4.2")


def parties_r1(ps):
    lst(ps, "parties", True, "5.1")
    for i, q in enumerate(ps):
        obj(q, ["id", "roles"], ["authorityBasis", "independenceBasis"], "parties[%d]" % i, sect="5.1")
        nestr(q["id"], "parties[%d].id" % i, "5.1")
        sorted_strs(q["roles"], "parties[%d].roles" % i, True, sect="5.1")
        for r in q["roles"]:
            inset(r, ROLES, "roles", "5.1")
        if "authorityBasis" in q:
            inset(q["authorityBasis"], AUTH_BASIS, "authorityBasis", "5.1")


def rule2(name, p):
    if name == "incident-action-authorization":
        common(p, ["action", "parties", "authorizedAt", "notAfter", "intentBinding"], ["executedAt", "pause"])
        a = obj(p["action"], ["functions", "targets", "inducedEffects"], [], "action", sect="5.1")
        sorted_strs(a["functions"], "action.functions", True, sect="5.1")
        for i, t in enumerate(lst(a["targets"], "action.targets", True, "5.1")):
            nestr(obj(t, ["id"], [], "targets[%d]" % i, sect="5.1")["id"], "targets.id", "5.1")
        ie = a["inducedEffects"]
        if not isinstance(ie, dict) or "declared" not in ie:
            raise Rej("predicate-malformed", "5.1", "inducedEffects carries no declared")
        if ie["declared"] == "listed":
            obj(ie, ["declared", "items"], [], "inducedEffects", sect="5.1")
            lst(ie["items"], "inducedEffects.items", sect="5.1")
        elif ie["declared"] == "none_observed":
            obj(ie, ["declared"], ["observation"], "inducedEffects", sect="5.1")
            if "observation" in ie:
                sha(ie["observation"], "inducedEffects.observation", "5.1")
        elif ie["declared"] == "unknown":
            obj(ie, ["declared"], [], "inducedEffects", sect="5.1")
        else:
            raise Rej("predicate-malformed", "5.1", "inducedEffects.declared outside the three forms")
        parties_r1(p["parties"])
        tm(p["authorizedAt"], "authorizedAt", "5.1")
        tm(p["notAfter"], "notAfter", "5.1")
        if "executedAt" in p:
            tm(p["executedAt"], "executedAt", "5.1")
        if not isinstance(p["intentBinding"], str):
            raise Rej("predicate-malformed", "5.1", "intentBinding not a string")
        if "pause" in p:
            pa = obj(p["pause"], ["hold", "holdProof"], [], "pause", sect="5.1")
            if not isinstance(pa["hold"], str):
                raise Rej("predicate-malformed", "5.1", "pause.hold not a string")
            sha(pa["holdProof"], "pause.holdProof", "5.1")
    elif name == "revocation-sweep":
        common(p, ["predecessors", "population", "partition", "revocations", "coverage"], [])
        if not any(x["predicateType"] == PREFIX + "incident-action-authorization" for x in p["predecessors"]):
            raise Rej("predicate-malformed", "5.2", "predecessors name no R1")
        pop = obj(p["population"], ["credentials"], [], "population", sect="5.2")
        sorted_strs(pop["credentials"], "population.credentials", True, True, "5.2")
        for i, part in enumerate(lst(p["partition"], "partition", sect="5.2")):
            obj(part, ["state", "credentials"], [], "partition[%d]" % i, sect="5.2")
            inset(part["state"], PART_STATE, "partition.state", "5.2")
            lst(part["credentials"], "partition.credentials", sect="5.2")
            if not all(isinstance(c, str) for c in part["credentials"]):
                raise Rej("predicate-malformed", "5.2", "partition credentials not identifiers")
        for i, r in enumerate(lst(p["revocations"], "revocations", sect="5.2")):
            obj(r, ["credential", "revokedAt", "evidence", "relyingParties"], [], "revocations[%d]" % i, sect="5.2")
            nestr(r["credential"], "revocations.credential", "5.2")
            tm(r["revokedAt"], "revocations.revokedAt", "5.2")
            descriptor(r["evidence"], "revocations.evidence")
            for j, rp in enumerate(lst(r["relyingParties"], "relyingParties", sect="5.2")):
                obj(rp, ["id", "state"], [], "relyingParties[%d]" % j, sect="5.2")
                nestr(rp["id"], "relyingParties.id", "5.2")
                if not isinstance(rp["state"], str):
                    raise Rej("predicate-malformed", "5.2", "relyingParties.state not a string")
        cv = p["coverage"]
        if not isinstance(cv, dict) or "claim" not in cv:
            raise Rej("predicate-malformed", "5.2", "coverage carries no claim")
        inset(cv["claim"], CLAIM, "coverage.claim", "5.2")
        obj(cv, ["claim"], ["issuedAfter"] if cv["claim"] == "issued_after_only" else [], "coverage", sect="5.2")
        if "issuedAfter" in cv:
            tm(cv["issuedAfter"], "coverage.issuedAfter", "5.2")
    elif name == "re-enable-decision":
        common(p, ["predecessors", "restoration", "approvers", "setSufficiency", "evidence"], [])
        lst(p["predecessors"], "predecessors", True, "5.3")
        rs = p["restoration"]
        obj(rs, ["decision"], ["restoredScope"], "restoration", sect="5.3")
        if not isinstance(rs["decision"], str):
            raise Rej("predicate-malformed", "5.3", "restoration.decision not a string")
        if "restoredScope" in rs:
            sc = obj(rs["restoredScope"], ["agents", "tools", "routes", "credentials"], [], "restoredScope", sect="5.3")
            for k in ("agents", "tools", "routes", "credentials"):
                sorted_strs(sc[k], "restoredScope." + k, sect="5.3")
        for i, ap in enumerate(lst(p["approvers"], "approvers", sect="5.3")):
            obj(ap, ["id", "roles", "independenceBasis"], [], "approvers[%d]" % i, sect="5.3")
            nestr(ap["id"], "approvers.id", "5.3")
            sorted_strs(ap["roles"], "approvers.roles", True, sect="5.3")
            for r in ap["roles"]:
                inset(r, ROLES, "approvers.roles", "5.3")
        if not isinstance(p["setSufficiency"], str):
            raise Rej("predicate-malformed", "5.3", "setSufficiency not a string")
        ev = p["evidence"]
        if not isinstance(ev, dict):
            raise Rej("predicate-malformed", "5.3", "evidence not an object")
        for k, v in ev.items():
            if isinstance(v, dict) and "notAddressed" in v:
                obj(v, ["notAddressed"], [], "evidence." + k, sect="5.3")
                if not isinstance(v["notAddressed"], str):
                    raise Rej("predicate-malformed", "5.3", "evidence.%s.notAddressed not a string" % k)
            else:
                descriptor(v, "evidence." + k)
    elif name == "joint-authority":
        common(p, ["sharedIndicators", "parties"], ["actions"])
        si = lst(p["sharedIndicators"], "sharedIndicators", True, "5.4")
        for i, x in enumerate(si):
            sha(x, "sharedIndicators[%d]" % i, "5.4")
        if [x["sha256"] for x in si] != sorted(x["sha256"] for x in si):
            raise Rej("predicate-malformed", "5.4", "sharedIndicators not sorted")
        ps = lst(p["parties"], "parties", sect="5.4")
        if len(ps) < 2:
            raise Rej("predicate-malformed", "5.4", "fewer than two parties")
        for i, q in enumerate(ps):
            obj(q, ["id", "organization", "correlationId", "assets"], ["authorityBasis"], "parties[%d]" % i, sect="5.4")
            for k in ("id", "organization", "correlationId"):
                nestr(q[k], "parties.%s" % k, "5.4")
            if "authorityBasis" in q:
                inset(q["authorityBasis"], AUTH_BASIS, "authorityBasis", "5.4")
            sorted_strs(q["assets"], "parties.assets", sect="5.4")
        if "actions" in p:
            for i, a in enumerate(lst(p["actions"], "actions", sect="5.4")):
                obj(a, ["party", "asset", "record"], [], "actions[%d]" % i, sect="5.4")
                nestr(a["party"], "actions.party", "5.4")
                nestr(a["asset"], "actions.asset", "5.4")
                sha(a["record"], "actions.record", "5.4")
    elif name == "revocation-boundary":
        common(p, ["sink", "observer", "revocation", "window", "counts", "exclusions", "result"], ["predecessors"])
        sk = obj(p["sink"], ["id", "kind", "commitBoundary"], [], "sink", sect="5.5")
        nestr(sk["id"], "sink.id", "5.5")
        inset(sk["kind"], SINK_KIND, "sink.kind", "5.5")
        nestr(sk["commitBoundary"], "sink.commitBoundary", "5.5")
        ob = obj(p["observer"], ["id", "vantage"], [], "observer", sect="5.5")
        nestr(ob["id"], "observer.id", "5.5")
        inset(ob["vantage"], VANTAGE, "observer.vantage", "5.5")
        rv = obj(p["revocation"], ["credential", "effectiveAt", "timeSource"], [], "revocation", sect="5.5")
        nestr(rv["credential"], "revocation.credential", "5.5")
        tm(rv["effectiveAt"], "revocation.effectiveAt", "5.5")
        nestr(rv["timeSource"], "revocation.timeSource", "5.5")
        w = obj(p["window"], ["start", "end"], [], "window", sect="5.5")
        tm(w["start"], "window.start", "5.5")
        tm(w["end"], "window.end", "5.5")
        c = obj(p["counts"], ["attempts", "inFlightAtRevocation", "postRevocationCommits", "replaysAttempted",
                              "replaysCommitted"], [], "counts", sect="5.5")
        for k, v in c.items():
            if not (isinstance(v, int) and not isinstance(v, bool) and v >= 0):
                raise Rej("predicate-malformed", "5.5", "counts.%s not a non-negative integer" % k)
        for i, e in enumerate(lst(p["exclusions"], "exclusions", sect="5.5")):
            obj(e, ["count", "reason"], [], "exclusions[%d]" % i, sect="5.5")
            if not (isinstance(e["count"], int) and not isinstance(e["count"], bool) and e["count"] >= 0):
                raise Rej("predicate-malformed", "5.5", "exclusions.count not a non-negative integer")
            nestr(e["reason"], "exclusions.reason", "5.5")
        inset(p["result"], RESULT, "result", "5.5")


def rule3(name, p):
    def bad(w, v):
        return Rej("closed-vocabulary-violation", "4.3", "%s=%r outside the registry set" % (w, v))

    if name == "incident-action-authorization":
        for f in p["action"]["functions"]:
            if f not in REG["response_function"]:
                raise bad("functions", f)
        for q in p["parties"]:
            if "independenceBasis" in q and q["independenceBasis"] not in REG["independence_basis"]:
                raise bad("independenceBasis", q["independenceBasis"])
        if p["intentBinding"] not in REG["intent_binding"]:
            raise bad("intentBinding", p["intentBinding"])
        # pause.hold: the draft lists no pause_hold values (NOT CHECKABLE)
    elif name == "revocation-sweep":
        for r in p["revocations"]:
            for rp in r["relyingParties"]:
                if rp["state"] not in REG["revocation_state"]:
                    raise bad("relyingParties.state", rp["state"])
    elif name == "re-enable-decision":
        if p["restoration"]["decision"] not in REG["restoration_decision"]:
            raise bad("restoration.decision", p["restoration"]["decision"])
        for ap in p["approvers"]:
            if ap["independenceBasis"] not in REG["independence_basis"]:
                raise bad("independenceBasis", ap["independenceBasis"])
        if p["setSufficiency"] not in REG["set_sufficiency"]:
            raise bad("setSufficiency", p["setSufficiency"])


def type_rules(name, p):
    if name == "incident-action-authorization":  # 5.1 table 2
        ps = p["parties"]
        if not any("authorized" in q["roles"] for q in ps):
            raise Rej("no-authorizer", "5.1")
        if not any("accountable" in q["roles"] for q in ps):
            raise Rej("no-accountable-party", "5.1")
        if any("authorized" in q["roles"] and "authorityBasis" not in q for q in ps):
            raise Rej("authority-basis-missing", "5.1")
        if ts(p["authorizedAt"]) > ts(p["notAfter"]):
            raise Rej("authorization-window-inverted", "5.1")
        if p["intentBinding"] == "committed_before_execution" and "executedAt" in p \
                and ts(p["executedAt"]) < ts(p["authorizedAt"]):
            raise Rej("intent-not-committed-before", "5.1")
        if "executedAt" in p and ts(p["executedAt"]) > ts(p["notAfter"]):
            raise Rej("authorization-expired", "5.1")
        ie = p["action"]["inducedEffects"]
        if ie["declared"] == "none_observed" and "observation" not in ie:
            raise Rej("induced-effects-unobserved", "5.1")
    elif name == "revocation-sweep":  # 5.2 table 3
        parts = p["partition"]
        allc = [c for part in parts for c in part["credentials"]]
        if len(allc) != len(set(allc)) or set(allc) != set(p["population"]["credentials"]):
            raise Rej("denominator-union-mismatch", "5.2")
        revoked = {c for part in parts if part["state"] == "revoked" for c in part["credentials"]}
        named = [r["credential"] for r in p["revocations"]]
        if len(named) != len(set(named)) or set(named) != revoked:
            raise Rej("revocation-entries-mismatch", "5.2")
        cv = p["coverage"]
        if cv["claim"] == "complete_verified" and revoked != set(p["population"]["credentials"]):
            raise Rej("coverage-claim-exceeds-proof", "5.2")
        if cv["claim"] == "issued_after_only" and "issuedAfter" not in cv:
            raise Rej("coverage-claim-incomplete", "5.2")
    elif name == "re-enable-decision":  # 5.3 table 5
        ev = p["evidence"]
        if set(ev.keys()) != set(SLOTS):
            raise Rej("evidence-slot-missing", "5.3")
        for v in ev.values():
            if "notAddressed" in v and v["notAddressed"] == "":
                raise Rej("evidence-slot-unexplained", "5.3")
        if not p["approvers"] or not any("authorized" in a["roles"] for a in p["approvers"]):
            raise Rej("no-approver", "5.3")
        rs = p["restoration"]
        if rs["decision"] == "resume_staged":
            sc = rs.get("restoredScope")
            if not sc or not any(sc[k] for k in ("agents", "tools", "routes", "credentials")):
                raise Rej("partial-without-scope", "5.3")
        if rs["decision"] == "resume_full" and "restoredScope" in rs:
            raise Rej("full-with-scope", "5.3")
    elif name == "joint-authority":  # 5.4 table 6
        ps = p["parties"]
        if any("authorityBasis" not in q for q in ps):
            raise Rej("authority-basis-missing", "5.4")
        if len({q["organization"] for q in ps}) < 2:
            raise Rej("single-organization", "5.4")
        assets = {q["id"]: set(q["assets"]) for q in ps}
        for a in p.get("actions", []):
            if a["party"] not in assets or a["asset"] not in assets[a["party"]]:
                raise Rej("party-acts-outside-assignment", "5.4")
    elif name == "revocation-boundary":  # 5.5 table 7
        w, rv, c = p["window"], p["revocation"], p["counts"]
        if not (ts(w["start"]) <= ts(rv["effectiveAt"]) <= ts(w["end"])):
            raise Rej("revocation-outside-window", "5.5")
        if c["inFlightAtRevocation"] > c["attempts"] or c["postRevocationCommits"] > c["inFlightAtRevocation"] \
                or c["replaysCommitted"] > c["replaysAttempted"]:
            raise Rej("counts-inconsistent", "5.5")
        pos = c["postRevocationCommits"] > 0 or c["replaysCommitted"] > 0
        if p["result"] != "not_established" and (p["result"] == "post_revocation_commit_observed") != pos:
            raise Rej("result-contradicts-counts", "5.5")
        if p["result"] == "no_post_revocation_commit_observed" and p["observer"]["vantage"] != "sink_side":
            raise Rej("observer-not-at-sink", "5.5")


def check_statement_obj(st):
    """Rule 1 to the end for a statement already parsed. Returns (name, predicate)."""
    name, p = check_statement(st)
    try:
        rule2(name, p)
    except (KeyError, TypeError, AttributeError) as e:
        raise Rej("predicate-malformed", "4.4", "shape: %r" % (e,))
    rule3(name, p)
    type_rules(name, p)
    return name, p


def check_record_bytes(raw):
    """One record as statement bytes (as carried in the DSSE payload)."""
    try:
        st = parse(raw)
        name, _ = check_statement_obj(st)
        return {"verdict": "accept", "reason": TYPES[name][1], "type": TYPES[name][0]}
    except Rej as r:
        return {"verdict": "reject", "reason": r.code, "section": r.section, "text": r.text}


# ------------------------------------------------ 6 Bundles
def check_bundle(items):
    """items: list of (file_name, raw_bytes) in file-name order (reading L-ORD)."""
    recs = []
    for fn, raw in items:
        try:
            st = parse(raw)
            name, p = check_statement_obj(st)
        except Rej as r:  # B1
            return {"verdict": "reject", "reason": r.code, "rule": "B1", "file": fn, "text": r.text}
        recs.append({"fn": fn, "digest": hashlib.sha256(raw).hexdigest(), "type": PREFIX + name, "name": name, "p": p})
    r3 = [r for r in recs if r["name"] == "re-enable-decision"]
    if len(r3) != 1:
        return {"verdict": "reject", "reason": "bundle-without-single-r3", "rule": "6 (reading L-ONE)"}
    by = {}
    for r in recs:
        by.setdefault(r["digest"], []).append(r)
    for r in recs:  # B2
        for pr in r["p"].get("predecessors", []):
            if len(by.get(pr["digest"]["sha256"], [])) != 1:
                return {"verdict": "reject", "reason": "predecessor-not-carried", "rule": "B2", "file": r["fn"]}
    for r in recs:  # B3
        for pr in r["p"].get("predecessors", []):
            if by[pr["digest"]["sha256"]][0]["type"] != pr["predicateType"]:
                return {"verdict": "reject", "reason": "predecessor-type-mismatch", "rule": "B3", "file": r["fn"]}
    # B4 cycle
    def reach(start):
        seen, stack = set(), [start]
        while stack:
            x = stack.pop()
            for pr in x["p"].get("predecessors", []):
                y = by[pr["digest"]["sha256"]][0]
                if y["digest"] == start["digest"]:
                    return True
                if y["digest"] not in seen:
                    seen.add(y["digest"])
                    stack.append(y)
        return False
    for r in recs:
        if reach(r):
            return {"verdict": "reject", "reason": "predecessor-cycle", "rule": "B4", "file": r["fn"]}
    # B5 same incident (reading L-B5: the sets from incident and related intersect with those of the R3)
    def ids(p):
        s = {(p["incident"]["issuer"], p["incident"]["id"])}
        for x in p["incident"].get("related", []):
            s.add((x["issuer"], x["id"]))
        return s
    ref = ids(r3[0]["p"])
    for r in recs:
        if not (ids(r["p"]) & ref):
            return {"verdict": "reject", "reason": "incident-mismatch", "rule": "B5", "file": r["fn"]}
    for r in recs:  # B6
        for pr in r["p"].get("predecessors", []):
            if ts(r["p"]["issuedAt"]) < ts(by[pr["digest"]["sha256"]][0]["p"]["issuedAt"]):
                return {"verdict": "reject", "reason": "predecessor-issued-later", "rule": "B6", "file": r["fn"]}
    # B7 (reading L-B7: appears in population.credentials of an R2)
    swept = set()
    for r in recs:
        if r["name"] == "revocation-sweep":
            swept |= set(r["p"]["population"]["credentials"])
    sc = r3[0]["p"]["restoration"].get("restoredScope")
    if sc:
        for c in sc["credentials"]:
            if c not in swept:
                return {"verdict": "reject", "reason": "restored-credential-unswept", "rule": "B7"}
    return {"verdict": "accept", "reason": "bundle-consistent"}
