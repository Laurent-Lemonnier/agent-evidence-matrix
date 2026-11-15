"""Adapter: AER-1 (draft-zambo-aer1-26) verifier rules recomputed from the draft text,
run over the AER-1 conformance kit's own vectors, compared case by case with the
kit's expected outcome.

Usage:  python -I aer1_adapter.py <path-to-kit-checkout>
The kit checkout is read only. Nothing from the kit's runner is imported or executed;
every check below is written from the draft text (sections named in comments). Where the
draft is silent and the kit's vectors define the rule (marked KIT-CONVENTION), the rule is
taken from the vector's own description and the line says so.

Output: one line per check, `[family] name: OK|DIFF expect=... got=...`, then a summary.
"""
import base64
import binascii
import hashlib
import json
import re
import sys
from pathlib import Path

# --------------------------------------------------------------------------------------
# Section 7.1 serializer: member names sorted by code point, no whitespace outside strings,
# strings escaped like Python json.dumps(ensure_ascii=True) with the draft's listed escapes.
# --------------------------------------------------------------------------------------
SHORT = {0x22: '\\"', 0x5C: "\\\\", 0x08: "\\b", 0x09: "\\t", 0x0A: "\\n", 0x0C: "\\f", 0x0D: "\\r"}


def ser_str(s):
    out = ['"']
    for ch in s:
        cp = ord(ch)
        if cp in SHORT:
            out.append(SHORT[cp])
        elif 0x20 <= cp <= 0x7E:
            out.append(ch)
        elif cp > 0xFFFF:
            cp -= 0x10000
            out.append("\\u%04x\\u%04x" % (0xD800 + (cp >> 10), 0xDC00 + (cp & 0x3FF)))
        else:
            out.append("\\u%04x" % cp)
    out.append('"')
    return "".join(out)


def ser(v):
    if v is True:
        return "true"
    if v is False:
        return "false"
    if v is None:
        return "null"
    if isinstance(v, str):
        return ser_str(v)
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        if v.is_integer() and abs(v) < 1e15:
            return str(int(v))
        return json.dumps(v)  # the draft fixes no float form beyond integer seq
    if isinstance(v, list):
        return "[" + ",".join(ser(x) for x in v) + "]"
    if isinstance(v, dict):
        return "{" + ",".join(ser_str(k) + ":" + ser(v[k]) for k in sorted(v)) + "}"
    raise TypeError(type(v))


def sha_hex(b):
    return hashlib.sha256(b).hexdigest()


# --------------------------------------------------------------------------------------
# Parsing with duplicate-member detection (Section 6, structural rule 1).
# --------------------------------------------------------------------------------------
def parse(text):
    dups = []

    def hook(pairs):
        seen = set()
        for k, _ in pairs:
            if k in seen:
                dups.append(k)
            seen.add(k)
        return dict(pairs)

    return json.loads(text, object_pairs_hook=hook), (dups[0] if dups else None)


# --------------------------------------------------------------------------------------
# RFC 3339 (Table 1: created_at "in RFC3339 format ... valid calendar date and time",
# reject seconds=60). RFC 3339 section 5.6 ABNF; T and Z may be lower case per its NOTE.
# --------------------------------------------------------------------------------------
TS = re.compile(
    r"([0-9]{4})-([0-9]{2})-([0-9]{2})[Tt]([0-9]{2}):([0-9]{2}):([0-9]{2})(\.[0-9]+)?"
    r"([Zz]|[+-]([0-9]{2}):([0-9]{2}))"
)


def valid_ts(s):
    if not isinstance(s, str):
        return False
    m = TS.fullmatch(s)
    if not m:
        return False
    y, mo, d, hh, mi, ss = (int(m.group(i)) for i in range(1, 7))
    if not (1 <= mo <= 12 and hh <= 23 and mi <= 59 and ss <= 59):
        return False
    if m.group(9) is not None and not (int(m.group(9)) <= 23 and int(m.group(10)) <= 59):
        return False
    leap = y % 4 == 0 and (y % 100 != 0 or y % 400 == 0)
    dim = [31, 29 if leap else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][mo - 1]
    return 1 <= d <= dim


UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
UUID4 = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
B64 = re.compile(r"[A-Za-z0-9+/]*={0,2}")
NIL = "00000000-0000-0000-0000-000000000000"
# Second reading, selected with --kit-reading: a 0.4 receipt that carries no metadata_hash is not failed
# (the kit's own stated rule). The default reading is draft -26 Section 6 step 4 verbatim:
# 'A "0.4" receipt without metadata_hash MUST fail.'
KIT_READING = False
ERRATA_READING = False


def version_tuple(s):
    # Table 1: versions compare numerically by dot-separated components.
    if not isinstance(s, str) or not re.fullmatch(r"[0-9]+(\.[0-9]+)*", s):
        return None
    return tuple(int(x) for x in s.split("."))


def prov_ok(p):
    # Section 5: three classes; "EXECUTED BY <system>"; no control characters U+0000-U+001F, U+007F.
    if not isinstance(p, str) or any(ord(c) <= 0x1F or ord(c) == 0x7F for c in p):
        return False
    if p in ("OBSERVED VIA GATEWAY", "LOGGED BY AGENT"):
        return True
    return p.startswith("EXECUTED BY ") and len(p) > len("EXECUTED BY ") and p[12:].strip() == p[12:] != ""


def decode_payload(cb):
    """Section 4: canonical base64 with standard padding and zero pad bits; strict UTF-8."""
    if not isinstance(cb, str) or not B64.fullmatch(cb):
        return None, "B64"
    try:
        raw = base64.b64decode(cb, validate=True)
    except (binascii.Error, ValueError):
        return None, "B64"
    if base64.b64encode(raw).decode("ascii") != cb:
        return raw, "B64CANON"
    try:
        raw.decode("utf-8")
    except UnicodeDecodeError:
        return None, "UTF8"
    return raw, None


def meta_block(r):
    # Section 3.1: exactly created_at, id, output_hash, provenance_class, receipt_schema_version, tool{name,scope,version}
    t = r.get("tool")
    if not isinstance(t, dict):
        return None
    keys = ("created_at", "id", "output_hash", "provenance_class", "receipt_schema_version")
    if not all(isinstance(r.get(k), str) for k in keys):
        return None
    if not all(isinstance(t.get(k), str) for k in ("name", "scope", "version")):
        return None
    blk = {k: r[k] for k in keys}
    blk["tool"] = {k: t[k] for k in ("name", "scope", "version")}
    return blk


def legacy_production(r):
    # Section 6 step 4 legacy forms: created_at carried by "timestamp"; tool a bare string naming the tool.
    return ("created_at" not in r and isinstance(r.get("timestamp"), str)
            and isinstance(r.get("tool"), str) and r.get("tool") != "")


def check_receipt(r, dup):
    """Return (reasons[(code,text)], notes[str]). Empty reasons means the receipt verifies."""
    why, notes = [], []
    if dup is not None:
        why.append(("DUP", "duplicate member name: %s" % dup))
    if not isinstance(r, dict):
        return why + [("MISSING", "receipt is not a JSON object")], notes
    lp = legacy_production(r)
    need = ["id", "receipt_schema_version", "tool", "provenance_class", "canonical_bytes",
            "output_hash", "verification_status"]
    need.append("timestamp" if lp else "created_at")
    for m in need:
        if m not in r:
            why.append(("MISSING", "missing required member: %s" % m))
    if why:
        return why, notes
    rid = r["id"]
    if not isinstance(rid, str) or not UUID.fullmatch(rid):
        why.append(("ID", "id is not a lowercase UUID-shaped string"))
    elif rid == NIL:
        why.append(("ID", "id is the nil UUID"))
    ver = r["receipt_schema_version"]
    vt = version_tuple(ver)
    if vt is None:
        why.append(("VERSION", "receipt_schema_version is not a dotted numeric string"))
    created = r["timestamp"] if lp else r["created_at"]
    if not valid_ts(created):
        why.append(("TIME", "created_at is not a valid RFC 3339 calendar date and time"))
    tool = r["tool"]
    if lp:
        notes.append("tool read in legacy bare-string form")
        notes.append("created_at read from legacy timestamp member")
    elif not (isinstance(tool, dict) and all(isinstance(tool.get(k), str) and tool[k] != ""
                                                for k in ("name", "version", "scope"))):
        why.append(("TOOL", "tool is not an object with non-empty name, version and scope strings"))
    if not prov_ok(r["provenance_class"]):
        why.append(("PROV", "provenance_class is not one of the three Section 5 classes"))
    raw, err = decode_payload(r["canonical_bytes"])
    if err == "B64":
        why.append(("B64", "canonical_bytes is not valid base64"))
    elif err == "B64CANON":
        why.append(("B64", "canonical_bytes is not the canonical base64 spelling"))
    elif err == "UTF8":
        why.append(("UTF8", "canonical_bytes is not valid UTF-8"))
    oh = r["output_hash"]
    if not isinstance(oh, str) or not DIGEST.fullmatch(oh):
        why.append(("HASHFMT", "output_hash is not sha256: plus 64 lowercase hex"))
    elif raw is not None and err is None and oh != "sha256:" + sha_hex(raw):
        why.append(("HASHMISMATCH", "output_hash differs from sha256 of the decoded canonical_bytes"))
    mh = r.get("metadata_hash")
    if vt is not None and vt >= (0, 4) and mh is None and not KIT_READING:
        # Table 1 and Section 6 step 4: a "0.4" receipt without metadata_hash MUST fail.
        why.append(("METAMISSING", "receipt_schema_version %s requires metadata_hash" % ver))
    if mh is not None:
        if not isinstance(mh, str) or not DIGEST.fullmatch(mh):
            why.append(("METAHASH", "metadata_hash is not sha256: plus 64 lowercase hex"))
        else:
            blk = meta_block(r)
            if blk is None:
                why.append(("METAHASH", "metadata block cannot be rebuilt from stored members"))
            elif mh != "sha256:" + sha_hex(ser(blk).encode("utf-8")):
                why.append(("METAHASH", "metadata_hash differs from the recomputed Section 3.1 block"))
    # Section 3.3 input commitment. KIT-CONVENTION layout: Section 7.1 serialization of the
    # payload's "inputs" member; not evaluated when the payload records no "inputs".
    ih = r.get("input_hash")
    if ih is not None:
        if not isinstance(ih, str) or not DIGEST.fullmatch(ih):
            why.append(("INPUTHASH", "input_hash is not sha256: plus 64 lowercase hex"))
        elif raw is not None and err is None:
            try:
                payload = json.loads(raw.decode("utf-8"))
            except ValueError:
                payload = None
            if isinstance(payload, dict) and "inputs" in payload:
                if ih != "sha256:" + sha_hex(ser(payload["inputs"]).encode("utf-8")):
                    why.append(("INPUTHASH", "input_hash differs from the serialized recorded inputs"))
    vs = r["verification_status"]
    if lp:
        if not isinstance(vs, str) or vs == "":
            why.append(("STATUS", "verification_status is not a non-empty string"))
        else:
            notes.append("verification_status %r read as a producer claim" % vs)
    elif vs != "verified":
        why.append(("STATUS", "verification_status is not verified"))
    # Section 6 step 4 legacy acceptance: schema below 0.4 and no metadata_hash.
    legacy_version = None
    if raw is not None and err is None:
        try:
            pl = json.loads(raw.decode("utf-8"))
        except ValueError:
            pl = None
        if isinstance(pl, dict):
            legacy_version = pl.get("receipt_schema_version")
    eff = legacy_version if legacy_version is not None else ver
    is_legacy = str(eff) in ("0.2", "0.3")
    if is_legacy:
        notes.append("legacy acceptance; id, tool, version, scope, creation time and provenance are not bound to the commitment")
        return why, notes
    # KIT-CONVENTION (draft Section 6 names these as "the Section 6 metadata checks" only by reference to the
    # corpus): version agreement and provenance binding against the committed payload.
    if raw is not None and err is None:
        try:
            pl = json.loads(raw.decode("utf-8"))
        except ValueError:
            pl = None
        inner = pl.get("receipt_schema_version") if isinstance(pl, dict) else None
        if inner is None or ver is None:
            why.append(("BIND_VERSION", "receipt_schema_version: one side missing"))
        elif str(inner) != str(ver):
            why.append(("BIND_VERSION", "receipt_schema_version: outer %s differs from committed %s" % (ver, inner)))
        ic = pl.get("issuer_claims") if isinstance(pl, dict) else None
        committed = ic.get("provenance_class") if isinstance(ic, dict) else None
        if committed is None:
            why.append(("BIND_PROV", "provenance binding: committed provenance_class missing"))
        elif committed != r["provenance_class"]:
            why.append(("BIND_PROV", "provenance binding: outer differs from committed"))
    return why, notes


def profile_check(r):
    # KIT-CONVENTION reference-producer profile: payload is a JSON object carrying "inputs".
    raw, err = decode_payload(r.get("canonical_bytes"))
    if err is not None or raw is None:
        return False
    try:
        pl = json.loads(raw.decode("utf-8"))
    except ValueError:
        return False
    return isinstance(pl, dict) and "inputs" in pl


# --------------------------------------------------------------------------------------
# Anchors. KIT-CONVENTION: the anchored profile {log, leaf_hash, anchored_at, proof} is described only
# in the vectors; draft -26 Section 10 defines a different envelope (type aer1-anchor), none exercised.
# --------------------------------------------------------------------------------------
PROFILE = {"log", "leaf_hash", "anchored_at", "proof"}


def anchor_present(r):
    a = r.get("anchor") if isinstance(r, dict) else None
    return isinstance(a, dict) and bool(set(a) & PROFILE)


def anchor_report(r, evaluate=True):
    if not anchor_present(r):
        return "absent", False, False
    if not evaluate:
        return "not checked", True, False
    a = r["anchor"]
    log = a.get("log")
    if isinstance(log, str):
        m = re.match(r"[A-Za-z][A-Za-z0-9+.-]*://([^/?#]+)", log)
        if m and m.group(1).rsplit("@", 1)[-1].split(":")[0].lower().endswith(".invalid"):
            return "rejected: unresolvable record", True, True  # RFC 2606: cannot resolve
    bad = set(a) != PROFILE
    bad |= not (isinstance(log, str) and log)
    raw, err = decode_payload(r.get("canonical_bytes"))
    leaf = a.get("leaf_hash")
    bad |= not (isinstance(leaf, str) and DIGEST.fullmatch(leaf)) or raw is None or leaf != "sha256:" + sha_hex(raw)
    bad |= not valid_ts(a.get("anchored_at"))
    bad |= not isinstance(a.get("proof"), dict)
    bad |= not (isinstance(r.get("id"), str) and UUID4.fullmatch(r["id"]))  # strict tier: UUID v4
    return ("verification failed" if bad else "verified"), True, True


# --------------------------------------------------------------------------------------
# Section 8.1 Merkle roots.
# --------------------------------------------------------------------------------------
def merkle(leaf_inputs):
    if not leaf_inputs:
        return sha_hex(b"")  # steps are non-empty in the draft; the empty vector defines this (kit)
    level = [hashlib.sha256(x.encode("utf-8")).digest() for x in leaf_inputs]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [hashlib.sha256(level[i] + level[i + 1]).digest() for i in range(0, len(level), 2)]
    return level[0].hex()


def workflow_root(steps, version):
    if version == "receipt-id-v0":
        return merkle([s["receipt_id"] for s in steps])
    if version == "seq-output-v1":
        leaves = []
        for s in steps:
            oh = s.get("output_hash")
            if not (isinstance(oh, str) and re.fullmatch(r"[0-9a-f]{64}", oh)):
                return None  # leaf cannot be formed: fail closed
            leaves.append("%d:%s" % (s["seq"], oh))
        return merkle(leaves)
    return None


def workflow_verdict(ids, root):
    # Section 8.2 steps 3-4 (offline parts): seq 1..n (constructed), unique receipt_id, root recomputes.
    if len(set(ids)) != len(ids):
        return "invalid", "duplicate receipt_id"
    if merkle(ids) != root:
        return "invalid", "merkle_root mismatch"
    return "valid", ""


# --------------------------------------------------------------------------------------
# Section 7 chains.
# --------------------------------------------------------------------------------------
def is_int_valued(x):
    return not isinstance(x, bool) and (isinstance(x, int) or (isinstance(x, float) and x.is_integer()))


def entry_digest_07(e):
    raw = base64.b64decode(e["canonical_bytes"], validate=True)
    seq = int(e["seq"])
    obj = {"close": e.get("close", False), "id": e["id"], "job_id": e["job_id"],
           "output_hash": sha_hex(raw), "prev_digest": e["prev_digest"],
           "provenance_class": e["provenance_class"], "seq": seq, "tool": e["tool"]}
    return sha_hex(ser(obj).encode("utf-8"))


def verify_chain_07(tl):
    if not isinstance(tl, list) or not tl:
        return ["empty timeline"]
    why, prev, job = [], None, None
    for i, e in enumerate(tl):
        if not isinstance(e, dict):
            return ["entry %d is not an object" % i]
        cb = e.get("canonical_bytes")
        if not isinstance(cb, str) or not B64.fullmatch(cb):
            return ["entry %d canonical_bytes is not valid base64" % i]
        try:
            base64.b64decode(cb, validate=True)
        except (binascii.Error, ValueError):
            return ["entry %d canonical_bytes is not valid base64" % i]
        for m in ("id", "tool", "provenance_class", "job_id", "prev_digest"):
            if not isinstance(e.get(m), str) or e[m] == "":
                return ["entry %d missing %s" % (i, m)]
        if not is_int_valued(e.get("seq")):
            return ["entry %d seq is not an integer" % i]
        if int(e["seq"]) != i + 1:
            why.append("entry %d seq breaks contiguity" % i)
        job = job if job is not None else e["job_id"]
        if e["job_id"] != job:
            why.append("entry %d mixes jobs" % i)
        if i == 0:
            if e["prev_digest"] != "0" * 64:
                why.append("entry 0 prev_digest is not the zero digest")
        elif e["prev_digest"] != prev:
            why.append("entry %d prev_digest does not match" % i)
        if "close" in e and not isinstance(e["close"], bool):
            why.append("entry %d close is not a boolean" % i)
        elif i < len(tl) - 1 and e.get("close") is True:
            why.append("entry %d closes before the last entry" % i)
        prev = entry_digest_07(e)
    if tl[-1].get("close") is not True:
        why.append("last entry is not closing")
    return why


def verify_chain_06(tl):
    # Historical -06 construction (Section 7.4: digest over the base64-decoded canonical_bytes only).
    if not isinstance(tl, list) or not tl:
        return ["empty timeline"]
    why, prev = [], None
    for i, e in enumerate(tl):
        cb = e.get("canonical_bytes") if isinstance(e, dict) else None
        if not isinstance(cb, str) or not B64.fullmatch(cb):
            return ["entry %d canonical_bytes is not valid base64" % i]
        try:
            raw = base64.b64decode(cb, validate=True)
        except (binascii.Error, ValueError):
            return ["entry %d canonical_bytes is not valid base64" % i]
        pd = e.get("prev_digest")
        if i == 0:
            if pd != "0" * 64:
                why.append("entry 0 prev_digest is not the zero digest")
        elif pd != prev:
            why.append("entry %d prev_digest does not match" % i)
        prev = sha_hex(raw)
    if tl[-1].get("close") is not True:
        why.append("last entry is not closing")
    return why


def verify_commitment(tl, c):
    # Section 7.3: job_id, final_entry_digest (64 lowercase hex), entry_count (JSON number with an
    # integer value), published_at (RFC 3339 valid date and time).
    if not isinstance(tl, list) or not tl:
        return ["empty timeline"]
    if not isinstance(c, dict):
        return ["commitment is not an object"]
    why = []
    jid, fed, cnt, pub = (c.get(k) for k in ("job_id", "final_entry_digest", "entry_count", "published_at"))
    if not (isinstance(jid, str) and jid):
        why.append("job_id")
    if not (isinstance(fed, str) and re.fullmatch(r"[0-9a-f]{64}", fed)):
        why.append("final_entry_digest")
    if not is_int_valued(cnt) or (ERRATA_READING and not (isinstance(cnt, int) and not isinstance(cnt, bool))):
        # ERRATA E-2026-11-15-2: entry_count MUST be encoded as a JSON integer; 5.0 is a mistyped member.
        why.append("entry_count")
    if not valid_ts(pub):
        why.append("published_at")
    if why:
        return ["malformed commitment member: " + ",".join(why)]
    if int(cnt) != len(tl):
        why.append("entry_count differs from timeline length")
    if any(e.get("job_id") != jid for e in tl):
        why.append("job_id differs from the timeline")
    try:
        if entry_digest_07(tl[-1]) != fed:
            why.append("final_entry_digest differs from the recomputed last entry digest")
    except (KeyError, ValueError, binascii.Error, TypeError):
        why.append("final entry digest cannot be recomputed")
    return why


# --------------------------------------------------------------------------------------
# Section 6 id layer.
# --------------------------------------------------------------------------------------
def id_layer(r, expected_id=None, resolved=None):
    why, notes = check_receipt(r, None)
    structural = "pass" if not why else "fail"
    rid = r.get("id") if isinstance(r, dict) else None
    if rid is None:
        return structural, "absent", "fail"
    verdict = "unverified"
    if expected_id is not None:
        verdict = "matched" if rid == expected_id else "mismatched"
    if resolved is not None:
        rec = resolved.get("receipt") if isinstance(resolved.get("receipt"), dict) else resolved
        ok = rec.get("output_hash") == r.get("output_hash") and rec.get("id") in (None, rid)
        if not ok:
            verdict = "mismatched"
        elif verdict != "mismatched":
            verdict = "resolved"
    composite = "fail" if (structural == "fail" or verdict == "mismatched") else "pass"
    return structural, verdict, composite


# --------------------------------------------------------------------------------------
# Kit rejected_by text -> reason code, to compare WHY a vector is rejected, not only that it is.
# --------------------------------------------------------------------------------------
THEIR_CODE = [
    ("duplicate member name", "DUP"), ("not RFC 3339", "TIME"), ("valid calendar", "TIME"),
    ("lowercase UUID", "ID"), ("tool is not an object", "TOOL"), ("provenance_class is not", "PROV"),
    ("canonical_bytes is not valid base64", "B64"), ("not valid UTF-8", "UTF8"),
    ("output_hash is not sha256", "HASHFMT"), ("output_hash does not match", "HASHMISMATCH"),
    ("input_hash does not match", "INPUTHASH"), ("verification_status is not verified", "STATUS"),
    ("missing required member", "MISSING"), ("provenance binding", "BIND_PROV"),
    ("receipt_schema_version: one side", "BIND_VERSION"),
]


def their_code(text):
    for needle, code in THEIR_CODE:
        if needle in text:
            return code
    return None


# --------------------------------------------------------------------------------------
def main(kit):
    kit = Path(kit)
    base = kit / "base"
    rows = []  # (family, name, ok, line)
    extras = []

    def rec(family, name, ok, detail):
        rows.append((family, name, ok))
        print("[%s] %s: %s %s" % (family, name, "OK" if ok else "DIFF", detail))

    def load(p):
        text = Path(p).read_text(encoding="utf-8")
        return parse(text)

    tv = base / "test-vectors"
    # ---- single receipts --------------------------------------------------------------
    for p in sorted((tv / "valid").glob("*.json")):
        r, dup = load(p)
        why, notes = check_receipt(r, dup)
        rec("valid", p.name, not why,
            "expect=accept got=%s%s%s" % ("accept" if not why else "reject",
                                           " notes=" + "|".join(notes) if notes and not why else "",
                                           " reasons=" + "; ".join(t for _, t in why) if why else ""))
    for p in sorted((tv / "invalid").glob("*.json")):
        r, dup = load(p)
        why, _ = check_receipt(r, dup)
        theirs = r.get("rejected_by") if isinstance(r, dict) else None
        tc = their_code(theirs) if isinstance(theirs, str) else None
        codes = {c for c, _ in why}
        ok = bool(why)
        extra = ""
        if ok and tc is not None:
            extra = " reason-code %s %s" % (tc, "present" if tc in codes else "ABSENT (mine: %s)" % ",".join(sorted(codes)))
            if tc not in codes:
                extras.append("%s: kit reason %s, my reasons %s" % (p.name, tc, sorted(codes)))
        rec("invalid", p.name, ok, "expect=reject got=%s%s%s" % (
            "reject" if why else "accept", extra, " first=" + why[0][1] if why else ""))
    for p in sorted((tv / "invalid-profile").glob("*.json")):
        r, dup = load(p)
        why, _ = check_receipt(r, dup)
        prof = profile_check(r)
        rec("profile-invalid", p.name, (not why) and (not prof),
            "expect=core-accept,profile-reject got=core-%s,profile-%s" % ("accept" if not why else "reject",
                                                                          "accept" if prof else "reject"))
    # anchored: KIT-CONVENTION expected outcome by file name (the kit's runner main); core must verify
    exp_by_file = {"anchored-valid.json": "verified", "anchored-unresolvable-anchor.json": "rejected: unresolvable record"}
    for p in sorted((tv / "anchored").glob("*.json")):
        r, dup = load(p)
        why, _ = check_receipt(r, dup)
        out, _, _ = anchor_report(r)
        want = exp_by_file.get(p.name, "verification failed")
        rec("anchored", p.name, (not why) and out == want,
            "expect=core-accept,%s got=core-%s,%s" % (want, "accept" if not why else "reject", out))
    # ---- anchor reports ---------------------------------------------------------------
    av = json.loads((base / "anchor-vectors.json").read_text(encoding="utf-8"))
    for v in av["vectors"]:
        r = load(base / v["file"])[0] if "file" in v else v["receipt"]
        out, pres, ev = anchor_report(r, v["evaluate"])
        ok = (out, pres, ev) == (v["expected_anchor_outcome"], v["expected_present"], v["expected_evaluated"])
        rec("anchor-report", v["name"], ok, "expect=%s/present=%s/evaluated=%s got=%s/present=%s/evaluated=%s" % (
            v["expected_anchor_outcome"], v["expected_present"], v["expected_evaluated"], out, pres, ev))
    # ---- Merkle (Section 8.1) ---------------------------------------------------------
    mv = json.loads((base / "merkle-vectors.json").read_text(encoding="utf-8"))
    for v in mv["vectors"]:
        if "receipt_ids" in v:
            got = merkle(v["receipt_ids"])
        else:
            leaves = [x["preimage"] for x in sorted(v["leaves"], key=lambda x: x["seq"])]
            got = merkle(leaves)
        ok = got == v["expected_root"] and got != v.get("must_not_equal")
        rec("merkle", v["name"], ok, "expect=%s.. got=%s.." % (v["expected_root"][:12], got[:12]))
        if "expected_workflow_verdict" in v:
            verdict, why = workflow_verdict(v["receipt_ids"], v["expected_root"])
            ok2 = verdict == v["expected_workflow_verdict"]
            if ok2 and verdict == "invalid" and v.get("rejected_by"):
                ok2 = v["rejected_by"] in why or why in v["rejected_by"]
            rec("merkle-workflow", v["name"], ok2, "expect=%s got=%s%s" % (
                v["expected_workflow_verdict"], verdict, " (" + why + ")" if why else ""))
    wv = json.loads((kit / "workflow-merkle-seq-output-v1.json").read_text(encoding="utf-8"))
    for v in wv["vectors"]:
        got = workflow_root(v["steps"], v["merkle_version"])
        verdict = "valid" if got == v["merkle_root"] else "invalid"
        rec("workflow-root", v["name"], verdict == v["expected_verdict"], "expect=%s got=%s (%s version)" % (
            v["expected_verdict"], verdict, v["merkle_version"]))
        x = v.get("cross_version_evaluation")
        if x:  # extra check the kit's own runner does not perform
            other = workflow_root(v["steps"], x["merkle_version"])
            xv = "invalid" if (other is None or other != x["must_not_equal"]) else "valid"
            okx = xv == x["expected_verdict"] and (other == x["computed_root"])
            extras.append("EXTRA cross-version %s: root %s under %s, computed_root in vector %s -> %s" % (
                v["name"], other, x["merkle_version"], x["computed_root"], "OK" if okx else "DIFF"))
            rows.append(("xversion-extra", v["name"], okx))
    # ---- chains -----------------------------------------------------------------------
    for fam, fn, fname in (("chain-06", verify_chain_06, "chain-vectors.json"),
                           ("chain-07", verify_chain_07, "chain-vectors-v07.json")):
        for v in json.loads((base / fname).read_text(encoding="utf-8"))["vectors"]:
            why = fn(v["timeline"])
            got = "valid" if not why else "invalid"
            rec(fam, v["name"], got == v["expected_verdict"], "expect=%s got=%s%s" % (
                v["expected_verdict"], got, " first=" + why[0] if why else ""))
            if fam == "chain-06" and not why:
                # Section 7.4: a verifying -06 timeline MUST NOT verify as current (-07 construction).
                w7 = verify_chain_07(v["timeline"])
                okx = bool(w7)
                extras.append("EXTRA %s verifies under -06; under the current construction: %s -> %s" % (
                    v["name"], "rejected" if w7 else "ACCEPTED", "OK" if okx else "DIFF"))
                rows.append(("chain-06-not-current-extra", v["name"], okx))
    for v in json.loads((base / "commitment-vectors.json").read_text(encoding="utf-8"))["vectors"]:
        why = verify_commitment(v["timeline"], v["commitment"])
        got = "valid" if not why else "invalid"
        rec("commitment", v["name"], got == v["expected_verdict"], "expect=%s got=%s%s" % (
            v["expected_verdict"], got, " first=" + why[0] if why else ""))
    # ---- Unicode (Section 4) ----------------------------------------------------------
    for v in json.loads((base / "unicode-vectors.json").read_text(encoding="utf-8"))["vectors"]:
        raw = base64.b64decode(v["payload_base64"], validate=True)
        same = sha_hex(raw) == v["sha256"] and raw.hex() == v["payload_utf8_hex"]
        got = "match" if sha_hex(raw) == v["sha256"] else "mismatch"
        ok = got == v["expected"] and (raw.hex() == v["payload_utf8_hex"])
        rec("unicode", v["name"], ok, "expect=%s got=%s" % (v["expected"], got))
    # ---- id layer (Section 6) ---------------------------------------------------------
    for v in json.loads((base / "id-binding-vectors.json").read_text(encoding="utf-8"))["vectors"]:
        structural, verdict, composite = id_layer(v["receipt"], v.get("expected_id"), v.get("resolved_record"))
        ok = verdict == v["expected_id_verdict"] and composite == v["expected_verdict"]
        rec("id-binding", v["name"], ok, "expect=%s/%s got=%s/%s (structural %s)" % (
            v["expected_id_verdict"], v["expected_verdict"], verdict, composite, structural))
    # ---- summary ----------------------------------------------------------------------
    kit_rows = [r for r in rows if not r[0].endswith("-extra") and r[0] != "xversion-extra"]
    fam = {}
    for f, n, ok in kit_rows:
        a = fam.setdefault(f, [0, 0])
        a[1] += 1
        a[0] += ok
    print()
    for f in sorted(fam):
        print("SUMMARY %-16s %d of %d agree" % (f, fam[f][0], fam[f][1]))
    tot_ok = sum(1 for r in kit_rows if r[2])
    print("SUMMARY TOTAL            %d of %d checks agree with the kit's expected outcome" % (tot_ok, len(kit_rows)))
    for r in kit_rows:
        if not r[2]:
            print("DIFFERS: [%s] %s" % (r[0], r[1]))
    for e in extras:
        print(e)
    return 0


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if a not in ("--kit-reading", "--errata-reading")]
    ERRATA_READING = "--errata-reading" in sys.argv[1:]
    KIT_READING = ERRATA_READING or "--kit-reading" in sys.argv[1:]  # E-1: absent metadata_hash is not failed
    if len(args) != 1:
        print("usage: aer1_adapter.py [--kit-reading | --errata-reading] <kit-checkout>", file=sys.stderr)
        sys.exit(2)
    reading = ("errata ERRATA.md E-2026-11-15-1 and -2 (absent metadata_hash not failed; entry_count must be a JSON integer)" if ERRATA_READING
               else "kit (0.4 without metadata_hash not failed)" if KIT_READING
               else "draft-26 verbatim (0.4 requires metadata_hash)")
    print("READING: %s" % reading)
    sys.exit(main(args[0]))
