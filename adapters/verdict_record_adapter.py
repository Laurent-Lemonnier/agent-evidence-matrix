"""Adapter: draft-wright-verdict-record-02 (published) against its author's examples and vectors.

Three independent readings, none of them the author's checker (vrcheck.py is never run):

 A. Appendix A of the published -02 text.  Unfolds the RFC 8792 blocks, parses the verdict
    records, writes them in the canonical form of Section 2.1, and recomputes every digest
    the text states (2a85c94e..., 62017940..., and the evidence digests the records cite);
    re-runs the Appendix A.2 rule on the cited hop bytes.
 B. The author's byte-level Appendix objects (appendix-objects.json): same digests from the
    author's bytes, and the bytes equal the text's bytes where the text prints them.
 C. The author's 91 vectors: an admission checker written here from Sections 2.1 to 2.3 of
    the -02 text.  It decides one thing, the one the -02 text fixes without any policy: is the
    record refused BEFORE any step runs (and under which section), or does it reach the steps.
    The vector's expected.state/expected.named is compared on that axis only.  Vectors added
    for -03 (a15-a18, g31-g46) are listed apart: -03 is not published (datatracker serves -02).

usage: verdict_record_adapter.py <verdict-record-test-vectors checkout or copy> <draft-02.txt>
"""
import base64
import datetime
import hashlib
import json
import pathlib
import re
import sys


def sha(b):
    return hashlib.sha256(b).hexdigest()


# --------------------------------------------------------- canonical form (2.1)
class Refuse(Exception):
    def __init__(self, section, why):
        self.section, self.why = section, why


def ser_str(s, short_escapes=True):
    out = ['"']
    for ch in s:
        c = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif c < 0x20:
            short = {8: "\\b", 9: "\\t", 10: "\\n", 12: "\\f", 13: "\\r"}
            out.append(short[c] if short_escapes and c in short else "\\u%04x" % c)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def ser(o, short_escapes=True):
    if o is None:
        return "null"
    if o is True:
        return "true"
    if o is False:
        return "false"
    if isinstance(o, int):
        return str(o)
    if isinstance(o, str):
        return ser_str(o, short_escapes)
    if isinstance(o, list):
        return "[" + ",".join(ser(x, short_escapes) for x in o) + "]"
    if isinstance(o, dict):
        return "{" + ",".join(ser_str(k, short_escapes) + ":" + ser(o[k], short_escapes) for k in sorted(o)) + "}"
    raise TypeError(type(o))


def canon(o):
    return ser(o).encode("utf-8")


def max_depth(raw):
    d = best = 0
    in_str = esc = False
    for ch in raw.decode("utf-8"):
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
        elif ch in "{[":
            d += 1
            best = max(best, d)
        elif ch in "}]":
            d -= 1
    return best


def strict_parse(raw):
    """Section 2.1: strict JSON. Raises Refuse('Section 2.1', why)."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise Refuse("Section 2.1", "not valid UTF-8")
    if text.startswith("﻿"):
        raise Refuse("Section 2.1", "byte-order mark")

    def pairs(ps):
        seen = {}
        for k, v in ps:
            if k in seen:
                raise Refuse("Section 2.1", f"member {k!r} twice")
            seen[k] = v
        return seen

    def bad_float(s):
        raise Refuse("Section 2.1", f"number {s!r} is not an integer")

    def bad_const(s):
        raise Refuse("Section 2.1", f"constant {s}")

    try:
        obj = json.loads(text, object_pairs_hook=pairs, parse_float=bad_float, parse_constant=bad_const)
    except Refuse:
        raise
    except ValueError as e:
        raise Refuse("Section 2.1", f"not JSON: {e}")
    if max_depth(raw) > 32:
        raise Refuse("Section 2.1", "nested deeper than 32")

    def walk(o):
        if isinstance(o, str):
            if any(0xD800 <= ord(c) <= 0xDFFF for c in o):
                raise Refuse("Section 2.1", "lone surrogate")
        elif isinstance(o, bool) or o is None:
            pass
        elif isinstance(o, int):
            if abs(o) > 2 ** 53 - 1:
                raise Refuse("Section 2.1", "integer out of range")
        elif isinstance(o, list):
            for x in o:
                walk(x)
        elif isinstance(o, dict):
            for k, v in o.items():
                walk(k)
                walk(v)

    walk(obj)
    return obj


TIME_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def valid_time(s):
    if not isinstance(s, str) or not TIME_RE.match(s):
        return False
    try:
        datetime.datetime.strptime(s[:19], "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        return False
    return True


def admit(raw):
    """Return None when the record reaches the steps, else (section, why)."""
    try:
        o = strict_parse(raw)
        # canonical form: re-serializing the parse gives the same bytes. Control-character
        # escapes are not fixed by -02 text (open point I-12): either form is accepted here.
        if raw not in (canon(o), ser(o, short_escapes=False).encode("utf-8")):
            raise Refuse("Section 2.1", "not in canonical form")
        if not isinstance(o, dict):
            raise Refuse("Section 2.2", "record is not an object")
        allowed = {"v", "kind", "key", "version", "supersedes", "writer", "actor", "act_time", "evidence", "check", "body"}
        extra = set(o) - allowed
        if extra:
            raise Refuse("Section 2.2", f"member {sorted(extra)} not allowed")
        for m in ("v", "kind", "key", "version", "writer", "body"):
            if m not in o:
                raise Refuse("Section 2.2", f"{m} missing")
        if o["v"] != "verdict-record/1":
            raise Refuse("Section 2.2", "v is not verdict-record/1")
        if not isinstance(o["kind"], str):
            raise Refuse("Section 2.2", "kind not a string")
        if not isinstance(o["key"], str) or not o["key"]:
            raise Refuse("Section 2.2", "key empty or not a string")
        v = o["version"]
        if isinstance(v, bool) or not isinstance(v, int) or v < 1:
            raise Refuse("Section 2.2", "version not an integer of 1 or more")
        if "supersedes" in o:
            s = o["supersedes"]
            if v == 1 and s is not None:
                raise Refuse("Section 2.2", "supersedes on version 1")
            if v > 1:
                if s is None:
                    raise Refuse("Section 2.2", "version above 1 with supersedes null")
                if not isinstance(s, str) or not HEX64.match(s):
                    raise Refuse("Section 2.1", "supersedes is not lowercase hex digest")
        elif v > 1:
            raise Refuse("Section 2.2", "version above 1 without supersedes")
        if not isinstance(o["writer"], str) or not o["writer"]:
            raise Refuse("Section 2.2", "writer empty or not a string")
        if "actor" in o:
            a = o["actor"]
            if not isinstance(a, dict) or a.get("type") not in ("person", "system") or not isinstance(a.get("id"), str):
                raise Refuse("Section 2.2", "actor malformed")
            if a["type"] == "system":
                if not isinstance(a.get("model"), str) or not isinstance(a.get("model_version"), str):
                    raise Refuse("Section 2.2", "system actor without model and model_version")
            elif set(a) != {"type", "id"}:
                raise Refuse("Section 2.2", "person actor with extra members")
        if "act_time" in o and not valid_time(o["act_time"]):
            raise Refuse("Section 2.1", "act_time not YYYY-MM-DDTHH:MM:SS.ffffffZ")
        b = o["body"]
        if not isinstance(b, dict):
            raise Refuse("Section 2.2", "body not an object")
        if "claim" not in b:
            raise Refuse("Section 2.3", "body.claim missing")
        c = b["claim"]
        if not isinstance(c, dict) or len(c) != 1 or set(c) - {"text", "ref"}:
            raise Refuse("Section 2.3", "claim is not exactly one of text, ref")
        if "text" in c and not isinstance(c["text"], str):
            raise Refuse("Section 2.3", "claim.text not a string")
        if "ref" in c:
            r = c["ref"]
            if not isinstance(r, dict) or set(r) != {"sha256", "format"} or not isinstance(r["format"], str):
                raise Refuse("Section 2.3", "claim.ref is not an evidence entry")
            if not isinstance(r["sha256"], str) or not HEX64.match(r["sha256"]):
                raise Refuse("Section 2.1", "claim.ref sha256 not lowercase hex")
            ev = o.get("evidence")
            # -02 Section 2.3: "the same entry MUST also appear in evidence" - a MUST on the record;
            # whether that is refused before the steps is not stated in -02.
            if not (isinstance(ev, list) and r in ev):
                return ("reaches-steps", "claim.ref not in evidence: -02 does not say refuse-before-steps")
        return None
    except Refuse as r:
        return (r.section, r.why)


# ------------------------------------------------------------ Appendix A (text)
def unfold(lines):
    out, cur = [], ""
    for l in lines:
        s = l.strip() if not cur else l.strip()
        if s.endswith("\\"):
            cur += s[:-1]
        else:
            out.append(cur + s)
            cur = ""
    if cur:
        out.append(cur)
    return out


def appendix_blocks(txt):
    a = txt.index("Appendix A.  Examples", txt.index("Appendix A.  Examples") + 30)
    b = txt.index("Appendix B.  Open Questions", a)
    keep = []
    for l in txt[a:b].splitlines():
        if l.startswith("Wright   ") or l.startswith("Internet-Draft  ") or "\f" in l:
            continue
        keep.append(l)
    blocks, i = [], 0
    while i < len(keep):
        if keep[i].strip().startswith("=============== NOTE:"):
            j = i + 1
            depth, body, started = 0, [], False
            while j < len(keep):
                t = keep[j]
                if t.strip():
                    body.append(t)
                    # bracket balance on the unfolded text so far (no braces inside these strings)
                    for ch in t.strip().rstrip("\\"):
                        depth += ch in "{[" ; depth -= ch in "}]"
                    started = True
                    if started and depth == 0 and not t.strip().endswith("\\"):
                        break
                j += 1
            blocks.append(unfold(body))
            i = j
        i += 1
    return blocks


OUT = []


def emit(case, verdict, detail):
    OUT.append(verdict)
    print(f"{case}\t{verdict}\t{detail}")


def appendix_a(txt, objs):
    blocks = appendix_blocks(txt)
    if len(blocks) != 5:
        emit("A/blocks", "cannot-tell", f"expected 5 folded blocks in Appendix A, found {len(blocks)}")
        return
    claim_line = blocks[0]
    assert len(claim_line) == 1
    claim_bytes = claim_line[0].encode("utf-8")
    rec1 = json.loads("".join(blocks[1]))
    parent_bytes = blocks[2][0].encode("utf-8")
    child_bytes = blocks[3][0].encode("utf-8")
    rec2 = json.loads("".join(blocks[4]))
    stated = re.sub(r"\s+", "", txt[txt.index("A.1.  A Model Decision"):])
    for name, rec, stated_digest in (("A.1", rec1, "2a85c94e39c56f50185b3b69b8f56026946364631799774a83b4f93399841c45"),
                                     ("A.2", rec2, "62017940a8ddddd5ddd7ff46c8ff2a6ce79dfcccb775d767b8dff8db0ebe19ed")):
        got = sha(canon(rec))
        emit(f"{name}/record-digest", "agrees" if got == stated_digest else "contradicted",
             f"sha256(canonical record) {got} vs stated {stated_digest}")
        emit(f"{name}/stated-digest-in-text", "agrees" if stated_digest in stated else "contradicted", "digest printed in the text")
        emit(f"{name}/record-admitted", "agrees" if admit(canon(rec)) is None else "contradicted",
             "canonical bytes reach the steps (no refusal under Sections 2.1 to 2.3)")
    for nm, raw in (("claim record", claim_bytes), ("parent hop", parent_bytes), ("child hop", child_bytes)):
        o = strict_parse(raw)
        emit(f"A/{nm.replace(' ', '-')}-is-canonical", "agrees" if canon(o) == raw else "contradicted",
             "item bytes equal their own canonical form (A.2 says the hops are already in JCS form)")
    emit("A.1/evidence0-digest", "agrees" if sha(claim_bytes) == rec1["evidence"][0]["sha256"] == rec1["body"]["claim"]["ref"]["sha256"] else "contradicted",
         f"sha256(claim record) {sha(claim_bytes)} equals evidence[0].sha256 and body.claim.ref.sha256")
    emit("A.1/evidence1-item-not-in-text", "cannot-tell",
         f"evidence[1] {rec1['evidence'][1]['sha256']} cites draft-gruszka-signed-evaluation-receipts; the text prints no bytes for it")
    emit("A.2/evidence0-digest", "agrees" if sha(parent_bytes) == rec2["evidence"][0]["sha256"] else "contradicted",
         f"sha256(parent hop) {sha(parent_bytes)}")
    emit("A.2/evidence1-digest", "agrees" if sha(child_bytes) == rec2["evidence"][1]["sha256"] else "contradicted",
         f"sha256(child hop) {sha(child_bytes)}")
    parent, child = json.loads(parent_bytes), json.loads(child_bytes)
    inputs = {
        "parent_digest": sha(parent_bytes),
        "parent_hash": child["parent_record_hash"],
        "parent_scopes": parent["granted_scopes"],
        "child_scopes": child["granted_scopes"],
    }
    # inputs bound by pointer exactly as the record's check.inputs says
    bound = {}
    for name, spec in rec2["check"]["inputs"].items():
        item = json.loads([parent_bytes, child_bytes][spec["evidence"]])
        if "pointer" in spec:
            node = item
            for part in spec["pointer"].lstrip("/").split("/"):
                node = node[part]
            bound[name] = node
        else:
            bound[name] = sha([parent_bytes, child_bytes][spec["evidence"]])
    emit("A.2/bound-inputs-resolve", "agrees" if bound == inputs else "contradicted", "check.inputs pointers read the cited bytes")
    linked = bound["parent_hash"] == bound["parent_digest"]
    attenuated = all(s in bound["parent_scopes"] for s in bound["child_scopes"])
    result = "attenuated_and_linked" if linked and attenuated else "not_attenuated_or_not_linked"
    emit("A.2/rule-rerun", "agrees" if result == rec2["check"]["result"] else "contradicted",
         f"rule re-run gives {result}; record states {rec2['check']['result']}")
    widened = dict(child, granted_scopes=child["granted_scopes"] + ["mcp:max_rows:100000"])
    w_att = all(s in parent["granted_scopes"] for s in widened["granted_scopes"])
    emit("A.2/widened-child-gives-different-result", "agrees" if not w_att else "contradicted",
         "text: if the child hop widened the scopes the re-run would give a different result (checked on a widened copy)")

    # ---- B. author's appendix-objects.json
    if objs is not None:
        def b64items(k):
            return [base64.b64decode(i["b64"]) for i in objs[k]["items"]]
        a1, a2 = b64items("A.1"), b64items("A.2")
        emit("B/A.2-parent-bytes-equal-text", "agrees" if a2[0] == parent_bytes else "contradicted", "author's bytes equal the text's bytes")
        emit("B/A.2-child-bytes-equal-text", "agrees" if a2[1] == child_bytes else "contradicted", "author's bytes equal the text's bytes")
        emit("B/A.1-claim-bytes-equal-text", "agrees" if a1[0] == claim_bytes else "contradicted", "author's bytes equal the text's bytes")
        same = sha(a1[1]) == rec1["evidence"][1]["sha256"]
        emit("B/A.1-second-item-vs-text", "agrees" if same else "cannot-tell",
             f"author's second A.1 item has sha256 {sha(a1[1])}; the -02 text cites {rec1['evidence'][1]['sha256']}"
             + ("" if same else ": the repository is at -03, which replaced this item (README), so -02's cited digest has no published bytes"))


# --------------------------------------------------------------- vectors (C)
# a15-a18 and g31-g46 were added for -03 (author README, "The vectors a01-f01 ... a15-a18 and g31-g46 were added for -03");
# c11 is listed with them because README open point I-2 says -02 reads claim.ref-not-in-evidence as a step 2 FAIL and -03 settled it.
V03 = re.compile(r"^(a1[5-8]|c11|g3[1-9]|g4[0-6])-")


def vectors(root):
    rows = []
    for p in sorted(pathlib.Path(root).glob("[a-h][0-9][0-9]-*.json")):
        d = json.loads(p.read_text())
        raw = base64.b64decode(d["record_b64"])
        e = d["expected"]
        state, named = e["state"], e.get("named")
        want = named if state == "refused" and isinstance(named, str) and named.startswith("Section") else "reaches-steps"
        res = admit(raw)
        got = "reaches-steps" if res is None else (res[0] if res[0] != "reaches-steps" else "reaches-steps")
        rows.append((p.stem, want, got, res[1] if res else "", bool(V03.match(p.name)), d.get("depends_on_interpretation") or ""))
    return rows


def main(root, draft):
    root = pathlib.Path(root)
    txt = pathlib.Path(draft).read_text()
    objs_path = root / "appendix-objects.json"
    objs = json.loads(objs_path.read_text()) if objs_path.exists() else None
    appendix_a(txt, objs)
    rows = vectors(root)
    n = len(rows)
    ok02 = [r for r in rows if not r[4]]
    ok03 = [r for r in rows if r[4]]
    for name, want, got, why, is03, interp in rows:
        v = "agrees" if want == got else "contradicted"
        tag = "-03-only" if is03 else ("open:" + interp if interp else "-02")
        emit(f"vec/{name}", v, f"expected pre-step outcome {want}; adapter {got}" + (f" ({why})" if why else "") + f" [{tag}]")
    a02 = sum(r[1] == r[2] for r in ok02)
    a03 = sum(r[1] == r[2] for r in ok03)
    print(f"VECTORS\ttotal={n}\tvectors-of--02={len(ok02)} agree={a02}\tvectors-added-for--03={len(ok03)} agree={a03}")
    print(f"SUMMARY\tagrees={OUT.count('agrees')}\tcontradicted={OUT.count('contradicted')}\tcannot-tell={OUT.count('cannot-tell')}\ttotal={len(OUT)}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
