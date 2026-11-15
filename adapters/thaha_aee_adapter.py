"""Adapter: recompute the Appendix A test vectors of
draft-thaha-scitt-agent-execution-evidence-02 from the author's own record bytes.

Reads the repository https://github.com/devinwarp/sijil-ietf (vectors/vectors.txt,
vectors/*.cose) and the draft text (-02), and for every value the draft states it
recomputes the value from the record bytes:

  keys           Ed25519 public key from each seed (draft A.1)
  signatures     every COSE_Sign1 in vectors/*.cose, plus the receipt's embedded agent_sig
  digests        Registration, Credential, Serving Party payload digests, the config
                 digest, the policy pack digests, principal digest, principal_link
  chain          record-hash of receipts 0 to 3 and the admission receipt, prev_hash links
  epoch          RFC 9162 Merkle Tree Hash over record-hashes 0 to 2
  call_digest    HTTP binding of Section 6.7

Own CBOR codec (no third-party CBOR package): deterministic encoding per RFC 8949
Section 4.2.1. Ed25519 through the cryptography package.

usage: thaha_aee_adapter.py <sijil-ietf checkout or _raw dir holding vectors/> <draft-02.txt>
Every line: <case>\t<verdict>\t<detail>   verdicts: agrees | contradicted | cannot-tell
"""
import hashlib
import re
import struct
import sys
import pathlib

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature


# ---------------------------------------------------------------- CBOR
class Tag:
    def __init__(self, tag, value):
        self.tag, self.value = tag, value


def _head(major, n):
    if n < 24:
        return bytes([major << 5 | n])
    for ai, fmt in ((24, ">B"), (25, ">H"), (26, ">I"), (27, ">Q")):
        if n < 1 << (8 * struct.calcsize(fmt)):
            return bytes([major << 5 | ai]) + struct.pack(fmt, n)
    raise ValueError("integer too large")


def enc(o):
    """Deterministic CBOR (RFC 8949 4.2.1): shortest ints, map keys sorted by encoding."""
    if o is None:
        return b"\xf6"
    if o is True:
        return b"\xf5"
    if o is False:
        return b"\xf4"
    if isinstance(o, int):
        return _head(0, o) if o >= 0 else _head(1, -1 - o)
    if isinstance(o, bytes):
        return _head(2, len(o)) + o
    if isinstance(o, str):
        b = o.encode("utf-8")
        return _head(3, len(b)) + b
    if isinstance(o, list):
        return _head(4, len(o)) + b"".join(enc(x) for x in o)
    if isinstance(o, dict):
        items = sorted((enc(k), enc(v)) for k, v in o.items())
        return _head(5, len(items)) + b"".join(k + v for k, v in items)
    if isinstance(o, Tag):
        return _head(6, o.tag) + enc(o.value)
    raise TypeError(type(o))


def dec(buf):
    """Decode one CBOR item; refuses trailing bytes and indefinite lengths."""
    v, pos = _dec(buf, 0)
    if pos != len(buf):
        raise ValueError("trailing bytes after item")
    return v


def _dec(b, p):
    ib = b[p]
    major, ai = ib >> 5, ib & 31
    p += 1
    if major == 7 and ai in (20, 21, 22):
        return {20: False, 21: True, 22: None}[ai], p
    if ai < 24:
        n = ai
    elif ai in (24, 25, 26, 27):
        size = 1 << (ai - 24)
        n = int.from_bytes(b[p:p + size], "big")
        p += size
    else:
        if major == 7 and ai in (20, 21, 22):
            return {20: False, 21: True, 22: None}[ai], p
        raise ValueError("indefinite length or unsupported simple value")
    if major == 0:
        return n, p
    if major == 1:
        return -1 - n, p
    if major == 2:
        return bytes(b[p:p + n]), p + n
    if major == 3:
        return b[p:p + n].decode("utf-8"), p + n
    if major == 4:
        out = []
        for _ in range(n):
            x, p = _dec(b, p)
            out.append(x)
        return out, p
    if major == 5:
        out = {}
        for _ in range(n):
            k, p = _dec(b, p)
            v, p = _dec(b, p)
            out[k] = v
        return out, p
    if major == 6:
        v, p = _dec(b, p)
        return Tag(n, v), p
    raise ValueError("unsupported major type")


# ---------------------------------------------- CBOR diagnostic notation
def parse_diag(text):
    toks = re.findall(r"h'[0-9a-fA-F]*'|\"(?:[^\"\\]|\\.)*\"|-?\d+\(|-?\d+|[\[\]{}:,()]|null", text)
    pos = 0

    def val():
        nonlocal pos
        t = toks[pos]
        pos += 1
        if t.startswith("h'"):
            return bytes.fromhex(t[2:-1])
        if t.startswith('"'):
            return t[1:-1]
        if t == "null":
            return None
        if t.endswith("("):
            v = val()
            assert toks[pos] == ")"
            pos += 1
            return Tag(int(t[:-1]), v)
        if t == "[":
            out = []
            while toks[pos] != "]":
                out.append(val())
                if toks[pos] == ",":
                    pos += 1
            pos += 1
            return out
        if t == "{":
            out = {}
            while toks[pos] != "}":
                k = val()
                assert toks[pos] == ":"
                pos += 1
                out[k] = val()
                if toks[pos] == ",":
                    pos += 1
            pos += 1
            return out
        return int(t)

    return val()


def sections(path):
    secs = {}
    for part in re.split(r"^--- ", path.read_text(), flags=re.M)[1:]:
        title, _, body = part.partition("\n")
        # a Tag(18) section ends with ')' which the tokenizer ignores
        secs[title.strip()] = parse_diag(body)
    return secs


# ------------------------------------------------------------- helpers
def sha(b):
    return hashlib.sha256(b).digest()


def dig(b):
    return [-16, sha(b)]


def mth(leaves):
    if len(leaves) == 1:
        return sha(b"\x00" + leaves[0])
    k = 1
    while k * 2 < len(leaves):
        k *= 2
    return sha(b"\x01" + mth(leaves[:k]) + mth(leaves[k:]))


def verify_sign1(cose_item, pk, detached=None):
    """cose_item: Tag(18,[phdr_bstr, uhdr, payload, sig]). Returns (ok, why)."""
    phdr_b, _, payload, sig = cose_item.value
    if payload is None:
        payload = detached
    sig_struct = enc(["Signature1", phdr_b, b"", payload])
    try:
        Ed25519PublicKey.from_public_bytes(pk).verify(sig, sig_struct)
        return True, "ed25519 ok"
    except InvalidSignature:
        return False, "signature does not verify"


def draft_appendix(path):
    txt = path.read_text()
    a = txt.index("Appendix A.  Test Vectors", txt.index("Appendix A.  Test Vectors") + 30)
    b = txt.index("Appendix B.  Mapping", a)
    lines = [
        l for l in txt[a:b].splitlines()
        if not l.startswith("Thaha & Shamsudeen") and not l.startswith("Internet-Draft")
    ]
    return re.sub(r"\s+", "", "".join(lines))


OUT = []


def emit(case, verdict, detail):
    line = f"{case}\t{verdict}\t{detail}"
    OUT.append(verdict)
    print(line)


def show(x):
    if isinstance(x, bytes):
        return x.hex() if len(x) <= 32 else f"{len(x)} bytes, sha256 {sha(x).hex()[:16]}"
    return "structure" if not isinstance(x, (int, str)) else str(x)


def eq_case(case, got, want, what):
    if got == want:
        emit(case, "agrees", f"{what}: {show(got)}")
    else:
        emit(case, "contradicted", f"{what}: recomputed {show(got)} vs stated {show(want)}")


def main(repo, draft):
    repo = pathlib.Path(repo)
    vec = repo / "vectors" if (repo / "vectors").is_dir() else repo
    draft_txt = draft_appendix(pathlib.Path(draft))
    S = sections(vec / "vectors.txt")

    def in_draft(case, h, what):
        hx = h.hex() if isinstance(h, bytes) else h
        if hx in draft_txt:
            emit(case, "agrees", f"{what} stated in draft Appendix A: {hx}")
        else:
            emit(case, "contradicted", f"{what} {hx} not found in draft Appendix A")

    # ---- A.1 keys: seeds -> public keys, vs vectors.txt and draft
    K = S["A.1 Keys"]
    for who in ("harness", "agent", "register", "serving"):
        seed = K[f"{who}_sk_seed"]
        pk = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        eq_case(f"A.1/{who}-pk-from-seed", pk, K[f"{who}_pk"], "public key from seed")
        in_draft(f"A.1/{who}-pk-in-draft", pk, "public key")
    pk = {w: K[f"{w}_pk"] for w in ("harness", "agent", "register", "serving")}

    # ---- COSE_Sign1 files: parse, canonical payload, signature, kid
    cose = {}
    for name, who in (("agent-registration", "register"), ("agent-credential", "harness"),
                      ("execution-receipt-2", "harness"), ("execution-epoch", "harness")):
        raw = (vec / f"{name}.cose").read_bytes()
        item = dec(raw)
        cose[name] = item
        assert isinstance(item, Tag) and item.tag == 18
        eq_case(f"cose/{name}/canonical-encoding", enc(item), raw, "file bytes equal deterministic re-encoding")
        ok, why = verify_sign1(item, pk[who])
        emit(f"cose/{name}/signature", "agrees" if ok else "contradicted", f"{why}; key={who}")
        phdr = dec(item.value[0])
        kid_ok = phdr.get(4) == sha(pk[who])[:8]
        emit(f"cose/{name}/kid", "agrees" if kid_ok else "contradicted", f"kid {phdr.get(4).hex()} == sha256(pk)[:8]")
        pay = dec(item.value[2])
        eq_case(f"cose/{name}/payload-canonical", enc(pay), item.value[2], "payload is deterministic CBOR")

    # ---- A.2 digests
    reg_payload = cose["agent-registration"].value[2]
    reg_d = sha(reg_payload)
    eq_case("A.2/registration-payload-digest", reg_d, S["A.2 Agent Registration Statement payload digest"][1], "sha256(payload) vs vectors.txt")
    in_draft("A.2/registration-payload-digest-in-draft", reg_d, "digest")
    eq_case("A.2/registration-payload-equals-diagnostic", dec(reg_payload), S["A.2 Agent Registration Statement payload"], "decoded payload vs diagnostic form")
    cred_payload = cose["agent-credential"].value[2]
    cred_d = sha(cred_payload)
    eq_case("A.2/credential-payload-digest", cred_d, S["A.2 Agent Credential Statement payload digest"][1], "sha256(payload) vs vectors.txt")
    in_draft("A.2/credential-payload-digest-in-draft", cred_d, "digest")
    cred = dec(cred_payload)
    eq_case("A.2/credential-registration-digest-link", cred[13][1], reg_d, "credential key 13 equals registration digest")
    principal = sha(b"operator-pepper-0001" + b"user:alice@example.com")
    eq_case("A.2/principal-digest", principal, cred[4][2], "sha256(pepper||principal) vs credential key 4")
    eq_case("A.2/credential-agent-key", cred[3][-2], pk["agent"], "COSE key in credential is the agent public key")

    # ---- A.3 config digest
    C = S["A.3 Configuration Integrity entries and digest"]
    names = [e[0].encode() for e in C["entries"]]
    emit("A.3/entries-ordered-by-name-octets", "agrees" if names == sorted(names) else "contradicted", "entries ordered by name (octet order)")
    eq_case("A.3/config-digest", sha(enc(C["entries"])), C["config_digest"][1], "sha256(canonical entries)")
    in_draft("A.3/config-digest-in-draft", C["config_digest"][1], "config_digest")
    for e in C["entries"]:
        in_draft(f"A.3/entry-digest-in-draft/{e[0]}", e[1][1], "entry digest")

    # ---- A.4 policy pack and receipts
    pack = sha(b'{"pack":"example-deployment-pack","v":"1.0.0"}')
    r = {i: S[t] for i, t in enumerate((
        "A.4 Execution Receipt seq 0 (task_start)",
        "A.4 Execution Receipt seq 1 (inference)",
        "A.4 Execution Receipt seq 2 (tool_call, confirm, parent_seq=1)",
        "A.4 Execution Receipt seq 3 (tool_call, allow outcome of seq 2)"))}
    eq_case("A.4/policy-pack-digest", pack, r[0][7][1], "sha256 of the stated pack octets vs receipt key 7")
    in_draft("A.4/policy-pack-digest-in-draft", pack, "pack digest")
    stated = [S[f"A.4 record-hash({i})"] for i in range(4)]
    hashes = []
    for i in range(4):
        h = sha(enc(r[i]))
        hashes.append(h)
        eq_case(f"A.4/record-hash-{i}", h, stated[i], "sha256(deterministic CBOR of receipt) vs vectors.txt")
        in_draft(f"A.4/record-hash-{i}-in-draft", h, "record-hash")
    emit("A.4/chain-links", "agrees" if (r[0][3] == b"\0" * 32 and all(r[i][3] == hashes[i - 1] for i in (1, 2, 3))) else "contradicted",
         "seq 0 prev_hash is 32 zero octets; each prev_hash is the previous record-hash; seq increases by one")
    emit("A.4/seq-increments", "agrees" if [r[i][2] for i in range(4)] == [0, 1, 2, 3] else "contradicted", "seq 0,1,2,3")

    # receipt 2: agent_sig at key 15 over the receipt without key 15
    r2 = r[2]
    sig_item = dec(r2[15])
    core = {k: v for k, v in r2.items() if k != 15}
    ok, why = verify_sign1(sig_item, pk["agent"], detached=enc(core))
    emit("A.4/receipt-2-agent-sig", "agrees" if ok else "contradicted", f"{why}; detached payload = canonical receipt without key 15; len(key15)={len(r2[15])}")
    eq_case("cose/execution-receipt-2/payload-equals-diagnostic", dec(cose["execution-receipt-2"].value[2]), r2, "signed receipt payload vs diagnostic")
    eq_case("cose/execution-receipt-2/record-hash", sha(cose["execution-receipt-2"].value[2]), hashes[2], "record-hash from the signed payload bytes")

    # call_digest, principal_link: inputs are the literal placeholders named in the draft
    call = dig(enc(["POST", "/invoices", sha(b"<invoice request bytes>")]))
    eq_case("A.4/call-digest", call[1], r[3][29][1], "HTTP binding over literal octets <invoice request bytes>")
    in_draft("A.4/call-digest-in-draft", call[1], "call_digest")
    eq_case("A.4/principal-link", sha(b"<delegation token octets>"), r[3][24], "sha256 of literal octets <delegation token octets>")
    in_draft("A.4/principal-link-in-draft", r[3][24], "principal_link")
    req = dig(b'{"to":"ap@customer.example","amount":"1200.00"}')
    emit("A.4/request-digest-input-not-in-draft", "cannot-tell",
         f"seq 2 key 12 {r[2][12][1].hex()}: the draft names the input only as <prompt bytes>/<request bytes>; generator input reproduces it: {req[1] == r[2][12][1]}")
    eq_case("A.4/prompt-digest-literal", dig(b"<prompt bytes>")[1], r[1][12][1], "seq 1 key 12 over literal octets <prompt bytes>")
    eq_case("A.4/completion-digest-literal", dig(b"<completion bytes>")[1], r[1][13][1], "seq 1 key 13 over literal octets <completion bytes>")

    # ---- A.5 epoch
    E = S["A.5 Execution Epoch Statement"]
    root = mth(hashes[:3])
    eq_case("A.5/epoch-root", root, E[7], "RFC 9162 MTH over record-hash 0..2 vs vectors.txt")
    in_draft("A.5/epoch-root-in-draft", root, "epoch_root")
    eq_case("A.5/epoch-last-hash", hashes[2], E[6], "epoch last_hash equals record-hash(2)")
    emit("A.5/epoch-count", "agrees" if E[8] == E[4] - E[3] + 1 == 3 else "contradicted", "count = last_seq - first_seq + 1")
    eq_case("cose/execution-epoch/payload-equals-diagnostic", dec(cose["execution-epoch"].value[2]), E, "signed epoch payload vs diagnostic")

    # ---- A.6 serving party
    sc = S["A.6 Serving Party Credential Statement payload"]
    sd = sha(enc(sc))
    eq_case("A.6/serving-credential-digest", sd, S["A.6 Serving Party Credential payload digest"][1], "sha256(canonical payload)")
    in_draft("A.6/serving-credential-digest-in-draft", sd, "digest")
    eq_case("A.6/serving-credential-key", sc[3][-2], pk["serving"], "serving key in credential")
    SC = S["A.6 Serving Party configuration entries and digest"]
    eq_case("A.6/serving-config-digest", sha(enc(SC["entries"])), SC["config_digest"][1], "sha256(canonical entries)")
    eq_case("A.6/serving-pack-digest", sha(b'{"pack":"example-serving-pack","v":"1.0.0"}'), S["A.6 Admission receipt seq 0"][7][1], "serving pack digest")
    a0 = S["A.6 Admission receipt seq 0"]
    ha0 = sha(enc(a0))
    eq_case("A.6/admission-record-hash", ha0, S["A.6 record-hash(admission 0)"], "sha256(canonical admission receipt)")
    in_draft("A.6/admission-record-hash-in-draft", ha0, "record-hash(admission 0)")
    eq_case("A.6/admission-names-caller-record", a0[21][3], hashes[3], "admission key 21 record-hash equals record-hash(3)")
    eq_case("A.6/admission-call-digest-equals-caller", a0[29], r[3][29], "same call_digest on both sides")
    eq_case("A.6/admission-principal-link-equals-caller", a0[24], r[3][24], "same principal_link on both sides")
    srv_principal = sha(b"serving-pepper-0001" + b"user:alice@example.com")
    eq_case("A.6/admission-principal-digest", srv_principal, a0[10][2], "serving-side pepper principal digest")
    emit("A.6/admission-principal-differs", "agrees" if a0[10][2] != r[3][10][2] else "contradicted", "peppers differ, so principal digests differ")

    print(f"SUMMARY\tagrees={OUT.count('agrees')}\tcontradicted={OUT.count('contradicted')}\tcannot-tell={OUT.count('cannot-tell')}\ttotal={len(OUT)}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
