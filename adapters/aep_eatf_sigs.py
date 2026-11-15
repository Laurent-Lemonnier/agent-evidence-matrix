"""Adapter: signature, receipt, ML-DSA-65 and RFC 3161 layers of EATF .aep packages.

Reads each package.aep (a ZIP) of the project's shared conformance vectors and
checks, one layer at a time and with no help from their verifier:

  rsa      signature.sig (base64 RSA PKCS#1 v1.5 / SHA-256) over canonical.bin,
           key = public_key.pem inside the package
  receipt  overt_receipt.json: content_hash == "sha256:" + hash.sha256, the text
           fields it shares with metadata.json agree, and when metadata names
           overt_receipt.sig the RSA signature over the exact receipt bytes holds
  mldsa    signature_pqc.sig (base64) over canonical.bin with pqc_public_key.pem
           (RFC 9881 SPKI or legacy raw 1952-byte PEM), ML-DSA-65, empty context
  tsr      timestamp.tsr (base64 RFC 3161 TimeStampResp): SHA-256 imprint equals
           hash.sha256, messageDigest attribute equals SHA-256(TSTInfo), and the
           CMS SignerInfo signature verifies against the certificate embedded
           in the token
  verdict  hash + canonical form + all layers present, against verify-expected.txt

Each layer prints pass, fail, absent or n/a (inputs missing). Output is
deterministic. usage: aep_eatf_sigs.py <eatf-verifier>/test-vectors
"""
import base64
import hashlib
import json
import pathlib
import sys
import zipfile

import rfc8785
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import mldsa, padding, rsa


def tlv(b, i=0):
    """Read one DER element at offset i: (tag, content_start, end)."""
    tag = b[i]
    n = b[i + 1]
    j = i + 2
    if n & 0x80:
        k = n & 0x7F
        n = int.from_bytes(b[j:j + k], "big")
        j += k
    return tag, j, j + n


def children(b, start, end):
    out = []
    i = start
    while i < end:
        tag, s, e = tlv(b, i)
        out.append((tag, i, s, e))
        i = e
    return out


def rsa_verify(pub_pem, sig, data):
    """Return "strict" (RFC 8017 DigestInfo with NULL, via OpenSSL), "no-null" (the
    SHA-256 DigestInfo without the NULL parameter, checked byte for byte), or None."""
    key = serialization.load_pem_public_key(pub_pem)
    if not isinstance(key, rsa.RSAPublicKey):
        return None
    try:
        key.verify(sig, data, padding.PKCS1v15(), hashes.SHA256())
        return "strict"
    except InvalidSignature:
        pass
    nums = key.public_numbers()
    k = (nums.n.bit_length() + 7) // 8
    if len(sig) != k:
        return None
    em = pow(int.from_bytes(sig, "big"), nums.e, nums.n).to_bytes(k, "big")
    di_nonull = bytes.fromhex("302f300b0609608648016503040201" "0420")
    want = b"\x00\x01" + b"\xff" * (k - 3 - len(di_nonull) - 32) + b"\x00" + di_nonull + hashlib.sha256(data).digest()
    return "no-null" if em == want else None


def layer_rsa(e):
    if "canonical.bin" not in e:
        return "n/a", "canonical.bin absent"
    try:
        how = rsa_verify(e["public_key.pem"], base64.b64decode(e["signature.sig"]), e["canonical.bin"])
    except Exception as exc:
        return "fail", type(exc).__name__
    if how == "strict":
        return "pass", "strict RFC 8017 DigestInfo"
    if how == "no-null":
        return "pass-nonnull", "DigestInfo without NULL parameter (BouncyCastle form)"
    return "fail", ""


def dig(d, *path):
    for k in path:
        if not isinstance(d, dict) or k not in d:
            return None
        d = d[k]
    return d


def layer_receipt(e, meta):
    if "overt_receipt.json" not in e:
        return "absent", ""
    try:
        r = json.loads(e["overt_receipt.json"])
    except Exception:
        return "fail", "receipt not JSON"
    want = "sha256:" + e["hash.sha256"].decode().strip().lower()
    if r.get("content_hash") != want:
        return "fail", "content_hash"
    pairs = [
        (("created_at",), ("event", "timestamp")),
        (("agent_id",), ("subject", "agent_id")),
        (("tenant_id_hash",), ("subject", "tenant_hash")),
        (("action_type",), ("event", "action_type")),
        (("policy_version",), ("policy", "version")),
        (("policy_decision",), ("policy", "decision")),
    ]
    for mk, rk in pairs:
        mv, rv = dig(meta, *mk), dig(r, *rk)
        if isinstance(mv, str) and isinstance(rv, str) and mv != rv:
            return "fail", f"{'.'.join(rk)} ({rv}) != metadata.{mk[0]} ({mv})"
    if meta.get("overt_receipt_signature") == "overt_receipt.sig":
        if "overt_receipt.sig" not in e:
            return "fail", "named signature entry absent"
        try:
            ok = rsa_verify(e["public_key.pem"], base64.b64decode(e["overt_receipt.sig"]), e["overt_receipt.json"]) is not None
        except Exception as exc:
            return "fail", type(exc).__name__
        if not ok:
            return "fail", "receipt signature"
        return "pass", "binding + fields + receipt signature"
    return "pass", "binding + fields; receipt not separately signed"


def layer_mldsa(e):
    if "signature_pqc.sig" not in e and "pqc_public_key.pem" not in e:
        return "absent", ""
    if "canonical.bin" not in e:
        return "n/a", "canonical.bin absent"
    try:
        sig = base64.b64decode(bytes(c for c in e["signature_pqc.sig"] if c not in b"\t\n\x0b\x0c\r "), validate=True)
        key = serialization.load_pem_public_key(e["pqc_public_key.pem"])
        key.verify(sig, e["canonical.bin"])
        return "pass", type(key).__name__
    except InvalidSignature:
        return "fail", "signature"
    except Exception as exc:
        return "fail", type(exc).__name__


def layer_tsr(e):
    raw = e.get("timestamp.tsr", b"")
    if not raw:
        return "fail", "empty or missing"
    try:
        der = base64.b64decode(raw.strip(), validate=True)
        # TimeStampResp ::= SEQ { status, timeStampToken }
        _, s, end = tlv(der)
        top = children(der, s, end)
        token = top[1] if len(top) > 1 else top[0]
        ci_tag, ci_i, ci_s, ci_e = token
        ci = children(der, ci_s, ci_e)          # OID, [0] EXPLICIT SignedData
        sd_tag, sd_i, sd_s, sd_e = ci[1]
        _, a, b = tlv(der, sd_s)                # SignedData SEQ
        sd = children(der, a, b)                # version, digestAlgs, encap, [0] certs, [1]? crls, signerInfos
        encap = sd[2]
        eci = children(der, encap[2], encap[3])
        octet = children(der, eci[1][2], eci[1][3])[0]
        tstinfo = der[octet[2]:octet[3]]
        tst = children(tstinfo, *tlv(tstinfo)[1:])
        imprint = children(tstinfo, tst[2][2], tst[2][3])
        if imprint[0][0] != 0x30:
            return "fail", "imprint shape"
        halg = der_oid(children(tstinfo, imprint[0][2], imprint[0][3])[0], tstinfo)
        hval = tstinfo[imprint[1][2]:imprint[1][3]]
        if halg != "2.16.840.1.101.3.4.2.1":
            return "fail", f"imprint algorithm {halg}"
        if hval.hex() != e["hash.sha256"].decode().strip().lower():
            return "fail", "imprint != hash.sha256"
        certs = [c for c in sd if c[0] == 0xA0]
        signer_infos = sd[-1]
        si_all = children(der, signer_infos[2], signer_infos[3])
        si = children(der, si_all[0][2], si_all[0][3])
        # version, sid, digestAlg, [0] signedAttrs, sigAlg, signature
        sattrs = next(x for x in si if x[0] == 0xA0)
        sig = der[si[-1][2]:si[-1][3]]
        attrs_der = b"\x31" + der[sattrs[1] + 1:sattrs[3]]   # retag [0] as SET for the signature input
        md = None
        for at in children(der, sattrs[2], sattrs[3]):
            kids = children(der, at[2], at[3])
            if der_oid(kids[0], der) == "1.2.840.113549.1.9.4":
                vs = children(der, kids[1][2], kids[1][3])
                md = der[vs[0][2]:vs[0][3]]
        if md is None or md != hashlib.sha256(tstinfo).digest():
            return "fail", "messageDigest != SHA-256(TSTInfo)"
        cert_objs = []
        for c in children(der, certs[0][2], certs[0][3]):
            cert_objs.append(x509.load_der_x509_certificate(der[c[1]:c[3]]))
        for cert in cert_objs:
            pk = cert.public_key()
            try:
                pk.verify(sig, attrs_der, padding.PKCS1v15(), hashes.SHA256())
                return "pass", "imprint + messageDigest + CMS signature (embedded test certificate)"
            except InvalidSignature:
                continue
        return "fail", "CMS signature"
    except Exception as exc:
        return "fail", "unparseable " + type(exc).__name__


def der_oid(el, buf):
    tag, i, s, e = el
    b = buf[s:e]
    first = f"{b[0] // 40}.{b[0] % 40}"
    n, parts = 0, []
    for x in b[1:]:
        n = (n << 7) | (x & 0x7F)
        if not x & 0x80:
            parts.append(str(n))
            n = 0
    return ".".join([first] + parts)


def hash_and_form(e, meta):
    if "canonical.bin" not in e:
        return "n/a", "canonical.bin absent"
    h = hashlib.sha256(e["canonical.bin"]).hexdigest() == e["hash.sha256"].decode().strip()
    cur = e["canonical.bin"] == e["response.txt"] + b"\n" + rfc8785.dumps(meta)
    leg = e["canonical.bin"] == e["response.txt"]
    return ("pass" if h and (cur or leg) else "fail"), ("current" if cur else "legacy" if leg else "no-form")


def run(path):
    with zipfile.ZipFile(path) as z:
        e = {n: z.read(n) for n in z.namelist()}
    out = {}
    try:
        meta = json.loads(e["metadata.json"])
    except Exception:
        meta = {}
    out["hash+form"] = hash_and_form(e, meta)
    out["rsa"] = layer_rsa(e)
    out["receipt"] = layer_receipt(e, meta)
    out["mldsa"] = layer_mldsa(e)
    out["tsr"] = layer_tsr(e)
    return out


def main(root):
    root = pathlib.Path(root)
    for label in ("valid", "invalid"):
        for p in sorted(root.glob(f"{label}/*/package.aep")):
            r = run(p)
            exp = (p.parent / "verify-expected.txt").read_text().split()[0].split("=")[1]
            applicable = [v[0] for v in r.values() if v[0] != "absent"]
            verdict = "true" if applicable and all(x.startswith("pass") for x in applicable) else "false"
            cols = "\t".join(f"{k}={v[0]}" for k, v in r.items())
            detail = "; ".join(f"{k}: {v[1]}" for k, v in r.items() if v[0] == "fail" and v[1])
            print(f"{label}/{p.parent.name}\t{cols}\tverdict={verdict}\texpected={exp}\t{detail}")


if __name__ == "__main__":
    main(sys.argv[1])
