"""Independent reader for the DNS-AID `sig` binding (does not import dns-aid).

usage: python -I sig_reader_v2.py <case.json> [...]
Prints: <case> <verdict> <reason> <jwks_fp>. What it checks beyond the signature:
  K  key authority: the JWKS carried in the evidence is not trusted by itself.
     jwks_url, when given, must be https://dns-aid.<zone>/... or the deprecated
     https://<zone>/... with fqdn inside <zone>; key_authority (a consumer pin of the
     key-set fingerprint today; a DNSSEC chain or an inclusion statement later) must
     match. A triple with no key authority tops out at cannot-tell, and every line
     reports the key-set fingerprint the verdict is scoped to.
  C  RFC 7515 4.1.11: a `crit` header is refused (this reader understands no
     extension), as is a malformed one.
  P  agent protocol binding: payload alpn is compared to record proto when present
     (dawn-00 Table 1), else to record alpn (draft -02 shape).
  R  every malformed input yields contradicted, never an exception; base64url must be
     the strict alphabet and canonical.
"""
import base64, hashlib, json, re, sys
from urllib.parse import urlsplit
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

SKEW = 300
B64URL = re.compile(r"\A[A-Za-z0-9_-]*\Z")


class Bad(ValueError):
    pass


class Dup(ValueError):
    pass


def ub64(s):
    if not isinstance(s, str) or not B64URL.match(s) or len(s) % 4 == 1:
        raise Bad("not base64url")
    raw = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    if base64.urlsafe_b64encode(raw).decode().rstrip("=") != s:
        raise Bad("non-canonical base64url")
    return raw


def strict(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise Dup(k)
        d[k] = v
    return d


def isint(v):
    return isinstance(v, int) and not isinstance(v, bool)


def norm(n):
    return n.rstrip(".").lower() if isinstance(n, str) else None


def within(name, zone):
    n, z = norm(name), norm(zone)
    return n is not None and z is not None and (n == z or n.endswith("." + z))


def svcb1(params):
    cov = {k: v for k, v in params.items() if v is not None}
    raw = b"svcb1:" + json.dumps(cov, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")


def jwks_fp(jwks):
    """Same digest as dns-aid-core jwks_fingerprint (key material only, order-free)."""
    keys = [":".join(str(k.get(f, "")) for f in ("kty", "crv", "x", "y", "n", "e"))
            for k in jwks.get("keys", []) if isinstance(k, dict)]
    raw = "\n".join(sorted(keys)).encode()
    return base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")


def key_for(jwks, kid):
    keys = [k for k in jwks.get("keys", []) if isinstance(k, dict) and k.get("kty") == "EC" and k.get("crv") == "P-256"]
    if kid is not None:
        keys = [k for k in keys if k.get("kid") == kid] or keys  # RFC 7515 4.1.4: kid is a hint
    out = []
    for k in keys:
        x, y = int.from_bytes(ub64(k["x"]), "big"), int.from_bytes(ub64(k["y"]), "big")
        out.append(ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key())
    return out


def authority(c, fp):
    """None when the key set is tied to the zone owner; otherwise (verdict, reason)."""
    rec, zone = c["record"], c["record"].get("zone")
    if zone is None or not within(rec["fqdn"], zone):
        return "cannot-tell", "no publishing zone that contains the fqdn"
    url = c.get("jwks_url")
    if url is not None:
        u = urlsplit(url)
        if u.scheme != "https" or norm(u.hostname) not in (f"dns-aid.{norm(zone)}", norm(zone)):
            return "contradicted", f"JWKS host {u.hostname!r} is not dns-aid.{zone} or {zone}"
    ka = c.get("key_authority")
    if ka is None:
        return "cannot-tell", f"signature binds the record to key set {fp}, which nothing ties to the owner of {zone}"
    if ka.get("kind") != "pin":
        return "cannot-tell", f"key authority kind {ka.get('kind')!r} not read by this reader"
    if ka.get("jwks_fingerprint") != fp:
        return "contradicted", "supplied JWKS is not the key set pinned for the zone"
    return None


def judge(c):
    rec, now = c["record"], c["now"]
    parts = c["sig"].split(".") if isinstance(c.get("sig"), str) else []
    if len(parts) != 3:
        return "contradicted", "not a compact JWS"
    hdr = json.loads(ub64(parts[0]), object_pairs_hook=strict)
    if not isinstance(hdr, dict):
        return "contradicted", "header is not a JSON object"
    if "crit" in hdr:
        return "contradicted", f"RFC 7515 4.1.11: crit {hdr['crit']!r} names an extension this reader does not support"
    if hdr.get("alg") != "ES256":
        return "contradicted", f"alg {hdr.get('alg')!r} is not ES256"
    sig = ub64(parts[2])
    if len(sig) != 64:
        return "contradicted", "ES256 signature is not 64 bytes"
    der = encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
    si = f"{parts[0]}.{parts[1]}".encode("ascii")
    keys = key_for(c["jwks"], hdr.get("kid"))
    if not keys:
        return "cannot-tell", "no usable P-256 key in the JWKS"
    for k in keys:
        try:
            k.verify(der, si, ec.ECDSA(hashes.SHA256()))
            break
        except InvalidSignature:
            pass
    else:
        return "contradicted", "signature does not verify under any published key"
    p = json.loads(ub64(parts[1]), object_pairs_hook=strict)
    if not isinstance(p, dict):
        return "contradicted", "payload is not a JSON object"
    for f in ("port", "iat", "exp"):
        if not isint(p.get(f)):
            return "contradicted", f"PROFILE: {f} is not a JSON integer ({p.get(f)!r})"
    if p["exp"] <= now:
        return "contradicted", "expired at check time"
    proto = rec.get("proto") or rec["alpn"]
    if not (norm(p.get("fqdn")) == norm(rec["fqdn"]) and norm(p.get("target")) == norm(rec["target"])
            and p["port"] == rec["port"] and p.get("alpn") == proto):
        return "contradicted", "signed endpoint differs from the served record"
    if "svcb" in p and p["svcb"] != svcb1(rec["params"]):
        return "contradicted", "svcb1 digest differs from the served params"
    a = authority(c, jwks_fp(c["jwks"]))
    if a is not None:
        return a
    if p["iat"] > now + SKEW:
        return "cannot-tell", "PROFILE: iat after check time plus skew"
    if "svcb" not in p:
        return "cannot-tell", "valid, endpoint only: svcb params not attested"
    return "agrees", "ES256 valid, unexpired, endpoint and svcb1 bound, key set pinned for the zone"


for path in sys.argv[1:]:
    name = path
    try:
        c = json.load(open(path))
        name = c.get("case", path)
        v, why = judge(c)
        fp = jwks_fp(c["jwks"]) if isinstance(c.get("jwks"), dict) else "-"
    except Dup as e:
        v, why, fp = "contradicted", f"duplicate member {e} (not I-JSON)", "-"
    except Exception as e:  # malformed input is a verdict, never a crash
        v, why, fp = "contradicted", f"malformed: {type(e).__name__}: {e}", "-"
    print(f"{name}\t{v}\t{why}\t{fp}")
