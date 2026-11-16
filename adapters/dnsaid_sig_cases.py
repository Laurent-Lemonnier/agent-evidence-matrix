"""Write the DNS-AID `sig` binding cases, signed by dns-aid-core's own signer (jwks.sign_record, svcb_digest,
export_jwks), so the signed records are theirs; fresh keys each run, verdicts are deterministic.

usage: python -I dnsaid_sig_cases.py <dns-aid-core checkout> <outdir>

<outdir>/pinned/  12 rule cases: valid, endpoint-only, parameter and endpoint tamper, expiry, wrong key,
                  alg none, a flipped signature bit, the svcb1 field boundary, and three strict-profile cases
                  (duplicate member, float port, future iat)
<outdir>/new/     8 key-authority and header cases: a foreign key with no provenance, from the wrong host and
                  against a pin, the owner-key control, an unknown crit extension, the dawn-00 record shape,
                  a malformed header and an injected empty parameter
Each case carries `expected` and `rule` (derived from the stated rule, not from any reader), the zone,
jwks_url, a consumer pin of the key-set fingerprint, and `zone_jwks`, what dns-aid.<zone> serves, which
only the model of their live path reads.
"""
import base64
import copy
import json
import os
import sys
import time

sys.path.insert(0, sys.argv[1] + "/src")
from dns_aid.core import jwks as J  # noqa: E402
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA  # noqa: E402

out = sys.argv[2]
for d in ("pinned", "new"):
    os.makedirs(os.path.join(out, d), exist_ok=True)
ZONE = "example.com"
URL = f"https://dns-aid.{ZONE}/.well-known/dns-aid-jwks.json"
NOW = int(time.time())
priv, pub = J.generate_keypair()
priv2, pub2 = J.generate_keypair()
JWKS = J.export_jwks(pub, kid="k1")

REC = {
    "fqdn": "_chat._a2a._agents.example.com",
    "target": "chat.example.com",
    "port": 443,
    "alpn": "a2a",
    "params": {"cap": "https://chat.example.com/.well-known/agent-cap.json",
               "cap-sha256": "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU",
               "policy": "https://example.com/agent-policy",
               "realm": "prod", "bap": None, "connect-class": None,
               "connect-meta": None, "enroll-uri": None, "well-known": None},
}


def payload(rec, svcb=True, iat=None, exp=None):
    return J.RecordPayload(fqdn=rec["fqdn"], target=rec["target"], port=rec["port"],
                           alpn=rec["alpn"], iat=NOW - 60 if iat is None else iat,
                           exp=NOW + 86400 if exp is None else exp,
                           svcb=J.svcb_digest(rec["params"]) if svcb else None)


def b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def resign_raw(header, body_bytes, key):
    """Sign arbitrary payload bytes with their DER-to-raw path, for crafted payloads."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
    hi = b64(json.dumps(header, separators=(",", ":")).encode())
    si = f"{hi}.{b64(body_bytes)}".encode()
    sig = J._der_to_raw_signature(key.sign(si, ECDSA(hashes.SHA256())))
    return f"{hi}.{b64(body_bytes)}.{b64(sig)}"


def write(name, rec, sig, expected, why, jwks=JWKS):
    rec = dict(rec, zone=ZONE)
    c = {"case": name, "now": NOW, "record": rec, "sig": sig, "jwks": jwks, "expected": expected, "rule": why,
         "jwks_url": URL, "key_authority": {"kind": "pin", "jwks_fingerprint": J.jwks_fingerprint(jwks)},
         "zone_jwks": jwks}
    with open(os.path.join(out, "pinned", name + ".json"), "w") as f:
        json.dump(c, f, indent=1, sort_keys=True)


good = J.sign_record(payload(REC), priv, kid="k1")
write("full-coverage-valid", REC, good, "agrees", "ES256 valid, unexpired, endpoint and svcb1 digest match")
write("endpoint-only", REC, J.sign_record(payload(REC, svcb=False), priv, kid="k1"), "cannot-tell",
      "valid, but no svcb claim: cap, cap-sha256, policy, realm are not attested")
r = copy.deepcopy(REC); r["params"]["cap-sha256"] = "AAAA" + REC["params"]["cap-sha256"][4:]
write("param-tamper-cap-sha256", r, good, "contradicted", "served cap-sha256 differs from the signed svcb1 digest")
r = copy.deepcopy(REC); r["target"] = "evil.example.net"
write("endpoint-tamper-target", r, good, "contradicted", "served target differs from signed target")
write("expired", REC, J.sign_record(payload(REC, iat=NOW - 7200, exp=NOW - 3600), priv, kid="k1"),
      "contradicted", "exp is before the check time")
write("wrong-key", REC, J.sign_record(payload(REC), priv2, kid="k1"), "contradicted",
      "signature does not verify under the published key")
h, p, s = good.split(".")
write("alg-none", REC, b64(json.dumps({"alg": "none", "kid": "k1"}).encode()) + "." + p + ".",
      "contradicted", "only ES256 is allowed")
flip = bytearray(base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))); flip[5] ^= 1
write("sig-bitflip", REC, f"{h}.{p}.{b64(bytes(flip))}", "contradicted", "one signature bit flipped")
r = copy.deepcopy(REC); r["params"]["cap"] = "u"; r["params"]["realm"] = "t"
r2 = copy.deepcopy(REC); r2["params"]["cap"] = "u\nrealm=t"; r2["params"]["realm"] = None
write("svcb1-field-boundary", r2, J.sign_record(payload(r), priv, kid="k1"), "contradicted",
      "signed {cap:u, realm:t}; served cap='u\\nrealm=t' with no realm must not bind")
body = payload(REC).to_json()
dup = '{"fqdn":"_x._a2a._agents.evil.example",' + body[1:]
write("dup-member-fqdn", REC, resign_raw({"alg": "ES256", "typ": "JWT", "kid": "k1"}, dup.encode(), priv),
      "contradicted", "PROFILE PROPOSAL: signed payload must be I-JSON (RFC 7493), duplicate member names refused; "
      "a last-wins parser and a first-wins parser bind different fqdn values to one signature")
d = json.loads(body); d["port"] = 443.0
write("port-float", REC, resign_raw({"alg": "ES256", "typ": "JWT", "kid": "k1"},
      json.dumps(d, sort_keys=True, separators=(",", ":")).encode(), priv),
      "contradicted", "PROFILE PROPOSAL: port must be a JSON integer; 443.0 is not 443 in a strict reader")
write("iat-future", REC, J.sign_record(payload(REC, iat=NOW + 86400, exp=NOW + 2 * 86400), priv, kid="k1"),
      "cannot-tell", "PROFILE PROPOSAL: iat a day after the check time (beyond 300 s skew) is not yet attested")


def write_new(name, c):
    with open(os.path.join(out, "new", name + ".json"), "w") as f:
        json.dump(c, f, indent=1, sort_keys=True)


# 2. New cases.
owner_priv, owner_pub = J.generate_keypair()
att_priv, att_pub = J.generate_keypair()
OWNER = J.export_jwks(owner_pub, kid="k1")
ATTACKER = J.export_jwks(att_pub, kid="k1")
PIN = {"kind": "pin", "jwks_fingerprint": J.jwks_fingerprint(OWNER)}
PARAMS = {"cap": "https://chat.example.com/.well-known/agent-cap.json",
          "cap-sha256": "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU",
          "policy": "https://example.com/agent-policy", "realm": None, "bap": None,
          "connect-class": None, "connect-meta": None, "enroll-uri": None, "well-known": None}
REC = {"fqdn": "chat.example.com", "target": "chat.example.com", "port": 443, "alpn": "a2a",
       "zone": ZONE, "params": PARAMS}


def payload(rec, params, alpn=None):
    return J.RecordPayload(fqdn=rec["fqdn"], target=rec["target"], port=rec["port"],
                           alpn=alpn or rec["alpn"], iat=NOW - 60, exp=NOW + 86400,
                           svcb=J.svcb_digest(params))


def case(name, rec, sig, jwks, expected, rule, **kw):
    c = {"case": name, "now": NOW, "record": rec, "sig": sig, "jwks": jwks,
         "zone_jwks": OWNER, "expected": expected, "rule": rule}
    c.update(kw)
    write_new(name, c)


# CE1: a self-consistent triple under a key the name's owner never published.
forged = J.sign_record(payload(REC, PARAMS), att_priv, kid="k1")
case("ce1-foreign-key-no-provenance", REC, forged, ATTACKER, "cannot-tell",
     "KEY AUTHORITY: the JWKS travels with the evidence and nothing ties it to the zone owner; "
     "their live path fetches the key from dns-aid.<zone> (jwks.py JWKS_HOST_PREFIX, discoverer "
     "sig_zone = agent.domain), an offline triple cannot")
case("ce1-foreign-key-wrong-host", REC, forged, ATTACKER, "contradicted",
     "KEY AUTHORITY: jwks_url host is not dns-aid.<zone> or the deprecated apex (jwks_urls())",
     jwks_url="https://dns-aid.attacker.example/.well-known/dns-aid-jwks.json")
case("ce1-foreign-key-pinned-owner", REC, forged, ATTACKER, "contradicted",
     "KEY AUTHORITY: the supplied JWKS fingerprint differs from the consumer's pin for the zone",
     jwks_url=URL, key_authority=PIN)
case("ce1-owner-key-pinned-control", REC, J.sign_record(payload(REC, PARAMS), owner_priv, kid="k1"),
     OWNER, "agrees", "control: owner key, derived host, pin matches, full svcb1 coverage",
     jwks_url=URL, key_authority=PIN)

# CE2: RFC 7515 4.1.11 crit naming an extension no reader understands.
hdr = {"alg": "ES256", "typ": "JWT", "kid": "k1", "crit": ["x-dnsaid-scope"], "x-dnsaid-scope": "tenant-a"}
hi = b64(json.dumps(hdr, separators=(",", ":")).encode())
pi = b64(payload(REC, PARAMS).to_json().encode())
der = owner_priv.sign(f"{hi}.{pi}".encode(), ECDSA(hashes.SHA256()))
case("ce2-crit-unknown-extension", REC, f"{hi}.{pi}.{b64(J._der_to_raw_signature(der))}", OWNER,
     "contradicted", "RFC 7515 4.1.11: a crit extension the recipient does not understand makes the "
     "JWS invalid (MUST)", jwks_url=URL, key_authority=PIN)

# CE3: a record in the current draft's shape (dawn-00 Table 1: alpn is the transport,
# proto is the agent protocol). Their publisher signs alpn = protocol value.
rec3 = copy.deepcopy(REC); rec3["alpn"] = "h2,h3"; rec3["proto"] = "a2a"
case("ce3-dawn00-alpn-transport-proto-a2a", rec3,
     J.sign_record(payload(REC, PARAMS, alpn="a2a"), owner_priv, kid="k1"), OWNER, "agrees",
     "dawn-00 section 3.1.1 and Table 1: alpn=h2,h3 proto=a2a; their discoverer binds payload.alpn to "
     "agent.protocol.value, not to the served alpn string", jwks_url=URL, key_authority=PIN)

# CE4: malformed compact JWS (bad base64url in the header). A reader must give a verdict.
case("ce4-malformed-header-b64", REC, "a." + pi + ".AAAA", OWNER, "contradicted",
     "not a decodable compact JWS: contradicted, never a crash", jwks_url=URL, key_authority=PIN)

# CE6: empty value injected for a param the publisher never set.
rec6 = copy.deepcopy(REC); rec6["params"]["realm"] = ""
case("ce6-empty-realm-injected", rec6,
     J.sign_record(payload(REC, PARAMS), owner_priv, kid="k1"), OWNER, "contradicted",
     "their own svcb_digest docstring: a param the publisher never set cannot be injected as \"\" "
     "without breaking the claim", jwks_url=URL, key_authority=PIN)

print("pinned", len(os.listdir(os.path.join(out, "pinned"))), "new", len(os.listdir(os.path.join(out, "new"))))
