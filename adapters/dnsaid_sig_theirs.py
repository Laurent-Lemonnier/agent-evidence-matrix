"""Their verifier as their LIVE discoverer runs it, on the break cases.

Models the live discoverer of
discoverer.py at 825ccea (lines 2096 to 2190):
  - the key comes from what dns-aid.<zone> serves (case zone_jwks), never from the
    evidence, because discoverer anchors the lookup to agent.domain;
  - payload.alpn is compared to the agent protocol (record proto when present,
    else alpn), as discoverer compares it to agent.protocol.value;
  - params are read back through their params_from_record rule (empty -> absent)
    over SIGNED_PARAM_FIELDS only.
usage: python -I their_live.py <dns-aid-core checkout> <case.json> [...]
"""
import hmac, json, sys
sys.path.insert(0, sys.argv[1] + "/src")
from dns_aid.core import jwks as J  # noqa: E402

S = J.SignatureStatus
MAP = {S.VERIFIED: "agrees", S.VERIFIED_ENDPOINT_ONLY: "cannot-tell", S.INVALID: "contradicted",
       S.UNBOUND: "contradicted", S.EXPIRED: "contradicted", S.NO_KEY: "cannot-tell"}


def eq(a, b):
    return a.rstrip(".").lower() == b.rstrip(".").lower()


for path in sys.argv[2:]:
    c = json.load(open(path))
    rec = c["record"]
    jwks = c.get("zone_jwks", c["jwks"])
    res = J._verify_against(jwks, c["sig"], J._jws_kid(c["sig"]), rec.get("zone", "example.com"))
    if res is None and J._jws_kid(c["sig"]) is not None:
        res = J._verify_against(jwks, c["sig"], None, rec.get("zone", "example.com"))
    st, ok, p = (S.NO_KEY, False, None) if res is None else (res[2], res[0], res[1])
    proto = rec.get("proto") or rec["alpn"]
    match = ok and p is not None and eq(p.fqdn, rec["fqdn"]) and eq(p.target, rec["target"]) \
        and p.port == rec["port"] and p.alpn == proto
    if match and p.svcb is not None:
        params = {k: (rec["params"].get(k) or None) for k in J.SIGNED_PARAM_FIELDS}
        if not hmac.compare_digest(p.svcb, J.svcb_digest(params)):
            match = False
    elif match and p.svcb is None:
        st = S.VERIFIED_ENDPOINT_ONLY
    if ok and not match:
        st = S.UNBOUND
    print(f"{c['case']}\t{MAP.get(st, str(st))}\t{st}")
