"""Run dns-aid-core's own publisher on its MockBackend and check the emitted DNS records against one
revision of the DNS-AID draft and against dnspython (RFC 9460 presentation and wire).

usage: <venv>/bin/python -I dnsaid_adapter.py <dns-aid-core-checkout> <draft.txt> [--tamper]

The draft text decides the rules. draft-mozleywilliams-dnsop-dnsaid-02 carries the agent protocol in
alpn and names cap, cap-sha256, policy, realm, well-known and bap in Table 1. Its successor
draft-mozleywilliams-dawn-dnsaid-00 moves the agent protocol to a `proto` parameter, keeps alpn for the
transport suite, and renames or drops the other names (Table 1: proto, proto-ver, well-known, path,
desc-ref, desc-ref-digest). The Table 1 names are read from the draft file, never typed here.

The checkout's src/ is put on sys.path on purpose: running THEIR code is the replay.
One line per case: "PASS|DIFF|INFO  <case>: <detail>". Output is deterministic and carries no local paths.
--tamper flips one byte of the capability descriptor after cap-sha256 was computed (second-angle check).
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import re
import sys

src_root, draft_path = sys.argv[1], sys.argv[2]
TAMPER = "--tamper" in sys.argv[3:]
sys.path.insert(0, src_root + "/src")

import dns.name  # noqa: E402
import dns.rdata  # noqa: E402
import dns.rdataclass  # noqa: E402
import dns.rdatatype  # noqa: E402
import dns.wire  # noqa: E402

import logging  # noqa: E402

import structlog  # noqa: E402

structlog.configure(wrapper_class=structlog.make_filtering_bound_logger(logging.CRITICAL))

from dns_aid.backends.mock import MockBackend  # noqa: E402
from dns_aid.backends.route53 import Route53Backend  # noqa: E402
from dns_aid.core.cap_fetcher import CapDigestMismatchError, _verify_cap_digest  # noqa: E402
from dns_aid.core.discoverer import _parse_svcb_custom_params  # noqa: E402
from dns_aid.core.models import DNS_AID_KEY_MAP  # noqa: E402
from dns_aid.core.publisher import publish  # noqa: E402

OUT: list[tuple[str, str, str]] = []


def emit(status: str, case: str, detail: str) -> None:
    OUT.append((status, case, detail))
    print(f"{status:4}  {case}: {detail}")


DRAFT = open(draft_path, encoding="utf-8").read()
DRAFT_SHA = hashlib.sha256(DRAFT.encode()).hexdigest()
DRAFT_NAME = re.search(r"draft-mozleywilliams-[a-z]+-dnsaid-\d\d", DRAFT).group(0)
print(f"{DRAFT_NAME} sha256 {DRAFT_SHA}")
print(f"dns-aid-core pyproject version {re.search(r'^version = .(.+).$', open(src_root + '/pyproject.toml').read(), re.M).group(1)}")

# The SvcParamKey names the draft defines: the first column of each "Table 1" (dawn-00 section 3.1, -02
# section 7.1), minus the RFC 9460 keys and TargetName that the table also lists.
RFC9460 = {"TargetName", "alpn", "port", "ipv4hint", "ipv6hint", "mandatory", "no-default-alpn", "ech"}
TABLE1_NAMES = []
for block in re.findall(r"((?:^ *[|+].*\n)+)\s*Table 1\b", DRAFT, re.M):
    for row in block.splitlines():
        m = re.match(r"^\s*\|\s*([A-Za-z][\w-]*)\s*\|", row)
        if m and m.group(1) not in RFC9460 | {"Parameter", "Name", "SvcParamKey"} and m.group(1) not in TABLE1_NAMES:
            TABLE1_NAMES.append(m.group(1))
DAWN = "proto" in TABLE1_NAMES  # dawn-00: the agent protocol lives in proto, alpn is the transport suite
TRANSPORT = {"h2", "h3", "http/1.1", "h2c"}
emit("INFO", "draft-table1-names", f"{DRAFT_NAME} Table 1 defines {TABLE1_NAMES}")
# dns-aid-core's own name map (models.DNS_AID_KEY_MAP), the names its publisher can emit
EMITTABLE = sorted(DNS_AID_KEY_MAP)

# capability descriptor and the digest the draft defines: base64url(SHA-256(descriptor)) (Table 1)
DESCRIPTOR = b'{"capabilities":["travel","booking"],"version":"1.0.0","protocols":["mcp"]}'
digest = base64.urlsafe_b64encode(hashlib.sha256(DESCRIPTOR).digest()).rstrip(b"=").decode()
served = bytearray(DESCRIPTOR)
if TAMPER:
    served[10] ^= 0x01
served = bytes(served)

AGENTS = [
    # name, protocol, endpoint host, extra kwargs. Fig 1 shape (own host) and Fig 3 shape (hosted service).
    ("agent-name", "a2a", "agent-name.example.com", dict(ipv4_hint="192.0.2.1", ipv6_hint="2001:db8::1",
        cap_uri="https://agent-name.example.com/cap.json", cap_sha256=digest, well_known_path="agent-card.json")),
    ("hosted-agent", "mcp", "resource.service-provider.example", dict(well_known_path="agent-card.json", policy_uri="https://example.com/policy", realm="prod")),
]
ZONE = "example.com"


async def run_publish() -> MockBackend:
    be = MockBackend(zones=[ZONE])
    for name, proto, host, kw in AGENTS:
        res = await publish(name=name, domain=ZONE, protocol=proto, endpoint=host, backend=be,
                            publish_walkable_alias=(name == "agent-name"), **kw)
        assert res.success, res.message
    return be


be = asyncio.run(run_publish())
fmt = Route53Backend._format_svcb_value  # their formatter, the exact text sent to the DNS provider

for name, proto, host, kw in AGENTS:
    owner = f"{name}.{ZONE}."
    rrset = be.records[ZONE][name]["SVCB"]
    rec = rrset[0]
    # E1 flat owner (draft 3.1: agent-name.example.com)
    emit("PASS" if len(rrset) == 1 and name in be.records[ZONE] else "DIFF", f"{name}/flat-owner", f"SVCB stored at {owner} (draft 3.1 flat name)")
    # E2 priority, target
    ok = rec["priority"] == 1 and rec["target"] == host + "." and "_" not in rec["target"]
    emit("PASS" if ok else "DIFF", f"{name}/servicemode-target", f"priority {rec['priority']} target {rec['target']} (draft Fig 1 and Fig 3: priority 1, dotted target without underscores)")
    # E3 one agent protocol per record (3.1.1 of both revisions), carried where the revision puts it
    alpn_ids = rec["params"]["alpn"].split(",")
    if DAWN:
        proto_param = rec["params"].get("proto") or rec["params"].get(DNS_AID_KEY_MAP.get("proto", "proto"))
        emit("PASS" if proto_param == proto else "DIFF", f"{name}/proto-single-agent-protocol",
             f"proto={proto_param} (dawn-00 3.1.1 and Table 1: the agent protocol is carried in proto)")
        emit("PASS" if set(alpn_ids) <= TRANSPORT else "DIFF", f"{name}/alpn-transport-only",
             f"alpn={rec['params']['alpn']} (dawn-00 Table 1: alpn is the transport suite, e.g. h2,h3)")
    else:
        agent_ids = [a for a in alpn_ids if a in ("mcp", "a2a")]
        emit("PASS" if agent_ids == [proto] else "DIFF", f"{name}/alpn-single-agent-protocol", f"alpn={rec['params']['alpn']} (draft 3.1.1: one agent protocol per record)")
    # E4 dnspython parse of THEIR presentation text, then wire round trip
    text = fmt(None, rec["priority"], rec["target"], rec["params"])
    try:
        rd = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.SVCB, text)
        wire = rd.to_wire()
        rd2 = dns.rdata.from_wire(dns.rdataclass.IN, dns.rdatatype.SVCB, wire, 0, len(wire), None)
        rt = rd2 == rd
        emit("PASS" if rt else "DIFF", f"{name}/rfc9460-parse-wire-roundtrip", f"dnspython parses the provider text and the wire round trip is {'equal' if rt else 'different'} ({len(wire)} octets)")
    except Exception as exc:  # a parse failure is the finding
        emit("DIFF", f"{name}/rfc9460-parse-wire-roundtrip", f"dnspython rejected the provider text: {type(exc).__name__}: {exc}")
        rd = None
    if rd is not None:
        params = {int(k): v for k, v in rd.params.items()}
        ok = params[1].ids[0].decode() == proto and params[3].port == 443
        emit("PASS" if ok else "DIFF", f"{name}/parsed-alpn-port", f"alpn id {params[1].ids[0].decode()} port {params[3].port}")
    # E5 every DNS-AID parameter the publisher emitted is a Table 1 name of this revision, in the private-use range
    emitted = sorted(n for n in EMITTABLE if DNS_AID_KEY_MAP[n] in rec["params"])
    outside = [n for n in emitted if n not in TABLE1_NAMES]
    emit("PASS" if not outside else "DIFF", f"{name}/parameter-names", f"emitted {emitted}; not in {DRAFT_NAME} Table 1: {outside}")
    keys = sorted(DNS_AID_KEY_MAP[n] for n in emitted)
    emit("PASS" if all(re.fullmatch(r"key65[0-9]{3}", v) for v in keys) else "DIFF", f"{name}/private-use-keys", f"emitted as {keys} (RFC 9460 private-use range 65280-65534; the draft defers numbers to IANA)")
    # E6 their text reader reads back what their emitter wrote
    back = _parse_svcb_custom_params(text)
    emit("PASS" if set(back) == set(emitted) else "DIFF", f"{name}/own-reader-roundtrip", f"_parse_svcb_custom_params recovers {sorted(back)} from the emitted text")
    # E7 mandatory keys present (RFC 9460 section 8)
    mand = rec["params"]["mandatory"].split(",")
    emit("PASS" if all(m in rec["params"] for m in mand) else "DIFF", f"{name}/mandatory-keys-present", f"mandatory={rec['params']['mandatory']}")

# E8 cap-sha256 (dawn-00 renames it desc-ref-digest): base64url SHA-256 of the capability descriptor
rec = be.records[ZONE]["agent-name"]["SVCB"][0]
pub = rec["params"][DNS_AID_KEY_MAP["cap-sha256"]]
emit("PASS" if pub == digest else "DIFF", "cap-sha256/value-equals-b64url-sha256", f"emitted {pub}, independent base64url(SHA-256(descriptor)) {digest}")
try:
    _verify_cap_digest(served, pub, "https://agent-name.example.com/cap.json")
    emit("PASS", "cap-sha256/their-verifier-accepts-served-bytes", "_verify_cap_digest accepts the served descriptor")
except CapDigestMismatchError:
    emit("DIFF", "cap-sha256/their-verifier-accepts-served-bytes", "_verify_cap_digest rejected the served descriptor (digest mismatch)")
emit("INFO", "cap-sha256/canonicalization", "draft says digest of the canonical capability descriptor and defines no canonical form; dns-aid-core hashes the fetched bytes as served")

# E9 walkable AliasMode (draft 3.1: AliasMode MUST point at the primary owner)
alias = be.records[ZONE]["agent-name._agents"]["SVCB"][0]
ok = alias["priority"] == 0 and alias["target"] == "agent-name.example.com." and alias["params"] == {}
emit("PASS" if ok else "DIFF", "agent-name/walkable-aliasmode", f"agent-name._agents.example.com. SVCB {alias['priority']} {alias['target']} params {alias['params']}")
atext = fmt(None, alias["priority"], alias["target"], alias["params"])
try:
    dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.SVCB, atext)
    emit("PASS", "agent-name/walkable-aliasmode-rfc9460", f"dnspython parses AliasMode text '{atext}'")
except Exception as exc:
    emit("DIFF", "agent-name/walkable-aliasmode-rfc9460", f"dnspython rejected '{atext}': {exc}")


# E10 multi-protocol: draft 3.1.1 "Each application-layer (agent) protocol MUST be a separate record in an RRset";
# publisher.py docstring: "Multi-protocol agents publish multiple AgentRecord instances at the same flat owner name,
# each with its own alpn ... NOT as a comma-separated list on a single record."
async def multi() -> MockBackend:
    b = MockBackend(zones=[ZONE])
    for proto in ("mcp", "a2a"):
        r = await publish(name="multi", domain=ZONE, protocol=proto, endpoint="multi.example.com", backend=b)
        assert r.success, r.message
    return b


def agent_protos(r):
    """The agent protocol(s) a record names: proto when present (dawn-00), else alpn minus transports (-02)."""
    p = r["params"]
    if p.get("proto"):
        return [x for x in p["proto"].split(",") if x]
    return [x for x in p.get("alpn", "").split(",") if x and x not in TRANSPORT]


def one_record_per_protocol(rr, want):
    per = [agent_protos(r) for r in rr]
    return all(len(x) == 1 for x in per) and sorted(x[0] for x in per) == sorted(want)


mb = asyncio.run(multi())
rr = mb.records[ZONE]["multi"]["SVCB"]
got = [agent_protos(r) for r in rr]
emit("PASS" if one_record_per_protocol(rr, ["a2a", "mcp"]) else "DIFF", "multi-protocol/two-records-one-owner", f"after publishing mcp then a2a for one owner the RRset holds {len(rr)} record(s) naming {got} (expected one record per agent protocol: a2a and mcp)")

# E10b the rule discriminates: the draft's own two-record examples pass it, a combined record fails it
for label, ctl, want in (("-02 example alpn=mcp,h2,h3 / alpn=a2a,h2,h3", [{"params": {"alpn": "mcp,h2,h3"}}, {"params": {"alpn": "a2a,h2,h3"}}], True),
                         ("dawn-00 example proto=a2a / proto=mcp", [{"params": {"alpn": "h2,h3", "proto": "a2a"}}, {"params": {"alpn": "h2,h3", "proto": "mcp"}}], True),
                         ("one record alpn=mcp,a2a", [{"params": {"alpn": "mcp,a2a"}}], False)):
    emit("PASS" if one_record_per_protocol(ctl, ["a2a", "mcp"]) == want else "DIFF", "multi-protocol/rule-control",
         f"{label}: {'conforms' if want else 'violates'} as expected")

# E11 the draft's own example records, read by dnspython
fig = [ln.strip() for ln in DRAFT.splitlines() if re.search(r"\bIN SVCB\b", ln) and "..." not in ln]
parsed = 0
bad = []
for ln in fig:
    m = re.match(r"(\S+)\s+(?:\d+\s+)?IN SVCB\s+(.*)", ln)
    body = m.group(2).rstrip("(").strip()
    try:
        dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.SVCB, body)
        parsed += 1
    except Exception:
        bad.append(body)
emit("INFO", "draft-examples/rfc9460-parse", f"{parsed} of {len(fig)} single-line example records in the draft parse as RFC 9460 presentation; unparsed: {bad}")

print(f"SUMMARY pass={sum(1 for s,_,_ in OUT if s=='PASS')} diff={sum(1 for s,_,_ in OUT if s=='DIFF')} info={sum(1 for s,_,_ in OUT if s=='INFO')}")
