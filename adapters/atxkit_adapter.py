"""Adapter: read the ATX conformance kit's fixtures and re-derive each outcome from the credential bytes.

Input: a checkout of https://github.com/opena2a-standards/atx-conformance (or its fixtures/ directory
and conformance.json). Each fixture is a wrapper (name, verifierState, expected) around one ATX
credential (the `atx` member). This adapter does not import or call the project's verifiers. It reads
the specification text (atx-spec core.md 1.3, 1.3a.1, 1.3a.2, 13) and the fixtures' own descriptions, and
reaches a verdict for every credential by its own code:

  parse   strict parse: a duplicate member at any depth, two member names that fold to one in the
          credential, a signature entry, scanSummary or behavioralProfile, or a member name outside
          printable ASCII in those objects
  gates   atcVersion is 1.0 or 1.1; expiresAt against the pinned clock (tolerance 0, and again at 60
          seconds, which must give the same answer); the revoked flag and the CRL; issuerDid in the
          trusted set
  bytes   atcVersion 1.0: the eleven-field pipe string of 1.3a.1. atcVersion 1.1: RFC 8785 of the
          explicit to-be-signed projection of 1.3a.2, with its rules 1 to 5
  sigs    Ed25519 by cryptography under the keys the fixture's verifierState publishes, with the key
          eligibility rule of 1.3 step 4 (the issuer, plus under 1.1 only a chain DID that is also a
          trusted issuer); ML-DSA-65 (FIPS 204) by cryptography under the published 1952-byte key;
          every declared signature must verify; an ML-DSA-65 entry needs a verifying Ed25519
          companion (core.md 13); requiredSignatures counts distinct Ed25519 keys

Not read: the distinct signer-authority count of core.md 1.3 step 7, DID document resolution, the
transparency log, content hash against a binary, the build attestation and the content of a
behavioralProfile. The verifier states in the fixtures are the only key and trust source.

Verdict per fixture: agrees (observed ACCEPT or REJECT[category] equals the fixture's expected and the
kit answer key's expected), contradicted (it differs), cannot-tell (a form this adapter does not
project, or an unreadable file). The expectation plays no part in the observed result.

usage: atxkit_adapter.py <atx-conformance checkout or extract> [--only name ...]
Needs rfc8785 and cryptography with ML-DSA (cryptography >= 47; the venv pins 50.0.2). Run with -I.
"""
import base64
import binascii
import hashlib
import json
import pathlib
import re
import sys

import rfc8785
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import mldsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

UTC_SECONDS = re.compile(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z$")
SCAN_STRINGS = ("hma", "secretless", "cryptoServe", "oasbLevel")
SCAN_INTEGERS = ("criticalFindings", "highFindings")
SCAN_MEMBERS = set(SCAN_STRINGS) | set(SCAN_INTEGERS)
PROFILE_MEMBERS = {"checksum", "generatedAt", "observationDays"}
CREDENTIAL_MEMBERS = {
    "id", "atcVersion", "agentId", "agentDid", "publisher", "publisherDid", "version", "contentHash",
    "buildAttestation", "transparencyLogIndex", "capabilities", "declaredPurpose", "behavioralProfile",
    "scanSummary", "trustScore", "trustLevel", "issuedAt", "expiresAt", "issuerDid", "issuerChain",
    "signatures", "revoked", "revokedAt", "revocationReason", "createdAt",
}
SIGNATURE_MEMBERS = {"keyId", "algorithm", "value"}
MAX_EXACT = 2**53 - 1
MLDSA65_PUBLIC_KEY_SIZE = 1952


class Unprojected(Exception):
    """A form this adapter does not project (reported cannot-tell, never coerced)."""


class Rejected(Exception):
    def __init__(self, category, reason):
        super().__init__(reason)
        self.category = category
        self.reason = reason


class Dup(Exception):
    pass


class NumberLiteral:
    """A JSON number with the text the credential wrote it in."""

    __slots__ = ("text", "is_integer", "value")

    def __init__(self, text, is_integer):
        self.text = text
        self.is_integer = is_integer
        self.value = int(text) if is_integer else float(text)


def _pairs(pairs):
    seen = set()
    for key, _ in pairs:
        if key in seen:
            raise Dup(key)
        seen.add(key)
    return _Obj(pairs)


class _Obj(dict):
    """A parsed object that also remembers its member names in document order."""

    def __init__(self, pairs):
        super().__init__(pairs)
        self.names = [k for k, _ in pairs]


def parse_text(text):
    return json.loads(
        text,
        object_pairs_hook=_pairs,
        parse_int=lambda s: NumberLiteral(s, True),
        parse_float=lambda s: NumberLiteral(s, False),
        parse_constant=lambda s: (_ for _ in ()).throw(ValueError(s)),
    )


def plain(value):
    """The value with NumberLiteral replaced by int or float, for fields read as plain numbers."""
    if isinstance(value, NumberLiteral):
        return value.value
    if isinstance(value, dict):
        return {k: plain(v) for k, v in value.items()}
    if isinstance(value, list):
        return [plain(v) for v in value]
    return value


def parse_time(value, name):
    if not isinstance(value, str):
        raise Unprojected(f"{name} is not a string")
    m = UTC_SECONDS.match(value)
    if not m:
        raise Unprojected(f"{name} is not written as YYYY-MM-DDTHH:MM:SSZ")
    import datetime

    try:
        dt = datetime.datetime(*map(int, m.groups()), tzinfo=datetime.timezone.utc)
    except ValueError as exc:
        raise Rejected("PARSE_ERROR", f"{name}: {exc}")
    return int(dt.timestamp())


def strict_parse_checks(atx):
    """core.md 1.3 step 1 and the fixtures' strict-parse rule, over the four decoded object kinds."""
    decoded = [("credential", atx)]
    decoded += [("signature entry", s) for s in atx.get("signatures") or [] if isinstance(s, dict)]
    for name in ("scanSummary", "behavioralProfile"):
        if isinstance(atx.get(name), dict):
            decoded.append((name, atx[name]))
    for label, obj in decoded:
        folded = {}
        for key in obj.names:
            if any(ord(ch) < 0x20 or ord(ch) > 0x7E for ch in key):
                raise Rejected("PARSE_ERROR", f"{label} member name {key!a} is outside printable ASCII")
            folded.setdefault(key.lower(), []).append(key)
        for group in folded.values():
            if len(group) > 1:
                raise Rejected("PARSE_ERROR", f"{label} members {group} fold to one name")


def check_credential_fields(atx):
    for field in ("agentId", "agentDid", "version", "contentHash", "issuerDid", "atcVersion", "issuedAt", "expiresAt"):
        if not isinstance(atx.get(field), str):
            raise Unprojected(f"{field} is absent or not a string")
    for field in ("trustLevel", "trustScore"):
        if not isinstance(atx.get(field), NumberLiteral):
            raise Unprojected(f"{field} is absent or not a number")
    if not isinstance(atx.get("signatures"), list) or not atx["signatures"]:
        raise Unprojected("signatures is absent or empty")


def integer(value, name):
    if not isinstance(value, NumberLiteral) or not value.is_integer:
        raise Rejected("SIGNATURE_INVALID", f"{name} is not an integer as written")
    if abs(value.value) > MAX_EXACT:
        raise Rejected("SIGNATURE_INVALID", f"{name} {value.text} is outside the I-JSON exact range")
    return value.value


def legacy_bytes(atx):
    """core.md 1.3a.1: eleven pipe-delimited fields; the last is the literal 1.0."""
    level = atx["trustLevel"]
    if not level.is_integer:
        raise Unprojected("trustLevel is not an integer")
    return "|".join(
        [
            atx["agentId"],
            atx["agentDid"],
            atx["version"],
            atx["contentHash"],
            atx.get("buildAttestation") or "",
            atx["issuerDid"],
            str(level.value),
            "%.6f" % atx["trustScore"].value,
            atx["issuedAt"],
            atx["expiresAt"],
            "1.0",
        ]
    ).encode("utf-8")


def declared_purpose_numbers(node):
    """Yield every number in declaredPurpose as the credential wrote it, in document order."""
    if isinstance(node, NumberLiteral):
        yield node
    elif isinstance(node, dict):
        for key in node.names if isinstance(node, _Obj) else node:
            yield from declared_purpose_numbers(node[key])
    elif isinstance(node, list):
        for item in node:
            yield from declared_purpose_numbers(item)


def tbs_v11(atx):
    """core.md 1.3a.2: the explicit projection, rules 1 to 5."""
    scan = atx.get("scanSummary")
    if not isinstance(scan, dict):
        raise Rejected("SIGNATURE_INVALID", "scanSummary is not an object: no signature covers it")
    if set(scan) - SCAN_MEMBERS:
        raise Rejected("SIGNATURE_INVALID", "scanSummary holds a member outside its six names: no signature covers it")
    scan_out = {}
    for name in SCAN_STRINGS:
        value = scan.get(name, "")
        if value is None:
            value = ""
        if not isinstance(value, str):
            raise Rejected("SIGNATURE_INVALID", f"scanSummary.{name} is outside its type")
        scan_out[name] = value
    for name in SCAN_INTEGERS:
        value = scan.get(name)
        if value is None:
            scan_out[name] = 0
        elif isinstance(value, NumberLiteral) and value.is_integer:
            scan_out[name] = integer(value, f"scanSummary.{name}")
        else:
            raise Rejected("SIGNATURE_INVALID", f"scanSummary.{name} is outside its type")
    profile = atx.get("behavioralProfile")
    if profile is not None:
        if not isinstance(profile, dict) or set(profile) != PROFILE_MEMBERS:
            raise Rejected("SIGNATURE_INVALID", "behavioralProfile is not exactly its three members: no signature covers it")
        if not isinstance(profile["checksum"], str):
            raise Rejected("SIGNATURE_INVALID", "behavioralProfile.checksum is outside its type")
        try:
            generated = profile["generatedAt"]
            parse_time(generated, "behavioralProfile.generatedAt")
        except Unprojected:
            raise Rejected("SIGNATURE_INVALID", "behavioralProfile.generatedAt is outside its type")
        profile = {
            "checksum": profile["checksum"],
            "generatedAt": generated,
            "observationDays": integer(profile["observationDays"], "behavioralProfile.observationDays"),
        }
    capabilities = atx.get("capabilities") or []
    chain = atx.get("issuerChain") or []
    if not all(isinstance(x, str) for x in list(capabilities) + list(chain)):
        raise Unprojected("capabilities or issuerChain holds a non-string")
    tbs = {
        "atcVersion": atx["atcVersion"],
        "agentId": atx["agentId"],
        "agentDid": atx["agentDid"],
        "publisher": atx.get("publisher") or "",
        "publisherDid": atx.get("publisherDid") or "",
        "version": atx["version"],
        "contentHash": atx["contentHash"],
        "buildAttestation": atx.get("buildAttestation") or "",
        "capabilities": list(capabilities),
        "behavioralProfile": profile,
        "scanSummary": scan_out,
        "trustScore": "%.6f" % atx["trustScore"].value,
        "trustLevel": integer(atx["trustLevel"], "trustLevel"),
        "issuedAt": atx["issuedAt"],
        "expiresAt": atx["expiresAt"],
        "issuerDid": atx["issuerDid"],
        "issuerChain": list(chain),
    }
    purpose = atx.get("declaredPurpose")
    if purpose is not None and not (isinstance(purpose, dict) and len(purpose) == 0):
        for number in declared_purpose_numbers(purpose):
            if not number.is_integer or abs(number.value) > MAX_EXACT:
                raise Rejected("SIGNATURE_INVALID", f"declaredPurpose number {number.text} is not an in-range integer as written")
        tbs["declaredPurpose"] = plain(purpose)
    return tbs


def signing_bytes(atx):
    version = atx.get("atcVersion")
    if version == "1.0":
        return legacy_bytes(atx), "pipe-form"
    return rfc8785.dumps(tbs_v11(atx)), "jcs-form"


def key_table(verifier_state, atx):
    """Eligible keys, core.md 1.3 step 4: the issuer, plus under 1.1 only a chain DID that is a trusted issuer."""
    trusted = set(verifier_state.get("trustedIssuers") or [])
    authorities = {atx["issuerDid"]}
    if atx["atcVersion"] == "1.1":
        authorities |= {d for d in (atx.get("issuerChain") or []) if d in trusted}
    ed, pq = [], []
    for ref in verifier_state.get("publicKeys") or []:
        key_id = ref.get("keyId") or ""
        if key_id and key_id.split("#", 1)[0] not in authorities:
            continue
        try:
            raw = bytes.fromhex(ref["publicKeyHex"])
        except ValueError:
            continue
        if ref["algorithm"] == "Ed25519" and len(raw) == 32:
            ed.append(raw)
        elif ref["algorithm"] == "ML-DSA-65" and len(raw) == MLDSA65_PUBLIC_KEY_SIZE:
            pq.append(raw)
    return ed, pq


def b64(value):
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError, TypeError):
        raise Rejected("SIGNATURE_INVALID", "signature value is not base64")


def verify_signatures(atx, payload, verifier_state, notes):
    ed_keys, pq_keys = key_table(verifier_state, atx)
    ed_ok, pq_ok, signers = 0, 0, set()
    for entry in atx["signatures"]:
        if not isinstance(entry, dict) or set(entry) - SIGNATURE_MEMBERS:
            raise Unprojected("signature entry outside its three members")
        algorithm = entry.get("algorithm")
        signature = b64(entry.get("value"))
        if algorithm == "Ed25519":
            hit = None
            for raw in ed_keys:
                try:
                    Ed25519PublicKey.from_public_bytes(raw).verify(signature, payload)
                    hit = raw
                    break
                except InvalidSignature:
                    continue
            if hit is None:
                raise Rejected("SIGNATURE_INVALID", f"Ed25519 signature {entry.get('keyId')} verifies under no eligible key")
            ed_ok += 1
            signers.add(hit)
        elif algorithm == "ML-DSA-65":
            hit = False
            for raw in pq_keys:
                try:
                    mldsa.MLDSA65PublicKey.from_public_bytes(raw).verify(signature, payload)
                    hit = True
                    break
                except InvalidSignature:
                    continue
                except UnsupportedAlgorithm:
                    raise Unprojected("ML-DSA-65 is not available in this cryptography build")
            if not hit:
                raise Rejected("SIGNATURE_INVALID", f"ML-DSA-65 signature {entry.get('keyId')} verifies under no eligible key")
            pq_ok += 1
        else:
            raise Rejected("SIGNATURE_INVALID", f"suite {algorithm!r} is not implemented, so the declared signature does not verify")
    if ed_ok + pq_ok == 0:
        raise Rejected("SIGNATURE_INVALID", "no valid signatures")
    if pq_ok and not ed_ok:
        raise Rejected("SIGNATURE_INVALID", "an ML-DSA-65 entry has no verifying Ed25519 companion (core.md 13)")
    required = plain(verifier_state.get("requiredSignatures"))
    if required is not None and len(signers) < required:
        raise Rejected("SIGNATURE_INVALID", f"threshold not met: {len(signers)} distinct Ed25519 keys of {required}")
    notes.append(f"ed25519 {ed_ok} verified, ml-dsa-65 {pq_ok} verified, {len(signers)} distinct Ed25519 keys")


def observe(record, notes):
    """Return (ACCEPT | REJECT[category]) from the credential and verifier state alone."""
    atx = record["atx"]
    verifier_state = record["verifierState"]
    if not isinstance(atx, dict):
        raise Rejected("PARSE_ERROR", "atx is not an object")
    strict_parse_checks(atx)
    check_credential_fields(atx)
    if atx["atcVersion"] not in ("1.0", "1.1"):
        raise Rejected("UNSUPPORTED_VERSION", f"atcVersion {atx['atcVersion']!r}")
    clock = parse_time(verifier_state["clockRfc3339"], "clockRfc3339")
    expires = parse_time(atx["expiresAt"], "expiresAt")
    parse_time(atx["issuedAt"], "issuedAt")
    verdicts = {tolerance: clock - tolerance > expires for tolerance in (0, 60)}
    if verdicts[0] != verdicts[60]:
        raise Unprojected("expiry verdict depends on the clock-skew tolerance (0 versus 60 seconds)")
    if verdicts[0]:
        raise Rejected("EXPIRED", f"expiresAt is {clock - expires} seconds before the clock")
    if atx.get("revoked") is True:
        raise Rejected("REVOKED", "the revoked flag is true")
    for entry in ((verifier_state.get("crl") or {}).get("entries")) or []:
        if entry.get("agentId") == atx["agentId"]:
            raise Rejected("REVOKED", "agentId is on the CRL")
    if atx["issuerDid"] not in (verifier_state.get("trustedIssuers") or []):
        raise Rejected("UNTRUSTED_ISSUER", f"{atx['issuerDid']} is not a trusted issuer")
    payload, form = signing_bytes(atx)
    notes.append(f"{form} {len(payload)} bytes sha256 {hashlib.sha256(payload).hexdigest()[:16]}")
    verify_signatures(atx, payload, verifier_state, notes)
    return "ACCEPT", None, payload


def read_expected(record):
    exp = record.get("expected") or {}
    result = exp.get("verifyResult")
    return result, exp.get("rejectCategory")


def label(result, category):
    return result if result == "ACCEPT" else f"REJECT[{category}]"


def run_fixture(path, key_expected):
    raw = path.read_bytes()
    notes = []
    try:
        record = parse_text(raw.decode("utf-8"))
        want_result, want_category = read_expected(record)
        want = label(want_result, want_category)
    except Dup as exc:
        # A duplicate member inside the fixture wrapper cannot be told apart here from one in the credential.
        record = None
        want = None
        dup = str(exc)
    except Exception as exc:
        return "cannot-tell", f"unreadable fixture: {type(exc).__name__}", None
    try:
        if record is None:
            raise Rejected("PARSE_ERROR", f"duplicate member {dup!r}")
        result, category, _ = observe(record, notes)
        observed = label(result, category)
    except Rejected as exc:
        observed = label("REJECT", exc.category)
        notes.append(exc.reason)
    except Unprojected as exc:
        return "cannot-tell", f"{exc}", want
    except Exception as exc:
        return "cannot-tell", f"{type(exc).__name__}: {exc}", want
    if want is None:
        # the duplicate sat in the wrapper or credential; the kit's answer key is the only expectation
        want = key_expected
    agrees = observed == want and (key_expected is None or observed == key_expected)
    detail = f"observed {observed}; expected {want}"
    if key_expected and key_expected != want:
        detail += f"; answer key {key_expected}"
    detail += "; " + "; ".join(notes)
    return ("agrees" if agrees else "contradicted"), detail, want


def main(argv):
    only = set()
    args = []
    it = iter(argv)
    for a in it:
        if a == "--only":
            only.update(next(it).split(","))
        else:
            args.append(a)
    root = pathlib.Path(args[0])
    fixtures = root / "fixtures" if (root / "fixtures").is_dir() else root
    key = {}
    answer = root / "conformance.json"
    if answer.exists():
        for item in json.loads(answer.read_text())["requirements"]:
            key[pathlib.Path(item["fixture"]).name] = item["expected"]
    counts = {"agrees": 0, "contradicted": 0, "cannot-tell": 0}
    for p in sorted(fixtures.glob("*.json")):
        if only and p.stem not in only:
            continue
        verdict, detail, _ = run_fixture(p, key.get(p.name))
        counts[verdict] += 1
        digest = hashlib.sha256(p.read_bytes()).hexdigest()
        print(f"{p.stem}\t{verdict}\t{detail}\tsha256={digest}")
    print(f"# summary: {counts['agrees']} agrees, {counts['contradicted']} contradicted, {counts['cannot-tell']} cannot-tell of {sum(counts.values())}")


if __name__ == "__main__":
    main(sys.argv[1:])
