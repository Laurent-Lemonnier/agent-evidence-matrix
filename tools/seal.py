"""Seal an answer set before it is published: SEAL.sha256 over the files, timestamped by two RFC 3161 authorities.

    python tools/seal.py make <seal dir> <file> [<file> ...]
        writes <seal dir>/SEAL.sha256 (one "sha256  name" line per file, names relative to the current
        directory), asks FreeTSA and DigiCert for an RFC 3161 token over it (seal-freetsa.tsr,
        seal-digicert.tsr) and stores FreeTSA's CA and TSA certificates beside them
    python tools/seal.py verify <seal dir> [--check-files] [--authority <token name>=<CA file> ...]
        requires one token per authority and verifies each over SEAL.sha256 with the system `openssl ts`:
        FreeTSA against its root, whose SHA-256 fingerprint is pinned here (the copy stored in the seal
        directory is only used when it carries that fingerprint), DigiCert against the system store. A
        missing token, or a token from an authority the verifier did not name, fails. --authority
        replaces the two defaults with authorities the verifier names (a CA file outside the seal
        directory); with --check-files, it also recomputes every listed file's SHA-256

Trust never comes from the seal directory: a sealer who could choose the authority could mint a
token with any time.

A token fixes the time of the commitment to the files' digests, not their contents: publish the seal and
the tokens first, the files when the answers are due. Exit 0 when every check holds, 1 when one fails,
2 on a usage or network error.
"""
from __future__ import annotations

import hashlib
import pathlib
import subprocess
import sys
import urllib.request

AUTHORITIES = {
    "seal-freetsa.tsr": "https://freetsa.org/tsr",
    "seal-digicert.tsr": "http://timestamp.digicert.com",
}
FREETSA_CERTS = {
    "freetsa-cacert.pem": "https://freetsa.org/files/cacert.pem",
    "freetsa-tsa.crt": "https://freetsa.org/files/tsa.crt",
}
SYSTEM_BUNDLE = "/etc/ssl/certs/ca-certificates.crt"
# SHA-256 over the DER form of the FreeTSA root (O=Free TSA, OU=Root CA, CN=www.freetsa.org, valid to 2041-03-07),
# read from https://freetsa.org/files/cacert.pem on 2026-11-15.
FREETSA_ROOT_SHA256 = "a6379e7cecc05faa3cbf076013d745e327bbbaa38c0b9af22469d4701d18aabc"


def sh(*args, data=None):
    r = subprocess.run(args, capture_output=True, input=data)
    return r.returncode, r.stdout, r.stderr.decode("utf-8", "replace")


def seal_text(files):
    return "".join(f"{hashlib.sha256(pathlib.Path(f).read_bytes()).hexdigest()}  {f}\n" for f in files)


def make(seal_dir, files):
    seal_dir.mkdir(parents=True, exist_ok=True)
    (seal_dir / "SEAL.sha256").write_text(seal_text(files))
    rc, query, err = sh("openssl", "ts", "-query", "-data", str(seal_dir / "SEAL.sha256"), "-sha256", "-cert")
    if rc:
        print(f"openssl ts -query failed: {err}", file=sys.stderr)
        return 2
    (seal_dir / "seal.tsq").write_bytes(query)
    for name, url in {**AUTHORITIES, **FREETSA_CERTS}.items():
        is_query = name.endswith(".tsr")
        req = urllib.request.Request(url, data=query if is_query else None,
                                     headers={"Content-Type": "application/timestamp-query"} if is_query else {})
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                (seal_dir / name).write_bytes(resp.read())
        except OSError as exc:
            print(f"{url}: {exc}", file=sys.stderr)
            return 2
    return verify(seal_dir, check_files=True)


def der_sha256(pem_path):
    rc, out, _ = sh("openssl", "x509", "-in", str(pem_path), "-noout", "-fingerprint", "-sha256")
    return out.decode().split("=", 1)[1].strip().replace(":", "").lower() if rc == 0 and b"=" in out else None


def default_authorities(seal_dir):
    """Token name -> (openssl trust arguments, a problem that refuses the token before it is checked)."""
    ca = seal_dir / "freetsa-cacert.pem"
    have = der_sha256(ca) if ca.is_file() else None
    problem = None if have == FREETSA_ROOT_SHA256 else (
        f"stored FreeTSA root has fingerprint {have or 'unreadable'}, not the pinned {FREETSA_ROOT_SHA256[:16]}...")
    return {
        "seal-freetsa.tsr": (["-CAfile", str(ca), "-untrusted", str(seal_dir / "freetsa-tsa.crt")], problem),
        "seal-digicert.tsr": (["-CAfile", SYSTEM_BUNDLE], None),
    }


def verify(seal_dir, check_files=False, authorities=None):
    seal = seal_dir / "SEAL.sha256"
    failed = False
    inside = [str(ca) for ca in (authorities or {}).values()
              if pathlib.Path(ca).resolve().is_relative_to(seal_dir.resolve())]
    if inside:
        print(f"a CA file inside the seal directory is the sealer's choice, not the verifier's: {inside}", file=sys.stderr)
        return 2
    trust = ({name: (["-CAfile", str(ca)], None) for name, ca in authorities.items()} if authorities
             else default_authorities(seal_dir))
    if check_files:
        for line in seal.read_text().splitlines():
            want, name = line.split(None, 1)
            have = hashlib.sha256(pathlib.Path(name).read_bytes()).hexdigest() if pathlib.Path(name).is_file() else "missing"
            ok = have == want
            failed |= not ok
            print(f"{'PASS' if ok else 'DIFF'}  file {name}: {have[:16]}")
    for token in sorted(seal_dir.glob("*.tsr")):
        if token.name not in trust:
            failed = True
            print(f"DIFF  token {token.name}: from an authority the verifier did not name")
    for name, (args, problem) in sorted(trust.items()):
        token = seal_dir / name
        if not token.is_file():
            failed = True
            print(f"DIFF  token {name}: missing")
            continue
        if problem:
            failed = True
            print(f"DIFF  token {name}: {problem}")
            continue
        rc, out, err = sh("openssl", "ts", "-verify", "-data", str(seal), "-in", str(token), *args)
        _, text, _ = sh("openssl", "ts", "-reply", "-in", str(token), "-text")
        text = text.decode("utf-8", "replace")
        when = next((l.split(":", 1)[1].strip() for l in text.splitlines() if l.startswith("Time stamp:")), "?")
        serial = next((l.split(":", 1)[1].strip() for l in text.splitlines() if l.startswith("Serial number:")), "?")
        ok = rc == 0
        failed |= not ok
        print(f"{'PASS' if ok else 'DIFF'}  token {token.name}: time {when}, serial {serial}"
              + ("" if ok else f" ({(out.decode() + err).strip().splitlines()[-1] if (out or err) else 'verify failed'})"))
    print(f"SEAL.sha256 sha256 {hashlib.sha256(seal.read_bytes()).hexdigest()}")
    return 1 if failed else 0


def main(argv):
    if len(argv) >= 3 and argv[0] == "make":
        return make(pathlib.Path(argv[1]), argv[2:])
    if len(argv) >= 2 and argv[0] == "verify":
        rest, check, named = argv[2:], False, {}
        while rest:
            if rest[0] == "--check-files":
                check, rest = True, rest[1:]
            elif rest[0] == "--authority" and len(rest) > 1 and "=" in rest[1]:
                name, ca = rest[1].split("=", 1)
                if not name.endswith(".tsr") or name in named:
                    break
                named[name], rest = pathlib.Path(ca).resolve(), rest[2:]
            else:
                break
        if not rest:
            return verify(pathlib.Path(argv[1]), check_files=check, authorities=named)
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
