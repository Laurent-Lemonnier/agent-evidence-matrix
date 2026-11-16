"""Seal an answer set before it is published: SEAL.sha256 over the files, timestamped by two RFC 3161 authorities.

    python tools/seal.py make <seal dir> <file> [<file> ...]
        writes <seal dir>/SEAL.sha256 (one "sha256  name" line per file, names relative to the current
        directory), asks FreeTSA and DigiCert for an RFC 3161 token over it (seal-freetsa.tsr,
        seal-digicert.tsr) and stores FreeTSA's CA and TSA certificates beside them
    python tools/seal.py verify <seal dir> [--check-files]
        verifies each token over SEAL.sha256 with the system `openssl ts` (FreeTSA against its stored
        certificates, DigiCert against the system store) and prints its time and serial; with
        --check-files, also recomputes every listed file's SHA-256 from the current directory

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


def verify(seal_dir, check_files=False):
    seal = seal_dir / "SEAL.sha256"
    failed = False
    if check_files:
        for line in seal.read_text().splitlines():
            want, name = line.split(None, 1)
            have = hashlib.sha256(pathlib.Path(name).read_bytes()).hexdigest() if pathlib.Path(name).is_file() else "missing"
            ok = have == want
            failed |= not ok
            print(f"{'PASS' if ok else 'DIFF'}  file {name}: {have[:16]}")
    for token in sorted(seal_dir.glob("*.tsr")):
        if token.name == "seal-freetsa.tsr":
            args = ["-CAfile", str(seal_dir / "freetsa-cacert.pem"), "-untrusted", str(seal_dir / "freetsa-tsa.crt")]
        elif (seal_dir / (token.stem + "-ca.pem")).is_file():  # a token from another authority, its CA stored beside it
            args = ["-CAfile", str(seal_dir / (token.stem + "-ca.pem"))]
        else:
            args = ["-CAfile", SYSTEM_BUNDLE]
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
    if len(argv) in (2, 3) and argv[0] == "verify" and argv[2:] in ([], ["--check-files"]):
        return verify(pathlib.Path(argv[1]), check_files=argv[2:] == ["--check-files"])
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
