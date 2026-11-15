"""Adapter: the two RFC 3161 tokens over the Round 1 seal (SEAL.sha256).

Claims read from timestamps/README.md: SHA-256 of SEAL.sha256 is 8d213af4...7303;
seal-freetsa.tsr verifies against the FreeTSA certificates and shows
2026-11-14 05:11:11 UTC, serial 0x0A019721; seal-digicert.tsr verifies against
the system store and shows 2026-11-14 05:11:11 UTC, serial
0x220EF8DFD9925DE96D5B3C4E28ED05BD. The checks run the system `openssl ts`
(not a Tyche tool). A tamper row repeats the check on a seal with one byte flipped.

usage: aep_seal_timestamps.py <dir with SEAL.sha256 copy and the timestamps dir files> <seal file> [<ca bundle>]
"""
import hashlib
import pathlib
import re
import subprocess
import sys

CLAIM_SHA = "8d213af4da148ed8779a9c4663a02e2b847f2748311cba08f973d33ab2fb7303"
CLAIM = {
    "seal-freetsa.tsr": ("Nov 14 05:11:11 2026 GMT", "0x0A019721"),
    "seal-digicert.tsr": ("Nov 14 05:11:11 2026 GMT", "0x220EF8DFD9925DE96D5B3C4E28ED05BD"),
}


def sh(*a):
    r = subprocess.run(a, capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr


def check(ts, seal, bundle, label):
    ok_all = True
    for tok, (when, serial) in CLAIM.items():
        if tok == "seal-freetsa.tsr":
            rc, out = sh("openssl", "ts", "-verify", "-data", str(seal), "-in", str(ts / tok),
                         "-CAfile", str(ts / "freetsa-cacert.pem"), "-untrusted", str(ts / "freetsa-tsa.crt"))
        else:
            rc, out = sh("openssl", "ts", "-verify", "-data", str(seal), "-in", str(ts / tok), "-CAfile", bundle)
        ver = rc == 0 and "Verification: OK" in out
        _, txt = sh("openssl", "ts", "-reply", "-in", str(ts / tok), "-text")
        t = re.search(r"Time stamp: (.*)", txt)
        s = re.search(r"Serial number: (\S+)", txt)
        match = bool(t and s and t.group(1).strip() == when and s.group(1) == serial)
        print(f"{label}\t{tok}\tverify={'OK' if ver else 'FAILED'}\ttime+serial matches README={match}")
        ok_all &= ver and match
    return ok_all


def main(ts, seal, bundle="/etc/ssl/certs/ca-certificates.crt"):
    ts, seal = pathlib.Path(ts), pathlib.Path(seal)
    sha = hashlib.sha256(seal.read_bytes()).hexdigest()
    print(f"seal\tsha256={sha}\tmatches README={sha == CLAIM_SHA}")
    check(ts, seal, bundle, "seal")
    b = bytearray(seal.read_bytes())
    b[0] ^= 1
    tmp = ts.parent / "tamper-SEAL.sha256"
    tmp.write_bytes(bytes(b))
    check(ts, tmp, bundle, "tampered-seal")
    tmp.unlink()


if __name__ == "__main__":
    main(*sys.argv[1:])
