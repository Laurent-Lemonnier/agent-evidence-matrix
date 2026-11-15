"""Runner: their Python CLI (aqta-verify-receipt, packages/verify-receipt-py at the pinned commit) on their own vectors.

Usage: aqta_theirs_cli_runner.py <checkout> <their-cli>
For ATTESTATION-v1 (test-vectors/{valid,invalid}, key from test-vectors/README.md), ACTION-v1
(test-vectors/action/{valid,invalid}, --profile action-1, key from its README) and the byte-level inputs
(test-vectors/bytes/expected.json: expected_exit and sha256 per file), it runs `<cli> <file> --key K -q` and compares
the exit code with the stated one (0 valid, 1 invalid, 2 malformed). This harness only drives their CLI.
"""
import hashlib
import json
import pathlib
import subprocess
import sys

root, cli = pathlib.Path(sys.argv[1]), sys.argv[2]
ATT = "alWzEnrA_z9McN9z_MFfQCnH9mVgOwRZ26wrI7oix4E"
ACT = "pOaccW6Csyo1POtxjixPH80oux9--YC1tzzaENT4vQ0"
jobs = []
for want, code in (("valid", 0), ("invalid", 1)):
    jobs += [("ATTESTATION-v1", p, code, ["--key", ATT]) for p in sorted((root / "test-vectors" / want).glob("*.json"))]
    jobs += [("ACTION-v1", p, code, ["--key", ACT, "--profile", "action-1"])
             for p in sorted((root / "test-vectors/action" / want).glob("*.json"))]
exp = json.loads((root / "test-vectors/bytes/expected.json").read_text())
pin_ok = True
for name, v in sorted(exp["vectors"].items()):
    p = root / "test-vectors/bytes" / name
    if hashlib.sha256(p.read_bytes()).hexdigest() != v["sha256"]:
        print("PIN MISMATCH bytes/%s" % name)
        pin_ok = False
    jobs.append(("bytes", p, v["expected_exit"], ["--key", exp["trusted_public_key"]]))
agree = 0
for fam, p, code, extra in jobs:
    rc = subprocess.run([cli, str(p), *extra, "-q"], capture_output=True, timeout=60).returncode
    ok = rc == code
    agree += ok
    print("%s %s %s expected exit %d got %d" % ("AGREE" if ok else "DIFF ", fam, p.relative_to(root).as_posix(), code, rc))
print("SUMMARY %d of %d agree%s" % (agree, len(jobs), "" if pin_ok else "; a bytes pin did not match"))
sys.exit(0 if agree == len(jobs) and pin_ok else 1)
