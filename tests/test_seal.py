"""The seal tool's verify refuses a changed file, a changed seal, a missing token and an authority the sealer chose.

A local RFC 3161 authority stands in for FreeTSA and DigiCert; the verifier names it with --authority.
"""
import subprocess
import sys
from pathlib import Path

import pytest

SEAL = Path(__file__).resolve().parents[1] / "tools" / "seal.py"
TS_CNF = """
[ tsa ]
default_tsa = tsa_config
[ tsa_config ]
serial = {d}/serial
crypto_device = builtin
signer_digest = sha256
default_policy = 1.2.3.4.1
digests = sha256
accuracy = secs:1
ordering = no
tsa_name = no
ess_cert_id_chain = no
ess_cert_id_alg = sha256
"""


LOCAL = ("--authority", "seal-local.tsr=ca.pem")  # the verifier names the test authority; its CA is outside the seal


def run(*args, cwd):
    return subprocess.run(args, cwd=cwd, capture_output=True, text=True)


@pytest.fixture
def sealed(tmp_path):
    d = tmp_path
    (d / "answers.json").write_text('{"r1-01":"ALLOW"}\n')
    seal = d / "seal"
    seal.mkdir()
    (seal / "SEAL.sha256").write_text(run(sys.executable, "-c",
        "import hashlib;print(hashlib.sha256(open('answers.json','rb').read()).hexdigest()+'  answers.json')", cwd=d).stdout)
    (d / "serial").write_text("01\n")
    (d / "ts.cnf").write_text(TS_CNF.format(d=d))
    (d / "ext.cnf").write_text("basicConstraints=CA:FALSE\nextendedKeyUsage=critical,timeStamping\n")
    for cmd in (
        ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
         "-keyout", "ca.key", "-out", "ca.pem", "-subj", "/CN=test ca", "-days", "2"],
        ["openssl", "req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
         "-keyout", "tsa.key", "-out", "tsa.csr", "-subj", "/CN=test tsa"],
        ["openssl", "x509", "-req", "-in", "tsa.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial",
         "-out", "tsa.crt", "-days", "2", "-extfile", "ext.cnf"],
        ["openssl", "ts", "-query", "-data", "seal/SEAL.sha256", "-sha256", "-cert", "-out", "q.tsq"],
        ["openssl", "ts", "-reply", "-queryfile", "q.tsq", "-signer", "tsa.crt", "-inkey", "tsa.key",
         "-config", "ts.cnf", "-out", "seal/seal-local.tsr"],
    ):
        out = run(*cmd, cwd=d)
        assert out.returncode == 0, out.stderr
    return d


def test_an_untouched_seal_verifies(sealed):
    out = run(sys.executable, str(SEAL), "verify", "seal", "--check-files", *LOCAL, cwd=sealed)
    assert out.returncode == 0, out.stdout + out.stderr
    assert "PASS  file answers.json" in out.stdout and "PASS  token seal-local.tsr" in out.stdout


def test_a_changed_file_fails(sealed):
    (sealed / "answers.json").write_text('{"r1-01":"DENY"}\n')
    out = run(sys.executable, str(SEAL), "verify", "seal", "--check-files", *LOCAL, cwd=sealed)
    assert out.returncode == 1 and "DIFF  file answers.json" in out.stdout


def test_a_changed_seal_fails_the_token(sealed):
    seal = sealed / "seal" / "SEAL.sha256"
    seal.write_text(seal.read_text().replace("answers.json", "answers.JSON"))
    out = run(sys.executable, str(SEAL), "verify", "seal", *LOCAL, cwd=sealed)
    assert out.returncode == 1 and "DIFF  token seal-local.tsr" in out.stdout


# Counter-examples from the adversarial read: a seal with no token verified (exit 0), and a token under a
# CA the sealer stored in the seal directory verified, so a sealer could mint a timestamp with any time.

def test_a_seal_with_no_token_fails(sealed):
    (sealed / "seal" / "seal-local.tsr").unlink()
    out = run(sys.executable, str(SEAL), "verify", "seal", *LOCAL, cwd=sealed)
    assert out.returncode == 1 and "DIFF  token seal-local.tsr: missing" in out.stdout
    out = run(sys.executable, str(SEAL), "verify", "seal", cwd=sealed)
    assert out.returncode == 1 and "seal-freetsa.tsr: missing" in out.stdout and "seal-digicert.tsr: missing" in out.stdout


def test_a_token_whose_authority_the_verifier_did_not_name_fails(sealed):
    (sealed / "seal" / "seal-local-ca.pem").write_text((sealed / "ca.pem").read_text())
    out = run(sys.executable, str(SEAL), "verify", "seal", cwd=sealed)
    assert out.returncode == 1 and "seal-local.tsr: from an authority the verifier did not name" in out.stdout


def test_a_self_minted_root_stored_under_the_freetsa_name_fails(sealed):
    seal = sealed / "seal"
    (seal / "seal-local.tsr").rename(seal / "seal-freetsa.tsr")
    (seal / "freetsa-cacert.pem").write_text((sealed / "ca.pem").read_text())
    (seal / "freetsa-tsa.crt").write_text((sealed / "tsa.crt").read_text())
    out = run(sys.executable, str(SEAL), "verify", "seal", cwd=sealed)
    assert out.returncode == 1 and "not the pinned" in out.stdout
    assert "PASS  token seal-freetsa.tsr" not in out.stdout


def test_a_ca_file_inside_the_seal_directory_is_refused(sealed):
    (sealed / "seal" / "mine.pem").write_text((sealed / "ca.pem").read_text())
    out = run(sys.executable, str(SEAL), "verify", "seal", "--authority", "seal-local.tsr=seal/mine.pem", cwd=sealed)
    assert out.returncode == 2
