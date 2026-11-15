"""tamper_sokolov.py <aep-sandbox> <run-dir> <work-dir>: change one thing in a copy of the run, rerun the adapter, report what flips."""
import os, re, shutil, subprocess, sys

sandbox, run, work = sys.argv[1:4]
adapter = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sokolov_aep_rats_adapter.py")


def adapter_lines(d):
    p = subprocess.run([sys.executable, "-I", adapter, sandbox, d], capture_output=True, text=True)
    return p.stdout.splitlines() + ([p.stderr.strip().splitlines()[-1]] if p.returncode else [])


def mutate(name, fn):
    d = os.path.join(work, name)
    shutil.rmtree(d, ignore_errors=True)
    shutil.copytree(run, d)
    fn(d)
    return adapter_lines(d)


def flip(fname, off):
    def f(d):
        b = bytearray(open(os.path.join(d, fname), "rb").read())
        b[off] ^= 1
        open(os.path.join(d, fname), "wb").write(b)
    return f


def edit(fname, pat, rep):
    def f(d):
        t = open(os.path.join(d, fname)).read()
        n = re.sub(pat, rep, t, count=1)
        assert n != t
        open(os.path.join(d, fname), "w").write(n)
    return f


base = adapter_lines(run)
cases = [
    ("runA.sig one bit (V1 signature)", flip("runA.sig", 40)),
    ("run.log nonce A one hex digit (V1 extraData)", edit("run.log", r"(fresh nonce \(run A\) = )(.)", lambda m: m.group(1) + ("0" if m.group(2) != "0" else "1"))),
    ("aep.json one bit (record digest)", flip("aep.json", 20)),
    ("runB.msg one bit in pcrDigest (V2 composite)", flip("runB.msg", 130)),
    ("reference-pcrs.txt one hex digit (PCR recompute)", edit("reference-pcrs.txt", r"(0 : 0x)(.)", lambda m: m.group(1) + ("0" if m.group(2) != "0" else "1"))),
    ("ak.pub modulus one bit (every signature)", flip("ak.pub", 60)),
]
flipped = 0
for name, fn in cases:
    got = mutate(name.split()[0].replace(".", "_") + str(cases.index((name, fn))), fn)
    diff = [l for l, b in zip(got, base) if l != b] or ([got[-1]] if got != base else [])
    flipped += bool(diff)
    print("CASE %s -> %s" % (name, "FLIPS" if diff else "NO CHANGE"))
    for l in diff[:2]:
        print("    " + l[:200])
print("TAMPER %d of %d changed the adapter output" % (flipped, len(cases)))
