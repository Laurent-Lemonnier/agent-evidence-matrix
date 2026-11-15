"""Second-angle check: flip one byte in a copy and show the matching layer flips.
usage: aep_tamper_check.py <eatf test-vectors dir> <round1 vectors dir> <trusted_issuers.json> <scratch dir>"""
import base64, copy, importlib.util, io, json, pathlib, sys, zipfile

here = pathlib.Path(__file__).parent
def load(n):
    s = importlib.util.spec_from_file_location(n, here / f"{n}.py"); m = importlib.util.module_from_spec(s); s.loader.exec_module(m); return m
eatf, sbx = load("aep_eatf_sigs"), load("aep_sandbox_adapter")

def flip(b, i=None):
    b = bytearray(b); b[len(b)//2 if i is None else i] ^= 1; return bytes(b)

def eatf_case(root, vec, entry, mutate, label):
    p = pathlib.Path(root) / vec / "package.aep"
    with zipfile.ZipFile(p) as z: e = {n: z.read(n) for n in z.namelist()}
    before = {k: v[0] for k, v in eatf_run(e).items()}
    e[entry] = mutate(e[entry])
    after = {k: v[0] for k, v in eatf_run(e).items()}
    flipped = [k for k in before if before[k] != after[k]]
    print(f"eatf {vec} mutate {entry} ({label})\tbefore={before}\tafter={after}\tlayers flipped={flipped}")

def eatf_run(e):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for n, v in e.items(): z.writestr(n, v)
    tmp = pathlib.Path(sys.argv[4]) / "t.aep"; tmp.write_bytes(buf.getvalue()); return eatf.run(tmp)

def main():
    root = sys.argv[1]
    pathlib.Path(sys.argv[4]).mkdir(parents=True, exist_ok=True)
    eatf_case(root, "valid/minimal-roundtrip", "canonical.bin", flip, "canonical bytes")
    eatf_case(root, "valid/minimal-roundtrip", "signature.sig", lambda b: base64.b64encode(flip(base64.b64decode(b))), "RSA signature")
    eatf_case(root, "valid/hybrid-mldsa65", "signature_pqc.sig", lambda b: base64.b64encode(flip(base64.b64decode(b))), "ML-DSA signature")
    eatf_case(root, "valid/minimal-roundtrip", "overt_receipt.json", lambda b: b.replace(b"allow", b"alloW") if b"allow" in b else flip(b), "receipt")
    def tsr(b):
        d = bytearray(base64.b64decode(b)); d[-5] ^= 1; return base64.b64encode(bytes(d))
    eatf_case(root, "valid/minimal-roundtrip", "timestamp.tsr", tsr, "last signature byte of the token")
    anchors = json.loads(pathlib.Path(sys.argv[3]).read_text())["issuers"]
    vec = pathlib.Path(sys.argv[2]); cases = {c["file"]: c for c in json.loads((vec / "cases.json").read_text())}
    p = json.loads((vec / "r1-01.aep.json").read_text()); c = cases["r1-01.aep.json"]
    print("sandbox r1-01 untouched\t", sbx.verify(p, anchors, c["now"], c["consumed"]), sbx.layers(p))
    for label, path in [("receipt_hash", ("receipt_hash",)), ("aep_sig", ("aep_sig",)),
                        ("credential.sig", ("credential", "sig")), ("mandate.sig", ("mandate", "sig")),
                        ("action.args.amount (signed core)", ("action", "args", "amount"))]:
        q = copy.deepcopy(p); d = q
        for k in path[:-1]: d = d[k]
        v = d[path[-1]]
        d[path[-1]] = (v + 1) if isinstance(v, int) else ("0" if v[0] != "0" else "1") + v[1:]
        print(f"sandbox r1-01 flip {label}\t", sbx.verify(q, anchors, c["now"], c["consumed"]), sbx.layers(q))
main()
