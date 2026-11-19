"""b7n0de verifiers: Konrad Gruszka's two verifiers run on the agent-evidence-vectors corpora they were written for.

Runs his own runner (`run_all.py` of the retained source under `records/b7n0de-verifiers/`) against a clone of
agent-evidence-vectors that holds the pinned commit, then reads the fresh result files it wrote and prints one line
per corpus member, the counts, and what the 38 members whose verdict differs from MANIFEST.json carry. Nothing
about his verdicts is taken from his results package: the verdicts are the ones his verifier produced in this run.

    <corpus>/<id>\t<his verdict>\t<manifest verdict>\t<equal|differ>\t<members the record carries that are not in -03>

usage: b7n0de_verifiers_adapter.py <records/b7n0de-verifiers> <agent-evidence-vectors clone> [--mutation]

--mutation flips one character of the signature of the first valid record of the audit-record corpus (in memory;
the clone is not touched) and prints his verdict on the record before and after. A mutation that does not turn the
verdict from valid to malformed is a broken comparison, and a missing record is a setup error.

The members counted as "not in -03" are detected here from the record bytes, not from his code: `supersedes` and
`asset` in `consumption`, the top-level members `principal` and `dataSubject`, and a `held` entry with a member
beyond operationKey, requestDigest, amount and payee. Revision 03 of the draft defines none of them.

Exit codes: 0 the run completed (his runner exited 0: every pin holds and the fresh result files equal his committed
ones byte for byte); 1 under --mutation, the comparison failed as it must; 2 setup error (a pin does not hold, the
runner failed, the clone lacks the commit, python lacks cryptography).
"""
from __future__ import annotations

import base64
import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import tempfile

NOT_IN_03 = ("supersedes", "asset", "principal", "dataSubject", "held-extra")


def die(msg: str) -> "None":
    print("setup error: " + msg, file=sys.stderr)
    sys.exit(2)


def git_blob(clone: str, commit: str, path: str) -> bytes:
    out = subprocess.run(["git", "-C", clone, "cat-file", "blob", f"{commit}:{path}"], capture_output=True)
    if out.returncode != 0:
        die(f"{commit[:12]}:{path} is not in {clone}: {out.stderr.decode(errors='replace').strip()}")
    return out.stdout


def statements(raw: bytes):
    """Every statement (decoded DSSE payload) of a member file: a record, a set of records or a retained record."""
    found = []

    def walk(x):
        if isinstance(x, dict):
            if isinstance(x.get("payload"), str):
                try:
                    found.append(json.loads(base64.b64decode(x["payload"] + "==")))
                except ValueError:
                    pass
            else:
                for v in x.values():
                    walk(v)
        elif isinstance(x, list):
            for v in x:
                walk(v)
    try:
        walk(json.loads(raw))
    except (ValueError, RecursionError):
        pass  # bytes that are not JSON carry no member to count; his verifier refuses them on its own
    return found


def carries(raw: bytes) -> list[str]:
    seen = set()
    for st in statements(raw):
        p = st.get("predicate", st) if isinstance(st, dict) else None
        if not isinstance(p, dict):
            continue
        for name in ("principal", "dataSubject"):
            if name in p:
                seen.add(name)
        ev = p.get("evaluation")
        for entry in ev.get("inputs", []) if isinstance(ev, dict) else []:
            c = entry.get("consumption") if isinstance(entry, dict) else None
            if not isinstance(c, dict):
                continue
            for name in ("supersedes", "asset"):
                if name in c:
                    seen.add(name)
            for held in c.get("held", []):
                if isinstance(held, dict) and set(held) - {"operationKey", "requestDigest", "amount", "payee"}:
                    seen.add("held-extra")
    return [n for n in NOT_IN_03 if n in seen]


def load_verifier(tools: str):
    spec = importlib.util.spec_from_file_location("aar_verifier", os.path.join(tools, "aar_verifier.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def mutation(src: str, clone: str, commit: str, corpus: str) -> int:
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        die("python lacks the cryptography package")
    tools = os.path.join(src, "audit-record", "agent_evidence_01", "tools")
    A = load_verifier(tools)
    man = json.loads(git_blob(clone, commit, corpus + "/MANIFEST.json"))
    obs = man["keys"]["observer"]
    pinned = {obs["keyid"]: Ed25519PublicKey.from_public_bytes(bytes.fromhex(obs["publicKey"]))}
    target = next((v for v in man["vectors"] if v["kind"] == "accept" and v["file"].startswith("statements/")), None)
    if target is None:
        die("no accept record in the audit-record manifest")
    env = json.loads(git_blob(clone, commit, corpus + "/" + target["file"]))
    before = A.verify_record(env, pinned)
    sig = env["signatures"][0]["sig"]
    env["signatures"][0]["sig"] = ("B" if sig[0] != "B" else "C") + sig[1:]
    after = A.verify_record(env, pinned)
    code = (after.get("failure") or {}).get("code")
    print(f"audit-record/{target['draftId']}\t{before['verdict']}\tunmutated")
    print(f"audit-record/{target['draftId']}\t{after['verdict']}\tsignature character changed\t{code}")
    if (before["verdict"], after["verdict"]) != ("valid", "malformed"):
        print("the mutation did not turn the verdict from valid to malformed", file=sys.stderr)
        return 2
    return 1


def main(argv: list[str]) -> int:
    args = [a for a in argv if not a.startswith("--")]
    if len(args) != 2 or set(argv) - set(args) - {"--mutation"}:
        die(__doc__.split("usage: ", 1)[1].splitlines()[0])
    src, clone = (str(pathlib.Path(a).resolve()) for a in args)
    pins = json.loads((pathlib.Path(src) / "audit-record/agent_evidence_01/pins.json").read_text())
    commit = pins["vectors"]["commit"]
    aar = next(c for c in pins["vectors"]["corpora"] if c.endswith("agent-audit-record"))
    rer = next(c for c in pins["vectors"]["corpora"] if c.endswith("restart-records"))
    if "--mutation" in argv:
        return mutation(src, clone, commit, aar)
    run_all = os.path.join(src, "audit-record", "agent_evidence_01", "tools", "run_all.py")
    with tempfile.TemporaryDirectory() as work:
        out = subprocess.run([sys.executable, "-I", run_all, "--work", work, "--repository", clone],
                             capture_output=True, text=True)
        if out.returncode != 0:
            print(out.stdout + out.stderr, file=sys.stderr)
            die(f"his run_all.py exited {out.returncode} (0 = every pin holds and every fresh result file equals his)")
        planted = next((ln for ln in out.stdout.splitlines() if ln.startswith("planted cases in total")), "")
        pinned = next((ln for ln in out.stdout.splitlines() if ln.startswith("pinned vector files")), "")
        results = pathlib.Path(work) / "results"
        man = json.loads(git_blob(clone, commit, aar + "/MANIFEST.json"))
        equal = differ = 0
        causes: dict[str, list[str]] = {}
        for v in man["vectors"]:
            r = json.loads((results / "agent_audit_record" / f"{v['draftId']}__{v['id']}.json").read_text())
            ok = bool(r["match"])
            cause = carries(git_blob(clone, commit, aar + "/" + v["file"]))
            exp = v["expected"].get("verdict") or "any reading"
            print(f"audit-record/{v['draftId']}\t{r['own']['verdict']}\t{exp}\t{'equal' if ok else 'differ'}\t{','.join(cause)}")
            if ok:
                equal += 1
            else:
                differ += 1
                causes.setdefault(",".join(cause) or "none", []).append(v["draftId"])
        rman = json.loads(git_blob(clone, commit, rer + "/MANIFEST.json"))
        r_equal = r_reason = 0
        for v in rman["vectors"]:
            r = json.loads((results / "restoration_evidence" / f"{v['id']}.json").read_text())
            vok = r["own"]["verdict"] == v["expected"]["verdict"]
            rok = r["own"].get("reason") == v["expected"].get("reason")
            r_equal += vok
            r_reason += vok and rok
            print(f"restoration/{v['id']}\t{r['own']['verdict']}\t{v['expected']['verdict']}\t{'equal' if vok else 'differ'}\t")
        print(f"SUMMARY audit-record\tmembers {len(man['vectors'])}\tverdict equal {equal}\tdifferent {differ}")
        for name in sorted(causes):
            print(f"SUMMARY audit-record differ carrying {name}\t{len(causes[name])}\t{' '.join(causes[name])}")
        print(f"SUMMARY restoration\tmembers {len(rman['vectors'])}\tverdict equal {r_equal}\tverdict and reason equal {r_reason}")
        print(f"SUMMARY pins\t{pinned}")
        print(f"SUMMARY planted faults\t{planted}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
