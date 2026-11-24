# Copyright 2026 Konrad Gruszka
# Licensed under the Apache License, Version 2.0; see LICENSE.
"""Fetches the vectors at the pinned commit, checks every pinned digest, runs both verifiers and the
planted faults, and compares the fresh results with the committed ones.

Usage: python -I run_all.py --work <dir outside this repository> [--repository <url>] [--update]

The vector repository is cloned bare, so no working tree is checked out. Only the files named in
pins.json are read, as blobs of the pinned commit, and each must match its SHA-256 in pins.json.
Only these files are written out as files; the rest of the repository stays in the object store of
the bare clone. Exit 0 means all digests match and the fresh results equal
the committed ones byte for byte. Exit 1 means a result differs or a committed result file cannot be read.
Exit 2 means a pin does not hold (a vector file, the set of vector files, LICENSE or its copy,
leap-seconds.list with its SHA-256 or its own #h line, pins.json itself), an argument is refused (also a
working directory or a write target that resolves into this repository) or git fails. A pinned file of
this folder (pins.json, leap-seconds.list, LICENSE.agent-evidence-vectors) fails its pin also when it is
missing, cannot be read, is not a regular file or is a symbolic link; the diagnostic names the file and
the reason. Exit 3 means the run stopped on an unexpected error of its own; the traceback is printed.

The location of this script is resolved (symbolic links, "..", aliases such as /proc/self/cwd) before its
folder and the repository root are derived from it, and every path is compared after resolving, on both
sides, so an alias of the script, of --work or of a write target is seen for what it points to.
"""
import argparse
import datetime
import hashlib
import importlib.util
import json
import os
import platform
import subprocess
import sys
import traceback

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.realpath(__file__))  # resolved first, then the parents are derived
FOLDER = os.path.dirname(HERE)
PINS = os.path.join(FOLDER, "pins.json")
COMMITTED = os.path.join(FOLDER, "results")
LEAP_LIST = os.path.join(FOLDER, "leap-seconds.list")


def refuse(msg):
    print(msg)
    sys.exit(2)


def inside(path, root):
    """Whether path lies in root or is root, both resolved (symbolic links, "..", relative parts)."""
    p, r = os.path.realpath(path), os.path.realpath(root)
    return os.path.commonpath([p, r]) == r


def write_target(path, root, repo_root):
    """path, resolved, if it lies in root and outside the repository, and if nothing below it that already
    exists is a symbolic link, which a later write would follow; otherwise the run is refused."""
    if not inside(path, root) or inside(path, repo_root):
        refuse("write target %s resolves to %s, outside %s or inside the repository" % (
            path, os.path.realpath(path), os.path.realpath(root)))
    for base, dirs, names in os.walk(os.path.realpath(path)):
        for n in dirs + names:
            if os.path.islink(os.path.join(base, n)):
                refuse("write target %s holds a symbolic link, %s" % (path, os.path.join(base, n)))
    return os.path.realpath(path)


def read_pinned(path):
    """The bytes of a pinned file of this folder; missing, unreadable, not a regular file or a symbolic link
    is a failed pin (exit 2) with the reason, like changed bytes."""
    name = os.path.basename(path)
    if os.path.islink(path):
        refuse("PIN FAILURE: %s is a symbolic link, to %s" % (name, os.readlink(path)))
    if not os.path.lexists(path):
        refuse("PIN FAILURE: %s is missing" % name)
    if not os.path.isfile(path):
        refuse("PIN FAILURE: %s is not a regular file" % name)
    try:
        with open(path, "rb") as f:
            return f.read()
    except OSError as e:
        refuse("PIN FAILURE: %s cannot be read, %s" % (name, e))


def _pins_int(s):
    if len(s.lstrip("-")) > 16:  # converts at most 16 digits, below every limit the interpreter allows
        raise ValueError("integer of more than 16 digits")
    return int(s)


def _pins_pairs(pairs):
    names = [k for k, _ in pairs]
    if len(set(names)) != len(names):
        raise ValueError("member name repeated")
    return dict(pairs)


def _pins_const(name):
    raise ValueError("non-finite number %s" % name)


def read_pins():
    """pins.json, read strictly: UTF-8 JSON without a repeated member name, integers of at most 16 digits and
    no non-finite number, with the members this runner uses in the types it uses them. Anything else is a
    failed pin (exit 2)."""
    raw = read_pinned(PINS)
    try:
        pins = json.loads(raw.decode("utf-8"), object_pairs_hook=_pins_pairs, parse_int=_pins_int,
                          parse_constant=_pins_const)
        vec = pins["vectors"]
        ok = isinstance(pins["leap_seconds"]["sha256"], str) and all(
            isinstance(vec[k], str) for k in ("repository", "commit", "license_sha256")) and \
            isinstance(vec["corpora"], list) and all(isinstance(c, str) for c in vec["corpora"]) and \
            isinstance(vec["files"], dict) and all(isinstance(h, str) for h in vec["files"].values())
    except (UnicodeDecodeError, ValueError, KeyError, TypeError) as e:
        refuse("PIN FAILURE: pins.json cannot be read as the pins of this runner, %s: %s" % (type(e).__name__, e))
    if not ok:
        refuse("PIN FAILURE: pins.json cannot be read as the pins of this runner, a member has another type")
    return pins


def check_leap_list(pins):
    """leap-seconds.list against pins.json, the pin in tools/leap_seconds.py and its own #h line."""
    raw = read_pinned(LEAP_LIST)
    if hashlib.sha256(raw).hexdigest() != pins["leap_seconds"]["sha256"]:
        refuse("PIN FAILURE: leap-seconds.list does not match its SHA-256 in pins.json")
    try:
        leap = load("leap_seconds")  # loading reads the list and raises if it fails
        why = leap.check(LEAP_LIST)
    except (OSError, UnicodeDecodeError, ValueError, IndexError, TypeError, RuntimeError) as e:
        why = "%s: %s" % (type(e).__name__, e)
    if why:
        refuse("PIN FAILURE: leap-seconds.list refused, %s" % why)
    print("leap-seconds.list equals its pin in pins.json and in tools/leap_seconds.py, and its #h line holds")


def load(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(HERE, name + ".py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def git(*args, binary=False):
    p = subprocess.run(["git", *args], capture_output=True)
    if p.returncode != 0:
        print("git %s failed with exit %d, %s" % (" ".join(args), p.returncode,
                                                  p.stderr.decode(errors="replace").strip()))
        sys.exit(2)
    return p.stdout if binary else p.stdout.decode().strip()


def fetch_vectors(pins, work, url, repo_root):
    vec = pins["vectors"]
    commit = vec["commit"]
    clone = write_target(os.path.join(work, "agent-evidence-vectors.git"), work, repo_root)
    if not os.path.isdir(clone):
        git("clone", "--quiet", "--bare", url, clone)
    if subprocess.run(["git", "-C", clone, "cat-file", "-e", commit + "^{commit}"]).returncode != 0:
        git("-C", clone, "fetch", "--quiet", "origin", commit)
    print("vector repository %s, pinned commit %s, resolved %s" % (
        url, commit, git("-C", clone, "rev-parse", commit + "^{commit}")))
    print("remote HEAD at run time:", git("ls-remote", url, "HEAD").split()[0])
    listed = set(git("-C", clone, "ls-tree", "-r", "--name-only", commit, "--", *vec["corpora"]).splitlines())
    listed = {p for p in listed if p.endswith(".json")}
    pinned = set(vec["files"])
    if listed != pinned:
        print("PIN FAILURE: .json files at the commit and pinned files differ")
        print(" only at the commit:", sorted(listed - pinned)[:20])
        print(" only pinned:", sorted(pinned - listed)[:20])
        sys.exit(2)
    out = write_target(os.path.join(work, "vectors"), work, repo_root)
    bad = 0
    for path in sorted(pinned):
        data = git("-C", clone, "cat-file", "blob", "%s:%s" % (commit, path), binary=True)
        if hashlib.sha256(data).hexdigest() != vec["files"][path]:
            print("PIN FAILURE:", path)
            bad += 1
            continue
        target = write_target(os.path.join(out, path), out, repo_root)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "wb") as f:
            f.write(data)
    print("pinned vector files: %d, digest equal to pins.json %d, different %d" % (
        len(pinned), len(pinned) - bad, bad))
    lic = git("-C", clone, "cat-file", "blob", "%s:LICENSE" % commit, binary=True)
    held = read_pinned(os.path.join(FOLDER, "LICENSE.agent-evidence-vectors"))
    if hashlib.sha256(lic).hexdigest() != vec["license_sha256"] or held != lic:
        print("PIN FAILURE: LICENSE at the commit, its pin and LICENSE.agent-evidence-vectors differ")
        bad += 1
    else:
        print("LICENSE at the commit equals its pin and LICENSE.agent-evidence-vectors byte for byte")
    if bad:
        sys.exit(2)
    return out


def tree(d):
    """The files below d by relative path; a file that cannot be read maps to None, which equals no bytes."""
    files = {}
    for root, _dirs, names in os.walk(d):
        for n in names:
            p = os.path.join(root, n)
            try:
                with open(p, "rb") as f:
                    files[os.path.relpath(p, d)] = f.read()
            except OSError as e:
                print("RESULT UNREADABLE: %s, %s" % (os.path.relpath(p, d), e))
                files[os.path.relpath(p, d)] = None
    return files


def main():
    try:
        run()
    except SystemExit:
        raise
    except Exception:
        traceback.print_exc()
        print("the run stopped on an unexpected error (exit 3)")
        sys.exit(3)


def run():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--work", required=True, help="working directory outside this repository")
    ap.add_argument("--repository", help="clone URL of the vector repository (default: from pins.json)")
    ap.add_argument("--update", action="store_true", help="write the fresh results into results/ of this folder")
    a = ap.parse_args()
    repo_root = os.path.realpath(os.path.dirname(os.path.dirname(FOLDER)))
    work = os.path.realpath(a.work)
    if inside(work, repo_root):
        refuse("--work must lie outside the repository, the planted-fault cases alone are thousands of files; "
               "%s resolves to %s" % (a.work, work))
    if os.path.exists(work) and not os.path.isdir(work):
        refuse("--work %s resolves to %s, which is not a directory" % (a.work, work))
    pins = read_pins()
    check_leap_list(pins)
    os.makedirs(work, exist_ok=True)
    import cryptography
    print("time of run (UTC):", datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    print("environment: Python %s (%s), %s, cryptography %s, %s" % (
        platform.python_version(), platform.python_implementation(), platform.platform(),
        cryptography.__version__, git("--version")))
    vectors = fetch_vectors(pins, work, a.repository or pins["vectors"]["repository"], repo_root)
    aar_corpus = os.path.join(vectors, "corpora", "vectors-agent-audit-record")
    rer_corpus = os.path.join(vectors, "corpora", "vectors-restart-records")
    fresh = write_target(os.path.join(work, "results"), work, repo_root)
    planted = write_target(os.path.join(work, "planted_faults"), work, repo_root)
    aar_out = os.path.join(fresh, "agent_audit_record")
    load("run_aar").run(HERE, aar_corpus, aar_out)
    load("run_rer").run(HERE, rer_corpus, os.path.join(fresh, "restoration_evidence"))
    load("run_faults").run(HERE, aar_corpus, rer_corpus, aar_out, planted,
                           os.path.join(fresh, "planted_faults_summary.json"))
    new = tree(fresh)
    if a.update:
        if not inside(COMMITTED, FOLDER) or os.path.realpath(COMMITTED) == os.path.realpath(FOLDER):
            refuse("results/ resolves to %s, outside this folder" % os.path.realpath(COMMITTED))
        for rel, data in new.items():
            target = os.path.join(COMMITTED, rel)
            if not inside(target, COMMITTED):
                refuse("result file %s resolves to %s, outside results/" % (rel, os.path.realpath(target)))
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with open(target, "wb") as f:
                f.write(data)
        print("results written to", COMMITTED)
    old = tree(COMMITTED) if os.path.isdir(COMMITTED) else {}
    differ = sorted(k for k in set(old) & set(new) if old[k] != new[k])
    only_old = sorted(set(old) - set(new))
    only_new = sorted(set(new) - set(old))
    print("result files: committed %d, fresh %d, byte-equal %d, different %d, only committed %d, only fresh %d" % (
        len(old), len(new), len(set(old) & set(new)) - len(differ), len(differ), len(only_old), len(only_new)))
    for k in (differ + only_old + only_new)[:40]:
        print("RESULT DIFFERS:", k)
    sys.exit(1 if (differ or only_old or only_new) else 0)


if __name__ == "__main__":
    main()
