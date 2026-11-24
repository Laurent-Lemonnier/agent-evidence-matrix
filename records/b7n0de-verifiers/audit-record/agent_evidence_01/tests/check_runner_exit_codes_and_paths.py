# Copyright 2026 Konrad Gruszka
# Licensed under the Apache License, Version 2.0; see LICENSE.
"""Exit codes and path checks of tools/run_all.py, each with a planted failure, run as a separate process.

The README gives the runner four exit codes: 0 when every pin holds and every result file is byte-equal,
1 when a result differs, 2 when a pin does not hold or an argument or a path is refused, and 3 when the run
stops on an unexpected error. Each check copies this folder into a temporary repository, plants one
failure and runs the runner with the interpreter of the checks. The vector repository is a small git
repository built here, with pins.json of the copy rewritten to its files, so no network is needed.
Paths are compared after resolving symbolic links on both sides, so an alias into the repository, such
as a symbolic link or /proc/self/cwd, is refused like the path it points to, and the runner resolves its own
location before it derives the folder and the repository root, so invoking it through such an alias does
not move the boundary. A pinned file of the folder fails its pin, exit 2, when its bytes change, when it is
missing, cannot be read, is a directory or is a symbolic link. A file that cannot be read is planted with
mode 000; as root, which reads such a file anyway, the runner then runs as the user nobody.
"""
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile

import pytest

TOOLS = os.environ.get("AGENT_EVIDENCE_TOOLS") or os.path.join(os.path.dirname(os.path.realpath(__file__)), "..",
                                                               "tools")
FOLDER = os.path.dirname(os.path.realpath(TOOLS))  # resolved before the parent is taken
ROOT = os.geteuid() == 0
NOBODY = 65534
GIT_ENV = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.invalid", GIT_COMMITTER_NAME="t",
               GIT_COMMITTER_EMAIL="t@example.invalid", GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")

# Stand-ins for the three corpus runners: each writes one fixed result file, so that the comparison with
# results/ is what the check plants a failure in
STUB = '''import json, os
def run(*args):
    out = [a for a in args if isinstance(a, str) and a.endswith(%r)][0]
    os.makedirs(os.path.dirname(out) if out.endswith(".json") else out, exist_ok=True)
    path = out if out.endswith(".json") else os.path.join(out, "r.json")
    with open(path, "w") as f:
        json.dump({"stub": %r}, f)
    return []
'''


def _git(*args, cwd=None):
    subprocess.run(["git", *args], cwd=cwd, env=GIT_ENV, check=True, capture_output=True)


def _sha(b):
    return hashlib.sha256(b).hexdigest()


@pytest.fixture
def tmp_path(tmp_path):
    """pytest's own tmp_path, except as root: a fresh directory that the user nobody can enter, so that a check
    can run the runner as nobody, for whom mode 000 makes a file unreadable."""
    if not ROOT:
        yield tmp_path
        return
    base = tempfile.mkdtemp(prefix="agent-evidence-runner-")
    os.chmod(base, 0o755)
    try:
        yield __import__("pathlib").Path(base)
    finally:
        shutil.rmtree(base, ignore_errors=True)


@pytest.fixture
def world(tmp_path):
    """A repository holding a copy of this folder, a vector repository and an empty working directory."""
    repo = tmp_path / "repo"
    folder = repo / "audit-record" / "agent_evidence_01"
    shutil.copytree(FOLDER, folder, ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache", "results"))
    vec = tmp_path / "vectors-src"
    files = {"corpora/vectors-agent-audit-record/a.json": b'{"a":1}\n',
             "corpora/vectors-restart-records/b.json": b'{"b":2}\n'}
    for rel, data in files.items():
        (vec / rel).parent.mkdir(parents=True, exist_ok=True)
        (vec / rel).write_bytes(data)
    lic = (folder / "LICENSE.agent-evidence-vectors").read_bytes()
    (vec / "LICENSE").write_bytes(lic)
    _git("init", "-q", str(vec))
    _git("add", "-A", cwd=vec)
    _git("commit", "-q", "-m", "v", cwd=vec)
    commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=vec, capture_output=True, text=True).stdout.strip()
    pins = json.loads((folder / "pins.json").read_text())
    pins["vectors"].update(repository=str(vec), commit=commit, license_sha256=_sha(lic),
                           files={k: _sha(v) for k, v in files.items()})
    (folder / "pins.json").write_text(json.dumps(pins, indent=2))
    for name, suffix in (("run_aar", "agent_audit_record"), ("run_rer", "restoration_evidence"),
                         ("run_faults", "planted_faults_summary.json")):
        (folder / "tools" / (name + ".py")).write_text(STUB % (suffix, name))
    work = tmp_path / "work"
    w = {"repo": repo, "folder": folder, "vec": vec, "work": work, "files": files, "pins": pins}
    # results/ of the copy as the stand-ins write them, so that an unchanged run ends with exit 0
    assert run_all(w, "--work", str(tmp_path / "seed"), "--update").returncode == 0
    return w


def run_all(w, *args, cwd=None, script=None, **kw):
    return subprocess.run([sys.executable, "-I", str(script or w["folder"] / "tools" / "run_all.py"), *args],
                          cwd=cwd or str(w["repo"]), capture_output=True, text=True, timeout=300, **kw)


def _unreadable(w, path):
    """path made unreadable with mode 000; returns the arguments that run the runner as a user who cannot read
    it: the same user when not root, the user nobody when root, with a working directory nobody can write and
    git told to trust the repositories root built here."""
    os.chmod(path, 0)
    if not ROOT:
        return {}
    w["work"].mkdir(exist_ok=True)
    os.chmod(w["work"], 0o777)
    # git reads safe.directory only from protected configuration and does not pass the environment form on to
    # a local upload-pack, so nobody gets a home of its own with a global configuration that trusts them
    home = w["work"].parent / "home-of-nobody"
    home.mkdir(exist_ok=True)
    (home / ".gitconfig").write_text("[safe]\n\tdirectory = *\n")
    env = dict(os.environ, HOME=str(home))
    env.pop("GIT_CONFIG_GLOBAL", None)
    return {"user": NOBODY, "group": NOBODY, "extra_groups": [], "env": env}


def _says(p, text):
    return text in p.stdout + p.stderr


# ---------------------------------------------------------------- 0 and 1


def test_exit_0_when_every_pin_holds_and_every_result_is_equal(world):
    p = run_all(world, "--work", str(world["work"]))
    assert p.returncode == 0, p.stdout + p.stderr
    assert _says(p, "byte-equal 3, different 0")


def test_exit_1_when_a_result_differs(world):
    (world["folder"] / "results" / "planted_faults_summary.json").write_text('{"stub": "changed"}')
    p = run_all(world, "--work", str(world["work"]))
    assert p.returncode == 1 and _says(p, "RESULT DIFFERS: planted_faults_summary.json")


def test_exit_1_when_a_result_file_is_missing_or_extra(world):
    (world["folder"] / "results" / "restoration_evidence" / "r.json").unlink()
    (world["folder"] / "results" / "extra.json").write_text("{}")
    p = run_all(world, "--work", str(world["work"]))
    assert p.returncode == 1 and _says(p, "only committed 1, only fresh 1")


# ---------------------------------------------------------------- 2, pins


def test_exit_2_when_a_vector_file_differs_from_its_pin(world):
    pins = world["pins"]
    pins["vectors"]["files"]["corpora/vectors-restart-records/b.json"] = "0" * 64
    (world["folder"] / "pins.json").write_text(json.dumps(pins))
    p = run_all(world, "--work", str(world["work"]))
    assert p.returncode == 2 and _says(p, "PIN FAILURE: corpora/vectors-restart-records/b.json")


def test_exit_2_when_the_set_of_vector_files_differs(world):
    pins = world["pins"]
    pins["vectors"]["files"]["corpora/vectors-restart-records/c.json"] = "0" * 64
    (world["folder"] / "pins.json").write_text(json.dumps(pins))
    p = run_all(world, "--work", str(world["work"]))
    assert p.returncode == 2 and _says(p, "pinned files differ")


def test_exit_2_when_license_differs_from_its_pin(world):
    pins = world["pins"]
    pins["vectors"]["license_sha256"] = "0" * 64
    (world["folder"] / "pins.json").write_text(json.dumps(pins))
    p = run_all(world, "--work", str(world["work"]))
    assert p.returncode == 2 and _says(p, "PIN FAILURE: LICENSE")


def test_exit_2_when_the_license_copy_differs(world):
    with open(world["folder"] / "LICENSE.agent-evidence-vectors", "ab") as f:
        f.write(b"\n")
    p = run_all(world, "--work", str(world["work"]))
    assert p.returncode == 2 and _says(p, "PIN FAILURE: LICENSE")


def test_exit_2_when_the_pinned_commit_is_not_there(world):
    pins = world["pins"]
    pins["vectors"]["commit"] = "1" * 40
    (world["folder"] / "pins.json").write_text(json.dumps(pins))
    p = run_all(world, "--work", str(world["work"]))
    assert p.returncode == 2 and _says(p, "failed with exit")


def _changed_list(world):
    path = world["folder"] / "leap-seconds.list"
    src = path.read_bytes()
    assert src.count(b"3692217600      37") == 1
    bad = src.replace(b"3692217600      37", b"3692217600      38")
    path.write_bytes(bad)
    return bad


def test_exit_2_when_the_leap_second_list_bytes_change(world):
    _changed_list(world)
    p = run_all(world, "--work", str(world["work"]))
    assert p.returncode == 2 and _says(p, "PIN FAILURE: leap-seconds.list")
    assert not world["work"].exists()  # refused before anything is fetched or written


def test_exit_2_when_the_leap_second_list_holds_its_pins_but_fails_its_own_hash_line(world):
    # both pins, in pins.json and in tools/leap_seconds.py, moved to the changed bytes: the #h line refuses
    bad = _changed_list(world)
    pins = world["pins"]
    old = pins["leap_seconds"]["sha256"]
    pins["leap_seconds"]["sha256"] = _sha(bad)
    (world["folder"] / "pins.json").write_text(json.dumps(pins))
    mod = world["folder"] / "tools" / "leap_seconds.py"
    text = mod.read_text()
    assert text.count(old) == 1
    mod.write_text(text.replace(old, _sha(bad)))
    p = run_all(world, "--work", str(world["work"]))
    assert p.returncode == 2 and _says(p, "PIN FAILURE: leap-seconds.list") and _says(p, "#h")


def test_exit_2_when_the_leap_second_list_is_missing(world):
    (world["folder"] / "leap-seconds.list").unlink()
    p = run_all(world, "--work", str(world["work"]))
    assert p.returncode == 2 and _says(p, "PIN FAILURE: leap-seconds.list")


# ---------------------------------------------------------------- 2, every pinned file of the folder, every way
# it can fail: bytes changed, missing, unreadable, a directory in its place, a symbolic link in its place

PINNED = ["pins.json", "leap-seconds.list", "LICENSE.agent-evidence-vectors"]
WAYS = ["changed", "missing", "unreadable", "directory", "symbolic-link"]


def _plant(world, tmp_path, name, way):
    path = world["folder"] / name
    kw = {}
    if way == "changed":
        if name == "leap-seconds.list":
            _changed_list(world)
        elif name == "pins.json":
            path.write_bytes(path.read_bytes()[: len(path.read_bytes()) // 2])  # no longer the pins
        else:
            with open(path, "ab") as f:
                f.write(b"\n")
    elif way == "missing":
        path.unlink()
    elif way == "unreadable":
        kw = _unreadable(world, path)
    elif way == "directory":
        path.unlink()
        path.mkdir()
    elif way == "symbolic-link":
        same = tmp_path / ("same-bytes-" + name)  # the same bytes, reached through a link
        same.write_bytes(path.read_bytes())
        path.unlink()
        path.symlink_to(same)
    return kw


@pytest.mark.parametrize("way", WAYS)
@pytest.mark.parametrize("name", PINNED)
def test_exit_2_when_a_pinned_file_of_the_folder_fails_in_any_way(world, tmp_path, name, way):
    kw = _plant(world, tmp_path, name, way)
    p = run_all(world, "--work", str(world["work"]), **kw)
    assert p.returncode == 2, (p.returncode, p.stdout + p.stderr)
    assert _says(p, "PIN FAILURE: " + name.split(".agent")[0]), p.stdout + p.stderr
    assert not _says(p, "Traceback")
    if way == "unreadable":
        assert _says(p, "cannot be read") and _says(p, "Permission denied")


def test_exit_2_when_a_pinned_file_is_a_socket_that_open_refuses(world, tmp_path):
    # a file that open() refuses whoever runs it (ENXIO): a socket in place of the license copy
    path = world["folder"] / "LICENSE.agent-evidence-vectors"
    path.unlink()
    short = tempfile.mkdtemp(prefix="s")  # a socket path is limited to about 100 bytes
    s = socket.socket(socket.AF_UNIX)
    try:
        s.bind(os.path.join(short, "s"))
        os.rename(os.path.join(short, "s"), path)
    except OSError:
        shutil.move(os.path.join(short, "s"), path)
    finally:
        s.close()
        shutil.rmtree(short, ignore_errors=True)
    p = run_all(world, "--work", str(world["work"]))
    assert p.returncode == 2 and _says(p, "PIN FAILURE: LICENSE") and not _says(p, "Traceback")


@pytest.mark.parametrize("text", ['{"schema": "a", "schema": "b"}', '{"x": 12345678901234567}', '{"x": NaN}',
                                  '[]', '{"vectors": {}, "leap_seconds": {"sha256": 1}}'])
def test_exit_2_when_pins_json_is_not_the_pins_of_the_runner(world, text):
    pins = json.dumps(world["pins"])
    (world["folder"] / "pins.json").write_text(text if text.startswith("[") or "vectors" in text
                                                  else pins[:-1] + "," + text[1:])
    p = run_all(world, "--work", str(world["work"]))
    assert p.returncode == 2 and _says(p, "PIN FAILURE: pins.json") and not _says(p, "Traceback")


def test_exit_2_when_the_license_is_missing_at_the_pinned_commit(world):
    vec = world["vec"]
    _git("rm", "-q", "LICENSE", cwd=vec)
    _git("commit", "-q", "-m", "no license", cwd=vec)
    commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=vec, capture_output=True, text=True).stdout.strip()
    pins = world["pins"]
    pins["vectors"]["commit"] = commit
    (world["folder"] / "pins.json").write_text(json.dumps(pins))
    p = run_all(world, "--work", str(world["work"]))
    assert p.returncode == 2 and _says(p, "failed with exit") and _says(p, "LICENSE")


def test_exit_1_when_a_committed_result_file_cannot_be_read(world):
    kw = _unreadable(world, world["folder"] / "results" / "planted_faults_summary.json")
    p = run_all(world, "--work", str(world["work"]), **kw)
    assert p.returncode == 1, p.stdout + p.stderr
    assert _says(p, "RESULT UNREADABLE: planted_faults_summary.json") and not _says(p, "Traceback")


# ---------------------------------------------------------------- 2, arguments and paths


@pytest.mark.parametrize("args", [(), ("--work",), ("--work", "x", "--no-such-option")])
def test_exit_2_for_invalid_arguments(world, args):
    p = run_all(world, *args)
    assert p.returncode == 2 and _says(p, "usage")


def test_exit_2_when_work_lies_in_the_repository(world):
    p = run_all(world, "--work", str(world["repo"] / "w"))
    assert p.returncode == 2 and _says(p, "--work must lie outside the repository")


def test_exit_2_when_work_is_a_symbolic_link_into_the_repository(world, tmp_path):
    alias = tmp_path / "alias"
    alias.symlink_to(world["repo"], target_is_directory=True)
    for w in (alias, alias / "sub"):
        p = run_all(world, "--work", str(w))
        assert p.returncode == 2 and _says(p, "--work must lie outside the repository")
    assert not (world["repo"] / "sub").exists()


def test_exit_2_when_work_is_proc_self_cwd_inside_the_repository(world):
    assert os.path.realpath("/proc/self/cwd") == os.getcwd()  # the alias resolves on this system
    for cwd in (world["repo"], world["folder"]):
        p = run_all(world, "--work", "/proc/self/cwd", cwd=str(cwd))
        assert p.returncode == 2 and _says(p, "--work must lie outside the repository")


def test_exit_2_when_the_repository_is_reached_through_a_relative_path(world):
    p = run_all(world, "--work", "../agent_evidence_01/../../x", cwd=str(world["folder"]))
    assert p.returncode == 2 and _says(p, "--work must lie outside the repository")


@pytest.mark.parametrize("name", ["results", "vectors", "planted_faults", "agent-evidence-vectors.git"])
def test_exit_2_when_a_write_target_in_work_links_into_the_repository(world, name):
    world["work"].mkdir()
    (world["work"] / name).symlink_to(world["folder"], target_is_directory=True)
    before = sorted(os.listdir(world["folder"]))
    p = run_all(world, "--work", str(world["work"]))
    assert p.returncode == 2 and _says(p, "write target")
    assert sorted(os.listdir(world["folder"])) == before


def test_exit_2_when_a_file_below_a_write_target_is_a_symbolic_link(world, tmp_path):
    out = world["work"] / "results" / "restoration_evidence"
    out.mkdir(parents=True)
    victim = tmp_path / "victim.json"
    victim.write_text("keep")
    (out / "r.json").symlink_to(victim)
    p = run_all(world, "--work", str(world["work"]))
    assert p.returncode == 2 and _says(p, "symbolic link")
    assert victim.read_text() == "keep"


def test_exit_2_when_update_would_write_through_a_linked_results_folder(world, tmp_path):
    outside = tmp_path / "outside"
    shutil.copytree(world["folder"] / "results", outside)
    shutil.rmtree(world["folder"] / "results")
    (world["folder"] / "results").symlink_to(outside, target_is_directory=True)
    p = run_all(world, "--work", str(world["work"]), "--update")
    assert p.returncode == 2 and _says(p, "results/ resolves to")


# ---------------------------------------------------------------- 2, the runner invoked through an alias of itself


def _work_inside(world):
    return str(world["repo"] / "w")


def test_exit_2_when_the_runner_is_invoked_through_proc_self_cwd(world):
    assert os.path.realpath("/proc/self/cwd") == os.getcwd()  # the alias resolves on this system
    for cwd, script in ((world["folder"], "/proc/self/cwd/tools/run_all.py"),
                        (world["folder"] / "tools", "/proc/self/cwd/run_all.py"),
                        (world["repo"], "/proc/self/cwd/audit-record/agent_evidence_01/tools/run_all.py")):
        p = run_all(world, "--work", _work_inside(world), cwd=str(cwd), script=script)
        assert p.returncode == 2 and _says(p, "--work must lie outside the repository"), (script, p.stdout)
    assert not (world["repo"] / "w").exists()
    # the alias itself is no refusal: a working directory outside the repository runs to exit 0
    p = run_all(world, "--work", str(world["work"]), cwd=str(world["folder"]), script="/proc/self/cwd/tools/run_all.py")
    assert p.returncode == 0, p.stdout + p.stderr


def test_exit_2_when_the_runner_is_invoked_through_a_directory_link(world, tmp_path):
    # a link to the folder and a link to tools/, deep enough that the parents of the unresolved link do not
    # hold the repository by accident
    deep = tmp_path / "a" / "b" / "c"
    deep.mkdir(parents=True)
    (deep / "folder").symlink_to(world["folder"], target_is_directory=True)
    (deep / "tools").symlink_to(world["folder"] / "tools", target_is_directory=True)
    for script in (deep / "folder" / "tools" / "run_all.py", deep / "tools" / "run_all.py"):
        p = run_all(world, "--work", _work_inside(world), script=str(script))
        assert p.returncode == 2 and _says(p, "--work must lie outside the repository"), (str(script), p.stdout)
        # the link itself is no refusal: a working directory outside the repository runs to exit 0
        p = run_all(world, "--work", str(tmp_path / "a" / "w"), script=str(script))
        assert p.returncode == 0, p.stdout + p.stderr
    assert not (world["repo"] / "w").exists()


def test_exit_2_when_the_runner_is_invoked_through_a_relative_path_with_dots(world):
    for cwd, script in ((world["folder"] / "tools", "../tools/run_all.py"),
                        (world["repo"], "audit-record/../audit-record/agent_evidence_01/./tools/../tools/run_all.py")):
        p = run_all(world, "--work", _work_inside(world), cwd=str(cwd), script=script)
        assert p.returncode == 2 and _says(p, "--work must lie outside the repository"), (script, p.stdout)
    assert not (world["repo"] / "w").exists()


# ---------------------------------------------------------------- 3


def test_exit_3_on_an_unexpected_error(world):
    (world["folder"] / "tools" / "run_rer.py").write_text("def run(*args):\n    raise ZeroDivisionError('planted')\n")
    p = run_all(world, "--work", str(world["work"]))
    assert p.returncode == 3 and _says(p, "ZeroDivisionError: planted") and _says(p, "unexpected error")
