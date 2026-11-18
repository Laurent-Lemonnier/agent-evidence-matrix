"""Review gate for a pull request: a matrix row lands only after a maintainer records its review.

Run by .github/workflows/intake.yml under pull_request_target from the BASE branch's checkout. It reads
the pull request through the API and never checks out or runs the pull request's code. Inputs come from
the environment (REPO, PR, AUTHOR, SENDER, BASE_SHA, HEAD_REPO, HEAD_SHA, HELD_LOGINS, HELD_OWNERS); the held lists
are repository variables and are never printed. A maintainer is an account with admin, maintain or write permission
on the repository, read through the API: the pull request's author_association is not used, because GitHub reports an
organization owner whose membership is private as CONTRIBUTOR. The pull request counts as a maintainer's only when
its author and the account whose event ran the gate (SENDER: for a push, the pusher) are both maintainers, so a
commit pushed to a maintainer's branch by someone else is judged as theirs.

Refusals:
- the author is on the held list;
- a non-maintainer changes reviews.json;
- a non-maintainer adds, changes or removes a project in matrix.json (a row lands after its review), or changes
  any other field of matrix.json (the reader, the verdict vocabulary, the count), which every row is read under;
- matrix.json lists a project with no id or one id twice (either copy could be the row that lands);
- any project the pull request adds or changes names a held owner anywhere in its entry, in any GitHub
  URL spelling (https://github.com/<owner>, git@github.com:<owner>/..., api.github.com/repos|users|orgs/<owner>,
  github.com/orgs/<owner>, raw.githubusercontent.com/<owner>, <owner>.github.io, ghcr.io/<owner>), percent-encoded
  or not, and read after NFKC folding with invisible format characters dropped (a zero-width space or a fullwidth
  letter inside the name still renders as the name);
- the changed-file list could not be read whole (every page, and as many files as the pull request says
  it changes).
Exit 0 when nothing is refused, 1 with one ::error:: line per refusal, 2 when the API could not be read.
"""
from __future__ import annotations

import base64
import json
import os
import re
import subprocess
import sys
import unicodedata
import urllib.parse

MAINTAINER = ("admin", "maintain", "write")


class ReadError(RuntimeError):
    pass


def gh(*args: str) -> str:
    out = subprocess.run(["gh", "api", *args], capture_output=True, text=True, check=False)
    if out.returncode != 0:
        raise ReadError(f"could not read {args[-1].split('?')[0]}: {out.stderr.strip()}")
    return out.stdout


def changed_files(repo: str, pr: str, read=gh) -> dict[str, str]:
    """{file name: status} for every file the pull request touches (both sides of a rename), every page."""
    rows = [json.loads(line) for line in read(
        "--paginate", "--jq", ".[] | {f: .filename, s: .status, p: .previous_filename}",
        f"repos/{repo}/pulls/{pr}/files?per_page=100").splitlines() if line.strip()]
    expected = json.loads(read(f"repos/{repo}/pulls/{pr}"))["changed_files"]
    if len(rows) != expected:
        raise ReadError(f"read {len(rows)} changed files of the {expected} the pull request reports")
    out = {}
    for row in rows:
        out[row["f"]] = row["s"]
        if row.get("p"):
            out[row["p"]] = "renamed-from"
    return out


def matrix_at(repo: str, sha: str, read=gh) -> dict:
    doc = json.loads(read(f"repos/{repo}/contents/matrix.json?ref={sha}"))
    if doc.get("encoding") != "base64" or not doc.get("content"):
        raise ReadError("matrix.json is not served inline (too large for the contents API)")
    return json.loads(base64.b64decode(doc["content"]))


def fold(text: str) -> str:
    """The text as a reader sees it: compatibility forms folded (NFKC) and invisible format characters dropped.

    A zero-width space, a soft hyphen or a fullwidth letter inside an owner name renders as that name in
    MATRIX.md while a pattern over the raw characters misses it.
    """
    text = unicodedata.normalize("NFKC", text)
    return "".join(c for c in text if unicodedata.category(c) != "Cf")


def held_owner_named(project: dict, owners: set[str]) -> bool:
    text = json.dumps(project, ensure_ascii=False)
    for _ in range(4):  # %2568 is %68 is h: decode until nothing changes
        decoded = fold(urllib.parse.unquote(text))
        if decoded == text:
            break
        text = decoded
    text = fold(text).casefold()
    for owner in owners:
        spelled = re.escape(owner)
        after = r"(?![\w.-])"
        host = r"(?:github\.com(?:/(?:repos|users|orgs))?|githubusercontent\.com|ghcr\.io)[/:]+"
        if re.search(host + spelled + after, text) or re.search(r"(?<![a-z0-9-])" + spelled + r"\.github\.io" + after,
                                                                 text):
            return True
    return False


def is_maintainer(repo: str, author: str, read=gh) -> bool:
    """True when the author holds admin, maintain or write permission on the repository (raises ReadError if unread)."""
    perm = json.loads(read(f"repos/{repo}/collaborators/{author}/permission")).get("permission")
    if not isinstance(perm, str):
        raise ReadError(f"no permission value for {author}")
    return perm in MAINTAINER


def refusals(files, base, head, author, maintainer, held_logins, held_owners) -> list[str]:
    """Every refusal for one pull request; base and head are matrix.json documents (or None if unchanged)."""
    out = []
    for name, doc in (("base", base), ("head", head)):
        ids = [p.get("id") if isinstance(p, dict) else None for p in (doc or {}).get("projects", [])]
        twice = sorted({i for i in ids if ids.count(i) > 1}, key=str)
        if None in ids or twice:
            out.append(f"matrix.json at the {name} lists a project with no id or ids {twice} more than once")
    if author.lower() in held_logins:
        out.append("this account's rows are held for maintainer review; a maintainer will follow up")
    if "reviews.json" in files and not maintainer:
        out.append("reviews.json is written by maintainers only")
    if "matrix.json" in files:
        before = {p.get("id"): p for p in (base or {}).get("projects", [])}
        after = {p.get("id"): p for p in (head or {}).get("projects", [])}
        added = sorted(set(after) - set(before), key=str)
        removed = sorted(set(before) - set(after), key=str)
        edited = sorted((pid for pid in set(after) & set(before) if after[pid] != before[pid]), key=str)
        rest = sorted(k for k in set(base or {}) | set(head or {}) if k != "projects"
                      and (base or {}).get(k) != (head or {}).get(k))
        if rest and not maintainer:
            out.append(f"matrix.json fields {rest} are read by every row; a maintainer changes them")
        if not maintainer:
            if added:
                out.append(f"project {added} has no review yet; a project lands after its review")
            if edited or removed:
                out.append(f"projects {edited + removed} change a reviewed row; a maintainer records the review")
        changed = set(added) | set(edited)
        for p in (head or {}).get("projects", []):  # every copy, so a second entry with one id is read too
            pid = p.get("id") if isinstance(p, dict) else None
            if (pid in changed or p != before.get(pid)) and held_owner_named(p, held_owners):
                out.append(f"project {pid} is held for maintainer review")
    return out


def main() -> int:
    env = os.environ
    held_logins = {x.strip().lower() for x in env.get("HELD_LOGINS", "").split(",") if x.strip()}
    held_owners = {x.strip().lower() for x in env.get("HELD_OWNERS", "").split(",") if x.strip()}
    try:
        files = changed_files(env["REPO"], env["PR"], gh)
        accounts = {env["AUTHOR"], env.get("SENDER") or env["AUTHOR"]}
        maintainer = all(is_maintainer(env["REPO"], a, gh) for a in sorted(accounts))
        base = head = None
        if "matrix.json" in files:
            base = matrix_at(env["REPO"], env["BASE_SHA"], gh)
            gone = files["matrix.json"] in ("removed", "renamed-from")
            head = {"projects": []} if gone else matrix_at(env["HEAD_REPO"], env["HEAD_SHA"], gh)
    except ReadError as exc:
        print(f"::error::intake: {exc}")
        return 2
    found = refusals(files, base, head, env["AUTHOR"], maintainer, held_logins, held_owners)
    for r in found:
        print(f"::error::{r}")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
