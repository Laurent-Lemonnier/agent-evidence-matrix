"""Review gate for a pull request: a matrix row lands only after a maintainer records its review.

Run by .github/workflows/intake.yml under pull_request_target from the BASE branch's checkout. It reads
the pull request through the API and never checks out or runs the pull request's code. Inputs come from
the environment (REPO, PR, AUTHOR, ASSOCIATION, BASE_SHA, HEAD_REPO, HEAD_SHA, HELD_LOGINS, HELD_OWNERS);
the held lists are repository variables and are never printed.

Refusals:
- the author is on the held list;
- a non-maintainer changes reviews.json;
- a non-maintainer adds, changes or removes a project in matrix.json (a row lands after its review);
- any project the pull request adds or changes names a held owner anywhere in its entry, in any GitHub
  URL spelling (https://github.com/<owner>, git@github.com:<owner>/..., api.github.com/repos/<owner>);
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

MAINTAINER = ("OWNER", "MEMBER", "COLLABORATOR")


class ReadError(RuntimeError):
    pass


def gh(*args: str) -> str:
    out = subprocess.run(["gh", "api", *args], capture_output=True, text=True)
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


def held_owner_named(project: dict, owners: set[str]) -> bool:
    text = json.dumps(project, ensure_ascii=False).lower()
    for owner in owners:
        spelled = re.escape(owner)
        if re.search(r"github\.com(?:/repos)?[/:]+" + spelled + r"(?![\w.-])", text):
            return True
    return False


def refusals(files, base, head, author, association, held_logins, held_owners) -> list[str]:
    """Every refusal for one pull request; base and head are matrix.json documents (or None if unchanged)."""
    maintainer = association in MAINTAINER
    out = []
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
        if not maintainer:
            if added:
                out.append(f"project {added} has no review yet; a project lands after its review")
            if edited or removed:
                out.append(f"projects {edited + removed} change a reviewed row; a maintainer records the review")
        for pid in added + edited:
            if held_owner_named(after[pid], held_owners):
                out.append(f"project {pid} is held for maintainer review")
    return out


def main() -> int:
    env = os.environ
    held_logins = {x.strip().lower() for x in env.get("HELD_LOGINS", "").split(",") if x.strip()}
    held_owners = {x.strip().lower() for x in env.get("HELD_OWNERS", "").split(",") if x.strip()}
    try:
        files = changed_files(env["REPO"], env["PR"])
        base = head = None
        if "matrix.json" in files:
            base = matrix_at(env["REPO"], env["BASE_SHA"])
            gone = files["matrix.json"] in ("removed", "renamed-from")
            head = {"projects": []} if gone else matrix_at(env["HEAD_REPO"], env["HEAD_SHA"])
    except ReadError as exc:
        print(f"::error::intake: {exc}")
        return 2
    found = refusals(files, base, head, env["AUTHOR"], env["ASSOCIATION"], held_logins, held_owners)
    for r in found:
        print(f"::error::{r}")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
