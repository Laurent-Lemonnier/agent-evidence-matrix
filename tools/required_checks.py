"""Fail when the default branch's rules stop requiring the review gate.

    python3 -I tools/required_checks.py            reads repos/$REPO/rules/branches/main through `gh api`

tools/intake.py only refuses a pull request if its result blocks the merge. Until 17 Nov 2026 the branch had no
protection and no ruleset (`rules/branches/main` answered []), so an outside pull request with a red intake could
still be merged. This check makes that state visible on every run: it reads the rules GitHub applies to main and
exits 1 unless one active `required_status_checks` rule names every context in REQUIRED, and 2 when the rules
could not be read (a read that failed is never a pass).
"""
from __future__ import annotations

import json
import os
import subprocess
import sys

REQUIRED = ("intake",)


def missing(rules) -> list[str]:
    """The REQUIRED contexts no required_status_checks rule names (all of them when ``rules`` is not a list)."""
    if not isinstance(rules, list):
        return list(REQUIRED)
    named = set()
    for rule in rules:
        if not isinstance(rule, dict) or rule.get("type") != "required_status_checks":
            continue
        for check in (rule.get("parameters") or {}).get("required_status_checks") or []:
            if isinstance(check, dict) and isinstance(check.get("context"), str):
                named.add(check["context"])
    return [c for c in REQUIRED if c not in named]


def main() -> int:
    repo = os.environ.get("REPO") or os.environ.get("GITHUB_REPOSITORY")
    if not repo:
        print("::error::required_checks: REPO is not set")
        return 2
    out = subprocess.run(["gh", "api", f"repos/{repo}/rules/branches/main"], capture_output=True, text=True,
                         check=False)
    if out.returncode != 0:
        print(f"::error::required_checks: could not read the rules of main: {out.stderr.strip()}")
        return 2
    try:
        rules = json.loads(out.stdout)
    except ValueError as exc:
        print(f"::error::required_checks: the rules answer is not JSON: {exc}")
        return 2
    gone = missing(rules)
    for context in gone:
        print(f"::error::main does not require the {context} status, so a pull request it refuses can still merge")
    return 1 if gone else 0


if __name__ == "__main__":
    sys.exit(main())
