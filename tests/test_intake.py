"""The review gate reads every changed file and finds a held owner in any URL spelling.

Counter-examples the inline gate accepted: reviews.json changed on the second page of a pull request's
file list (it read one page of 100), a held owner spelled git@github.com:<owner>/x, https://github.com/<owner>
with no trailing slash, or api.github.com/repos/<owner>/x, and a non-maintainer editing or removing a
reviewed row.
"""
import json
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "tools"))
import intake  # noqa: E402

HELD = {"heldowner"}


def proj(pid, url="https://github.com/someone/thing", **kw):
    p = {"id": pid, "name": f"p{pid}", "upstream": {"url": url, "sha": "a" * 40}, "cells": []}
    p.update(kw)
    return p


def pages(*pages_of_rows, changed=None):
    """A fake `gh api` that serves the file list as `--paginate --jq` would (all pages, one row per line)."""
    rows = [r for page in pages_of_rows for r in page]

    def read(*args):
        if "--paginate" in args:
            return "\n".join(json.dumps({"f": f, "s": "modified", "p": None}) for f in rows) + "\n"
        return json.dumps({"changed_files": len(rows) if changed is None else changed})
    return read


def test_a_file_on_the_second_page_is_read():
    first = [f"docs/{i}.md" for i in range(100)]
    files = intake.changed_files("o/r", "1", pages(first, ["reviews.json"]))
    assert "reviews.json" in files
    assert intake.refusals(files, None, None, "outsider", "CONTRIBUTOR", set(), HELD) == [
        "reviews.json is written by maintainers only"]


def test_a_short_file_list_is_a_read_error():
    with pytest.raises(intake.ReadError):
        intake.changed_files("o/r", "1", pages(["a.md"], changed=101))


@pytest.mark.parametrize("url", ["git@github.com:HeldOwner/x", "https://github.com/heldowner",
                                 "https://api.github.com/repos/heldowner/x", "https://www.github.com/heldowner/x/"])
def test_a_held_owner_is_found_in_any_spelling(url):
    base = {"projects": [proj(1)]}
    head = {"projects": [proj(1), proj(2, url=url)]}
    out = intake.refusals({"matrix.json": "modified"}, base, head, "maint", "MEMBER", set(), HELD)
    assert out == ["project 2 is held for maintainer review"]


def test_a_held_owner_named_outside_the_upstream_is_found():
    head = {"projects": [proj(2, replay="git clone https://github.com/heldowner/x")]}
    out = intake.refusals({"matrix.json": "modified"}, {"projects": []}, head, "maint", "MEMBER", set(), HELD)
    assert out == ["project 2 is held for maintainer review"]


def test_a_longer_owner_name_is_not_the_held_one():
    head = {"projects": [proj(2, url="https://github.com/heldowner2/x")]}
    assert intake.refusals({"matrix.json": "modified"}, {"projects": []}, head, "m", "MEMBER", set(), HELD) == []


def test_a_non_maintainer_may_not_edit_or_remove_a_reviewed_row():
    base = {"projects": [proj(1), proj(2)]}
    edited = {"projects": [proj(1, name="changed")]}
    out = intake.refusals({"matrix.json": "modified"}, base, edited, "outsider", "CONTRIBUTOR", set(), HELD)
    assert out == ["projects [1, 2] change a reviewed row; a maintainer records the review"]


def test_a_maintainer_edit_of_an_unheld_row_passes():
    base = {"projects": [proj(1)]}
    head = {"projects": [proj(1, name="changed"), proj(2)]}
    assert intake.refusals({"matrix.json": "modified"}, base, head, "m", "MEMBER", set(), HELD) == []
