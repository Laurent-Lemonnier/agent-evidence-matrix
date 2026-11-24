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
    assert intake.refusals(files, None, None, "outsider", False, set(), HELD) == [
        "reviews.json is written by maintainers only"]


def test_a_short_file_list_is_a_read_error():
    with pytest.raises(intake.ReadError):
        intake.changed_files("o/r", "1", pages(["a.md"], changed=101))


@pytest.mark.parametrize("url", ["git@github.com:HeldOwner/x", "https://github.com/heldowner",
                                 "https://api.github.com/repos/heldowner/x", "https://www.github.com/heldowner/x/"])
def test_a_held_owner_is_found_in_any_spelling(url):
    base = {"projects": [proj(1)]}
    head = {"projects": [proj(1), proj(2, url=url)]}
    out = intake.refusals({"matrix.json": "modified"}, base, head, "maint", True, set(), HELD)
    assert out == ["project 2 is held for maintainer review"]


def test_a_held_owner_named_outside_the_upstream_is_found():
    head = {"projects": [proj(2, replay="git clone https://github.com/heldowner/x")]}
    out = intake.refusals({"matrix.json": "modified"}, {"projects": []}, head, "maint", True, set(), HELD)
    assert out == ["project 2 is held for maintainer review"]


def test_a_longer_owner_name_is_not_the_held_one():
    head = {"projects": [proj(2, url="https://github.com/heldowner2/x")]}
    assert intake.refusals({"matrix.json": "modified"}, {"projects": []}, head, "m", True, set(), HELD) == []


def test_a_non_maintainer_may_not_edit_or_remove_a_reviewed_row():
    base = {"projects": [proj(1), proj(2)]}
    edited = {"projects": [proj(1, name="changed")]}
    out = intake.refusals({"matrix.json": "modified"}, base, edited, "outsider", False, set(), HELD)
    assert out == ["projects [1, 2] change a reviewed row; a maintainer records the review"]


def test_a_maintainer_edit_of_an_unheld_row_passes():
    base = {"projects": [proj(1)]}
    head = {"projects": [proj(1, name="changed"), proj(2)]}
    assert intake.refusals({"matrix.json": "modified"}, base, head, "m", True, set(), HELD) == []


def test_maintainer_status_comes_from_repository_permission_not_association():
    """GitHub reports an organization owner with private membership as CONTRIBUTOR; the permission API says admin."""
    def read(perm):
        return lambda *args: json.dumps({"permission": perm})
    assert intake.is_maintainer("o/r", "owner", read=read("admin"))
    assert intake.is_maintainer("o/r", "writer", read=read("write"))
    assert not intake.is_maintainer("o/r", "outsider", read=read("read"))
    assert not intake.is_maintainer("o/r", "nobody", read=read("none"))


def test_an_unreadable_permission_is_a_read_error_not_a_verdict():
    def fail(*args):
        raise intake.ReadError("could not read")
    with pytest.raises(intake.ReadError):
        intake.is_maintainer("o/r", "x", read=fail)
    with pytest.raises(intake.ReadError):
        intake.is_maintainer("o/r", "x", read=lambda *a: "{}")


# Second break pass: each of these passed the gate before the fix.

def test_a_non_maintainer_may_not_change_the_fields_every_row_is_read_under():
    base = {"reader": {"agent-evidence-vectors": "0.36.3"}, "verdicts": ["agrees"], "total_projects": 1,
            "projects": [proj(1)]}
    for key, value in (("reader", {"agent-evidence-vectors": "9.9.9"}), ("verdicts", ["agrees", "trust-me"]),
                       ("total_projects", 40)):
        head = {**base, key: value}
        out = intake.refusals({"matrix.json": "modified"}, base, head, "outsider", False, set(), HELD)
        assert out == [f"matrix.json fields ['{key}'] are read by every row; a maintainer changes them"]
        assert intake.refusals({"matrix.json": "modified"}, base, head, "m", True, set(), HELD) == []


def test_a_second_entry_with_a_reviewed_id_is_refused_and_read_for_held_owners():
    """With the new copy first, the id map kept the reviewed copy and saw no change at all."""
    base = {"projects": [proj(1)]}
    head = {"projects": [proj(1, url="https://github.com/heldowner/x"), proj(1)]}
    for maintainer in (False, True):
        out = intake.refusals({"matrix.json": "modified"}, base, head, "a", maintainer, set(), HELD)
        assert "matrix.json at the head lists a project with no id or ids [1] more than once" in out
        assert "project 1 is held for maintainer review" in out
    head = {"projects": [proj(1), {"name": "no id"}]}
    out = intake.refusals({"matrix.json": "modified"}, base, head, "m", True, set(), HELD)
    assert out[0].startswith("matrix.json at the head lists a project with no id")


@pytest.mark.parametrize("url", ["https://raw.githubusercontent.com/heldowner/x/main/a.json",
                                 "https://heldowner.github.io/x/", "https://github.com/orgs/heldowner",
                                 "https://api.github.com/users/heldowner", "https://github.com/%68eldowner/x",
                                 "https://github.com/%2568eldowner/x", "ghcr.io/heldowner/image"])
def test_a_held_owner_is_found_in_the_other_github_spellings(url):
    head = {"projects": [proj(2, url=url)]}
    out = intake.refusals({"matrix.json": "modified"}, {"projects": []}, head, "m", True, set(), HELD)
    assert out == ["project 2 is held for maintainer review"]


@pytest.mark.parametrize("url", ["https://not-heldowner.github.io/x", "https://heldowner2.github.io/x",
                                 "https://raw.githubusercontent.com/heldowner-x/y"])
def test_a_neighbouring_owner_name_is_not_the_held_one(url):
    head = {"projects": [proj(2, url=url)]}
    assert intake.refusals({"matrix.json": "modified"}, {"projects": []}, head, "m", True, set(), HELD) == []


def test_a_push_by_a_non_maintainer_to_a_maintainers_pull_request_is_judged_as_theirs(monkeypatch, capsys):
    """The author alone decided: someone with push access to a maintainer's fork could add a row unreviewed."""
    perms = {"maint": "admin", "pusher": "read"}

    def fake(*args):
        path = args[-1]
        if "--paginate" in args:
            return json.dumps({"f": "reviews.json", "s": "modified", "p": None}) + "\n"
        if path.endswith("/permission"):
            return json.dumps({"permission": perms[path.split("/")[-2]]})
        return json.dumps({"changed_files": 1})
    monkeypatch.setattr(intake, "gh", fake)
    env = {"REPO": "o/r", "PR": "1", "AUTHOR": "maint", "BASE_SHA": "b", "HEAD_REPO": "o/r", "HEAD_SHA": "h"}
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setenv("SENDER", "maint")
    assert intake.main() == 0
    monkeypatch.setenv("SENDER", "pusher")
    assert intake.main() == 1
    assert "reviews.json is written by maintainers only" in capsys.readouterr().out


@pytest.mark.parametrize("spelling", [
    "https://github.com/​heldowner/x",            # zero-width space before the name
    "https://github.com/held­owner/x",            # soft hyphen inside it
    "https://github.com/held⁠owner/x",            # word joiner
    "ｇｉｔｈｕｂ．ｃｏｍ／heldowner",  # fullwidth github.com/heldowner
    "https://github.com/%E2%80%8Bheldowner/x",          # the zero-width space percent-encoded
    "https://github.com/ＨＥＬＤOWNER/x",  # fullwidth capitals in the name
])
def test_a_held_owner_hidden_by_an_invisible_or_fullwidth_character_is_found(spelling):
    # Each renders in MATRIX.md as the held owner's name; the inline gate read the raw characters and passed them.
    assert intake.held_owner_named(proj(9, note=spelling), HELD)


def test_folding_does_not_invent_a_held_owner():
    assert not intake.held_owner_named(proj(9, note="https://github.com/someone/heldowner"), HELD)
    assert not intake.held_owner_named(proj(9, note="https://github.com/heldowners/x"), HELD)


def held_row(pid, **kw):
    """A row naming a held owner, with one contradicted cell and one supported cell."""
    cells = [{"id": "a", "verdict": "contradicted"}, {"id": "b", "verdict": "supported"}]
    return proj(pid, url="https://github.com/heldowner/x", cells=cells, **kw)


def labelled(row, **labels):
    cells = [dict(c) for c in row["cells"]]
    cells[0].update(labels)
    return {**row, "cells": cells}


LABELS = {"basis": "the maintainer's stated reason", "divergence_in": "spec", "declared_revision": "v1.2"}


def test_a_maintainer_may_label_a_contradicted_cell_of_a_held_row():
    row = held_row(1)
    out = intake.refusals({"matrix.json": "modified"}, {"projects": [row]}, {"projects": [labelled(row, **LABELS)]},
                          "m", True, set(), HELD)
    assert out == []


def test_a_maintainer_may_change_only_the_labels_of_a_held_row():
    row = held_row(1)
    changed = labelled(row, **LABELS)
    changed["name"] = "renamed"
    out = intake.refusals({"matrix.json": "modified"}, {"projects": [row]}, {"projects": [changed]}, "m", True, set(), HELD)
    assert out == ["project 1 is held for maintainer review"]
    flipped = labelled(row, **LABELS)
    flipped["cells"][1]["verdict"] = "contradicted"
    out = intake.refusals({"matrix.json": "modified"}, {"projects": [row]}, {"projects": [flipped]}, "m", True, set(), HELD)
    assert out == ["project 1 is held for maintainer review"]


def test_a_non_maintainer_may_not_label_a_held_row():
    row = held_row(1)
    out = intake.refusals({"matrix.json": "modified"}, {"projects": [row]}, {"projects": [labelled(row, **LABELS)]},
                          "outsider", False, set(), HELD)
    assert "project 1 is held for maintainer review" in out


def test_labels_that_name_a_held_owner_are_refused():
    row = held_row(1)
    named = labelled(row, **{**LABELS, "basis": "see https://github.com/heldowner/x/issues/1"})
    out = intake.refusals({"matrix.json": "modified"}, {"projects": [row]}, {"projects": [named]}, "m", True, set(), HELD)
    assert out == ["project 1 is held for maintainer review"]
