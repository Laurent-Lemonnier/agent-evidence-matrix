"""The matrix builder refuses mislabelled cells, unreviewed projects and paths a reader cannot open.

Each fixture is one mislabel class that a published matrix carried before the schema existed: a
refusal inside a declared profile shown as a contradiction, an expected rejection counted as a
contradiction, a contradiction with no stated basis, and evidence that pointed at one laptop.
"""
import copy
import json
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import build_matrix as bm  # noqa: E402


def cell(**kw):
    base = {"cell": "c", "source": "their records", "verdict": "agrees", "evidence": "adapters/rfc8785_cli.py"}
    base.update(kw)
    return base


def project(pid=1, cells=None, **kw):
    p = {"id": pid, "name": f"p{pid}", "cells": cells or [cell()],
         "upstream": {"url": f"https://github.com/example/p{pid}", "sha": "a" * 40}, "replay": "true"}
    p.update(kw)
    return p


def matrix(*projects):
    return {"reader": {"agent-evidence-vectors": "0", "agent-evidence-verify": "0"},
            "verdicts": ["agrees", "contradicted", "cannot-tell", "unsupported", "not run"],
            "total_projects": len(projects), "projects": list(projects)}


def reviews(*ids, frozen=None):
    out = [{"project": i, "review": f"R-{i}", "date": "2026-11-15", "state": "published"} for i in ids]
    for p in frozen or []:
        out.append({"project": p["id"], "review": "R-f", "date": "2026-11-15", "state": "frozen",
                    "digest": bm.project_digest(p)})
    return {"reviews": out}


def check(*projects, frozen=()):
    ids = [p["id"] for p in projects if p not in frozen]
    return bm.problems(matrix(*projects), reviews(*ids, frozen=list(frozen)), ROOT)


def test_the_live_matrix_is_clean():
    data = json.loads((ROOT / "matrix.json").read_text())
    rev = json.loads((ROOT / "reviews.json").read_text())
    assert bm.problems(data, rev, ROOT) == []


def test_a_project_without_a_review_is_refused():
    out = bm.problems(matrix(project(1)), {"reviews": []}, ROOT)
    assert any("no review entry" in line for line in out)


def test_a_frozen_project_keeps_its_bytes():
    p = project(1)
    assert check(p, frozen=[p]) == []
    changed = copy.deepcopy(p)
    changed["cells"][0]["detail"] = "edited"
    out = bm.problems(matrix(changed), reviews(frozen=[p]), ROOT)
    assert any("frozen and the entry changed" in line for line in out)


def test_a_contradiction_needs_basis_divergence_and_revision():
    out = check(project(1, [cell(verdict="contradicted")]))
    for key in ("basis", "divergence_in", "declared_revision"):
        assert any(f"needs {key}" in line for line in out)
    ok = cell(verdict="contradicted", basis="defect", divergence_in="their spec", declared_revision="draft-x-01")
    assert check(project(1, [ok])) == []


def test_a_refusal_inside_a_declared_profile_is_unsupported_not_contradicted():
    # The 1e20 and 1e21 refusals of an integer-only profile were published as a contradiction.
    wrong = cell(verdict="contradicted", basis="declared-profile", divergence_in="their code",
                 declared_revision="r", profile="integers below 2^53")
    assert any("not contradicted" in line for line in check(project(1, [wrong])))
    right = cell(verdict="unsupported", basis="declared-profile", profile="integers below 2^53")
    assert check(project(1, [right])) == []
    assert any("requires the profile" in line
               for line in check(project(1, [cell(verdict="unsupported", basis="declared-profile")])))


@pytest.mark.parametrize("verdict,ok", [("agrees", True), ("contradicted", False)])
def test_an_expected_rejection_that_is_rejected_agrees(verdict, ok):
    # A tampered fixture that declares REJECT and is rejected was counted as contradicted.
    c = cell(verdict=verdict, expected="REJECT", observed="REJECT", expected_source="the fixture's expect member",
             basis="defect", divergence_in="their records", declared_revision="r")
    assert (check(project(1, [c])) == []) is ok


def test_an_outcome_different_from_the_declared_one_is_never_agreement():
    c = cell(verdict="agrees", expected="SATISFIED", observed="VIOLATED", expected_source="fixture")
    assert any("differs from expected" in line for line in check(project(1, [c])))


def test_evidence_must_resolve_in_the_tree():
    out = check(project(1, [cell(evidence="adapters/no-such-run.txt")]))
    assert any("does not resolve" in line for line in out)


@pytest.mark.parametrize("evidence", ["_raw/kenosian-retry2.log", "/home/someone/run.txt", "~/x/run.txt",
                                      "see probity-lanes/x"])
def test_evidence_on_one_machine_is_refused(evidence):
    assert any("one machine" in line for line in check(project(1, [cell(evidence=evidence)])))


def test_a_result_needs_an_upstream_pin_and_a_replay():
    p = project(1)
    del p["replay"]
    assert any("needs upstream.url" in line for line in check(p))
    bare = {"id": 2, "name": "n", "cells": [cell(verdict="unsupported", source="none", evidence="no records")]}
    assert check(bare) == []


def test_two_projects_never_share_an_upstream():
    a, b = project(1), project(2)
    b["upstream"] = dict(a["upstream"])
    assert any("share the upstream" in line for line in check(a, b))


def test_columns_use_listed_names_and_need_evidence_for_a_result():
    bad = project(1, columns={"vibes": {"verdict": "agrees"}})
    assert any("unknown column" in line for line in check(bad))
    no_ev = project(1, columns={"edit detection": {"verdict": "agrees"}})
    assert any("no evidence" in line for line in check(no_ev))
    ok = project(1, columns={"edit detection": {"verdict": "not run"}})
    assert check(ok) == []


def test_frozen_projects_get_no_badge():
    a, b = project(1), project(2)
    _, badges = bm.render(matrix(a, b), reviews(1, frozen=[b]))
    assert set(badges) == {"badges/1.json"}
    assert json.loads(badges["badges/1.json"])["message"] == "1 agrees / 1 cells"


def test_freshness_reports_a_moved_upstream_and_a_failed_read():
    data = matrix(project(1), project(2))

    def fetch(owner, repo):
        if repo == "p2":
            raise RuntimeError("HTTP 404")
        return "b" * 40

    lines = bm.freshness(data, fetch)
    assert any("project 1: upstream-moved" in line for line in lines)
    assert any("project 2: freshness not checked" in line for line in lines)
    assert bm.freshness(matrix(project(1)), lambda o, r: "a" * 40) == []


def test_unread_count_counts_projects_with_no_result():
    c = bm.counts(matrix(project(1), {"id": 2, "name": "n", "cells": [cell(verdict="not run")]}))
    assert c["unread"] == {2} and c["run"] == {1}
