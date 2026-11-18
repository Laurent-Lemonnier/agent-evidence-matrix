"""The required-check reader passes only when main's rules require the review gate.

Counter-example: on 17 Nov 2026 `rules/branches/main` answered [] and the intake gate was advisory.
"""
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "tools"))
import required_checks as rc  # noqa: E402


def rule(*contexts, kind="required_status_checks"):
    return {"type": kind, "parameters": {"required_status_checks": [{"context": c} for c in contexts]}}


def test_no_rules_means_the_gate_is_not_required():
    assert rc.missing([]) == ["intake"]


@pytest.mark.parametrize("rules", [None, {}, "[]", [rule("build")], [rule("intake", kind="pull_request")],
                                   [{"type": "required_status_checks"}], [{"type": "required_status_checks",
                                                                           "parameters": {"required_status_checks": [
                                                                               {"context": 1}, "intake"]}}]])
def test_anything_short_of_a_required_intake_context_is_missing(rules):
    assert rc.missing(rules) == ["intake"]


def test_a_required_intake_context_passes():
    assert rc.missing([rule("build"), rule("intake")]) == []
