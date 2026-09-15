"""Tests for the decision engine (engine/decision.py)."""

from __future__ import annotations

import io
import sys

import pytest

from ir_soar.actions.base import get_action_class
from ir_soar.config.loader import load_config
from ir_soar.engine.decision import ConditionError, Decision, decide, evaluate_condition
from ir_soar.models.action_result import ActionResult
from ir_soar.models.playbook import Step

CONFIG_PATH = None  # set in fixture below via test_config; kept for clarity


@pytest.fixture
def step_results() -> dict[str, ActionResult]:
    return {
        "correlate_auth_logs": ActionResult(status="success", data={"suspicious": True, "matched_events": 5}),
        "whois_check": ActionResult(status="success", data={"recently_registered": False}),
        "failed_step": ActionResult(status="failure", error="boom"),
    }


@pytest.mark.parametrize(
    ("condition", "expected"),
    [
        (None, True),
        ("steps.correlate_auth_logs.result.suspicious == true", True),
        ("steps.correlate_auth_logs.result.suspicious == false", False),
        ("steps.correlate_auth_logs.result.suspicious", True),
        ("steps.whois_check.result.recently_registered == true", False),
        ("steps.whois_check.result.recently_registered != true", True),
        ("steps.failed_step.result.suspicious == true", False),
        ("steps.never_ran.result.suspicious == true", False),
        ("steps.correlate_auth_logs.result.matched_events == 5", True),
    ],
)
def test_evaluate_condition(condition, expected, step_results: dict[str, ActionResult]) -> None:
    assert evaluate_condition(condition, step_results) is expected


def test_evaluate_condition_rejects_invalid_syntax(step_results: dict[str, ActionResult]) -> None:
    with pytest.raises(ConditionError):
        evaluate_condition("this is not valid syntax at all", step_results)


def test_dry_run_always_auto_approves(test_config) -> None:
    cfg = test_config.model_copy(update={"mode": "dry-run"})
    step = Step(id="isolate_x", action_type="isolate_host", inputs={"hostname": "h"}, requires_approval=True, risk="high")
    action_class = get_action_class("isolate_host")
    decision = decide(step, action_class, cfg, {}, interactive=False)
    assert decision.should_run is True
    assert decision.approved is True
    assert decision.auto_approved is True


def test_enrichment_low_risk_auto_approves_by_default(test_config) -> None:
    cfg = test_config.model_copy(update={"mode": "live"})
    step = Step(id="enrich", action_type="ip_domain_reputation", inputs={"target": "1.2.3.4"}, requires_approval=False, risk="low")
    action_class = get_action_class("ip_domain_reputation")
    decision = decide(step, action_class, cfg, {}, interactive=False)
    assert decision.approved is True
    assert decision.auto_approved is True


def test_containment_requires_approval_and_denies_when_non_interactive(test_config) -> None:
    cfg = test_config.model_copy(update={"mode": "live"})
    step = Step(id="isolate_x", action_type="isolate_host", inputs={"hostname": "h"}, requires_approval=True, risk="high")
    action_class = get_action_class("isolate_host")
    decision = decide(step, action_class, cfg, {}, interactive=False)
    assert decision.should_run is True
    assert decision.approved is False
    assert "non-interactively" in decision.reason


def test_containment_approved_interactively(test_config, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = test_config.model_copy(update={"mode": "live"})
    step = Step(id="isolate_x", action_type="isolate_host", inputs={"hostname": "h"}, requires_approval=True, risk="high")
    action_class = get_action_class("isolate_host")

    monkeypatch.setattr("sys.stdin", io.StringIO("y\n"))
    decision = decide(step, action_class, cfg, {}, interactive=True)
    assert decision.approved is True
    assert decision.auto_approved is False


def test_containment_denied_interactively(test_config, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = test_config.model_copy(update={"mode": "live"})
    step = Step(id="isolate_x", action_type="isolate_host", inputs={"hostname": "h"}, requires_approval=True, risk="high")
    action_class = get_action_class("isolate_host")

    monkeypatch.setattr("sys.stdin", io.StringIO("n\n"))
    decision = decide(step, action_class, cfg, {}, interactive=True)
    assert decision.approved is False


def test_full_auto_bypasses_prompt(test_config) -> None:
    cfg = test_config.model_copy(update={"mode": "live", "full_auto": True})
    step = Step(id="isolate_x", action_type="isolate_host", inputs={"hostname": "h"}, requires_approval=True, risk="high")
    action_class = get_action_class("isolate_host")
    decision = decide(step, action_class, cfg, {}, interactive=False)
    assert decision.approved is True
    assert decision.auto_approved is True
    assert "full-auto" in decision.reason.lower()


def test_condition_false_skips_regardless_of_approval(test_config) -> None:
    cfg = test_config.model_copy(update={"mode": "live"})
    step = Step(
        id="isolate_x", action_type="isolate_host", inputs={"hostname": "h"},
        requires_approval=True, risk="high", condition="steps.missing.result.x == true",
    )
    action_class = get_action_class("isolate_host")
    decision = decide(step, action_class, cfg, {}, interactive=False)
    assert decision.should_run is False


def test_risk_floor_can_auto_approve_containment(test_config) -> None:
    cfg = test_config.model_copy(
        update={"mode": "live", "approval": test_config.approval.model_copy(update={"auto_approve_risk_below": "high"})}
    )
    step = Step(id="block_x", action_type="block_ip_domain", inputs={"target": "1.2.3.4"}, requires_approval=True, risk="medium")
    action_class = get_action_class("block_ip_domain")
    decision = decide(step, action_class, cfg, {}, interactive=False)
    assert decision.approved is True
    assert decision.auto_approved is True
