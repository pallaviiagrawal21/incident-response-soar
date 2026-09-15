"""Tests for safety guardrails (utils/safety.py)."""

from __future__ import annotations

import io

import pytest
from rich.console import Console

from ir_soar.config.schema import AppConfig
from ir_soar.utils import safety as s


def test_run_guard_allows_up_to_the_limit() -> None:
    guard = s.RunGuard(max_actions=3)
    for i in range(3):
        guard.consume(f"step{i}")
    assert guard.count == 3
    assert guard.remaining == 0


def test_run_guard_raises_past_the_limit() -> None:
    guard = s.RunGuard(max_actions=2)
    guard.consume("a")
    guard.consume("b")
    with pytest.raises(s.SafetyError, match="max_actions_per_run"):
        guard.consume("c")


@pytest.mark.parametrize(
    ("risk", "floor", "expected"),
    [("high", "medium", True), ("low", "medium", False), ("medium", "medium", True), ("low", "low", True)],
)
def test_risk_at_or_above(risk: str, floor: str, expected: bool) -> None:
    assert s.risk_at_or_above(risk, floor) is expected


def test_prompt_confirmation_yes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO("y\n"))
    assert s.prompt_confirmation("Proceed?") is True


def test_prompt_confirmation_no(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO("n\n"))
    assert s.prompt_confirmation("Proceed?") is False


def test_prompt_confirmation_eof_denies(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    assert s.prompt_confirmation("Proceed?") is False


def test_redact_sensitive_masks_secret_like_keys() -> None:
    data = {"username": "jdoe", "api_key": "sk-12345", "nested": {"password": "hunter2", "note": "fine"}}
    redacted = s.redact_sensitive(data)
    assert redacted["username"] == "jdoe"
    assert redacted["api_key"] == "***REDACTED***"
    assert redacted["nested"]["password"] == "***REDACTED***"
    assert redacted["nested"]["note"] == "fine"


def _quiet_console() -> Console:
    return Console(file=io.StringIO(), stderr=True)


def test_full_auto_off_is_a_no_op() -> None:
    cfg = AppConfig(full_auto=False)
    s.enforce_full_auto_safety(cfg, interactive=True, console=_quiet_console())  # must not raise or prompt


def test_full_auto_non_interactive_without_ack_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(s.FULL_AUTO_ACK_ENV, raising=False)
    cfg = AppConfig(full_auto=True)
    with pytest.raises(s.SafetyError):
        s.enforce_full_auto_safety(cfg, interactive=False, console=_quiet_console())


def test_full_auto_non_interactive_with_ack_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(s.FULL_AUTO_ACK_ENV, "true")
    cfg = AppConfig(full_auto=True)
    s.enforce_full_auto_safety(cfg, interactive=False, console=_quiet_console())  # must not raise


def test_full_auto_interactive_correct_phrase_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO(s.FULL_AUTO_CONFIRM_PHRASE + "\n"))
    cfg = AppConfig(full_auto=True)
    s.enforce_full_auto_safety(cfg, interactive=True, console=_quiet_console())  # must not raise


def test_full_auto_interactive_wrong_phrase_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO("yes i guess\n"))
    cfg = AppConfig(full_auto=True)
    with pytest.raises(s.SafetyError):
        s.enforce_full_auto_safety(cfg, interactive=True, console=_quiet_console())
