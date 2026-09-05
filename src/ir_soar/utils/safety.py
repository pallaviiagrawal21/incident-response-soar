"""
Safety guardrails for ir_soar.

Everything an operator relies on to trust "full-auto won't do something
crazy" lives here:

  - `enforce_full_auto_safety`: the loud warning banner + explicit
    acknowledgement gate that MUST pass before full-auto is allowed to run.
  - `prompt_confirmation`: a single, non-looping y/N prompt for human
    approval gates (containment steps, by default).
  - `RunGuard`: the hard ceiling on total actions in a run — one of the
    architectural guarantees that the engine cannot loop indefinitely.
  - `redact_sensitive`: shallow secret redaction for anything written to
    logs or the audit trail.

Nothing here talks to a real connector or executes anything itself — this
module is pure guardrail logic, reused identically by the engine, the CLI,
and (in tests) directly.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from rich.console import Console
from rich.panel import Panel

from ir_soar.config.schema import AppConfig, RiskLevel

FULL_AUTO_ACK_ENV = "IR_SOAR_FULL_AUTO_ACK"
FULL_AUTO_CONFIRM_PHRASE = "I UNDERSTAND THE RISK"

_RISK_ORDER: dict[RiskLevel, int] = {"low": 0, "medium": 1, "high": 2}
_SENSITIVE_KEY_HINTS = ("key", "token", "secret", "password", "credential")


class SafetyError(RuntimeError):
    """Raised when a safety guardrail blocks a run or an action."""


def risk_at_or_above(risk: RiskLevel, floor: RiskLevel) -> bool:
    """True if `risk` is at least as severe as `floor` (low < medium < high)."""
    return _RISK_ORDER[risk] >= _RISK_ORDER[floor]


def is_dangerous_action(risk: RiskLevel, config: AppConfig) -> bool:
    """True if `risk` meets or exceeds the configured dangerous-action floor."""
    return risk_at_or_above(risk, config.safety.dangerous_action_risk_floor)


def warn_if_dangerous(step_id: str, risk: RiskLevel, config: AppConfig, logger: logging.Logger) -> None:
    """Emit a WARNING-level log line if this step is classified as dangerous."""
    if is_dangerous_action(risk, config):
        logger.warning(
            "DANGEROUS ACTION: step '%s' has risk level '%s' (>= configured floor '%s')",
            step_id,
            risk,
            config.safety.dangerous_action_risk_floor,
            extra={"extra_fields": {"step_id": step_id, "risk": risk, "dangerous": True}},
        )


def prompt_confirmation(message: str) -> bool:
    """
    Block for exactly one y/N answer from the operator.

    Deliberately NOT a retry loop: any answer other than 'y'/'yes'
    (including a closed/EOF stdin, e.g. a non-interactive shell) is treated
    as "deny" and returned as False. Callers that need to fail loudly on a
    non-interactive deny should check `sys.stdin.isatty()` before calling
    this and raise SafetyError themselves — see `enforce_full_auto_safety`
    for that pattern.
    """
    try:
        answer = input(f"{message} [y/N]: ").strip().lower()
    except EOFError:
        return False
    return answer in ("y", "yes")


def print_full_auto_banner(console: Console | None = None) -> None:
    """Print an unmissable warning banner before a full-auto run."""
    console = console or Console(stderr=True)
    message = (
        "[bold]FULL-AUTO MODE[/bold] is enabled.\n\n"
        "Containment actions that would normally require human approval\n"
        "WILL EXECUTE AUTOMATICALLY, subject to configured risk thresholds.\n\n"
        "Validation, timeouts, retry limits, and audit logging still apply —\n"
        "only the interactive approval prompt is skipped."
    )
    console.print(Panel(message, title="⚠ WARNING ⚠", style="bold white on red", expand=False))


def enforce_full_auto_safety(config: AppConfig, *, interactive: bool, console: Console | None = None) -> None:
    """
    Gate that MUST be called once, before any run in full-auto mode.

    - No-op if `config.full_auto` is False.
    - If interactive: prints the warning banner and requires the operator
      to type the exact confirmation phrase. Exactly one prompt — a wrong
      answer aborts the run rather than re-prompting.
    - If non-interactive (CI/cron/scripted): requires
      `IR_SOAR_FULL_AUTO_ACK=true` to already be set in the environment,
      since there is no human present to answer a prompt.

    Raises:
        SafetyError: if the acknowledgement is not obtained.
    """
    if not config.full_auto:
        return

    print_full_auto_banner(console)

    if interactive:
        try:
            answer = input(f'Type "{FULL_AUTO_CONFIRM_PHRASE}" to proceed: ').strip()
        except EOFError as exc:
            raise SafetyError(
                "Full-auto acknowledgement required but stdin is closed (non-interactive session)."
            ) from exc
        if answer != FULL_AUTO_CONFIRM_PHRASE:
            raise SafetyError("Full-auto acknowledgement phrase did not match. Aborting run.")
    else:
        if os.environ.get(FULL_AUTO_ACK_ENV, "").strip().lower() != "true":
            raise SafetyError(
                f"Full-auto mode requires {FULL_AUTO_ACK_ENV}=true when running "
                "non-interactively (no operator available to confirm the warning)."
            )


class RunGuard:
    """
    Enforces the hard `max_actions_per_run` ceiling from config.

    The executor MUST call `.consume(step_id)` before running each action.
    Once the ceiling is reached, every subsequent call raises SafetyError
    instead of executing — this is one of the architectural guarantees that
    ir_soar cannot loop or run away indefinitely, independent of anything a
    malformed or malicious playbook might try to do.
    """

    def __init__(self, max_actions: int) -> None:
        if max_actions < 1:
            raise ValueError("max_actions must be >= 1")
        self._max_actions = max_actions
        self._count = 0

    @property
    def count(self) -> int:
        return self._count

    @property
    def remaining(self) -> int:
        return max(self._max_actions - self._count, 0)

    def consume(self, step_id: str) -> None:
        if self._count >= self._max_actions:
            raise SafetyError(
                f"Run exceeded max_actions_per_run={self._max_actions} at step '{step_id}'. "
                "Aborting to prevent runaway execution."
            )
        self._count += 1


def redact_sensitive(data: dict[str, Any]) -> dict[str, Any]:
    """
    Recursively redact values whose key name suggests a secret (key, token,
    secret, password, credential — case-insensitive substring match).

    Used before writing action inputs/results to logs or the audit trail.
    This is a pragmatic, naming-convention-based safeguard, not a
    substitute for never putting real secrets in playbook inputs in the
    first place (which the config schema already enforces by only ever
    passing around env-var *names*, not values).
    """
    redacted: dict[str, Any] = {}
    for key, value in data.items():
        if isinstance(value, dict):
            redacted[key] = redact_sensitive(value)
        elif any(hint in key.lower() for hint in _SENSITIVE_KEY_HINTS):
            redacted[key] = "***REDACTED***"
        else:
            redacted[key] = value
    return redacted
