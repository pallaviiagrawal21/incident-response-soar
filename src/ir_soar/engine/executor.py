"""
Core execution engine: walks a `Playbook`'s phases/steps in order, applies
the decision gate for each step, resolves and runs actions (via
`BaseAction.run()`, itself timeout-bounded per attempt), retries failed
live actions up to a bounded number of attempts with backoff, records every
decision and result to the hash-chained audit trail, and enforces the hard
`max_actions_per_run` ceiling via `RunGuard`.

This is the one place playbook data and action code actually meet.
Everything above this layer deals only with data (YAML) or isolated logic
(a single action, a single decision). The executor is the last line of
defense against a malformed playbook: every loop here is bounded — by
`max_actions_per_run` (RunGuard), by `max_retries`/per-step `retries`
(attempt count), and by `default_timeout_seconds`/per-step `timeout_seconds`
(each individual attempt) — so no playbook, however written, can make a
run hang or run away indefinitely.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field as dc_field
from typing import Any

from ir_soar.actions.base import get_action_class
from ir_soar.config.schema import AppConfig
from ir_soar.engine.decision import decide
from ir_soar.engine.templating import TemplateRenderError, render_inputs
from ir_soar.models.action_result import ActionResult
from ir_soar.models.playbook import Playbook
from ir_soar.utils.logging import AuditLogger
from ir_soar.utils.safety import RunGuard, SafetyError, redact_sensitive, warn_if_dangerous


@dataclass
class StepOutcome:
    """What happened for one playbook step during a run."""

    step_id: str
    phase: str
    action_type: str
    ran: bool
    decision_reason: str
    result: ActionResult | None
    attempts: int


@dataclass
class RunResult:
    """Summary of an entire playbook run, returned by `Executor.run()`."""

    playbook_id: str
    mode: str
    dry_run: bool
    outcomes: list[StepOutcome] = dc_field(default_factory=list)
    aborted: bool = False
    abort_reason: str | None = None

    @property
    def executed_steps(self) -> list[StepOutcome]:
        return [o for o in self.outcomes if o.ran]

    @property
    def succeeded_steps(self) -> list[StepOutcome]:
        return [o for o in self.outcomes if o.result is not None and o.result.succeeded]

    @property
    def failed_steps(self) -> list[StepOutcome]:
        return [o for o in self.outcomes if o.result is not None and not o.result.succeeded]

    @property
    def skipped_steps(self) -> list[StepOutcome]:
        return [o for o in self.outcomes if not o.ran]


class Executor:
    """Runs a single `Playbook` against a single incident context."""

    def __init__(
        self,
        config: AppConfig,
        audit: AuditLogger,
        *,
        interactive: bool,
        logger: logging.Logger | None = None,
    ) -> None:
        self._config = config
        self._audit = audit
        self._interactive = interactive
        self._logger = logger or logging.getLogger("ir_soar.engine.executor")

    def run(self, playbook: Playbook, incident_context: dict[str, Any]) -> RunResult:
        dry_run = self._config.mode == "dry-run"
        result = RunResult(playbook_id=playbook.id, mode=self._config.mode, dry_run=dry_run)
        guard = RunGuard(self._config.execution.max_actions_per_run)
        step_results: dict[str, ActionResult] = {}

        self._audit.log_event(
            "run_started",
            playbook_id=playbook.id,
            mode=self._config.mode,
            full_auto=self._config.full_auto,
            environment=self._config.environment,
        )
        self._logger.info(
            "Starting run of playbook '%s' (mode=%s, environment=%s)",
            playbook.id,
            self._config.mode,
            self._config.environment,
        )

        for phase in playbook.phases:
            if result.aborted:
                break
            for step in phase.steps:
                outcome = self._run_step(phase.name, step, guard, step_results, incident_context, dry_run)
                result.outcomes.append(outcome)
                if outcome.result is not None:
                    step_results[step.id] = outcome.result

                if outcome.result is None:
                    continue  # skipped by condition — nothing to evaluate for on_success/on_failure

                if outcome.result.succeeded:
                    if step.on_success == "abort_run":
                        result.aborted = True
                        result.abort_reason = f"Step '{step.id}' succeeded and on_success=abort_run (explicit stop point)"
                else:
                    if outcome.decision_reason == "Run guard ceiling reached":
                        result.aborted = True
                        result.abort_reason = outcome.result.error
                    elif step.on_failure == "abort_run":
                        result.aborted = True
                        result.abort_reason = f"Step '{step.id}' failed and on_failure=abort_run"
                    elif step.on_failure == "continue_with_warning":
                        self._logger.warning(
                            "Step '%s' failed (%s); continuing per on_failure=continue_with_warning",
                            step.id,
                            outcome.result.error,
                        )

                if result.aborted:
                    self._audit.log_event(
                        "run_aborted", playbook_id=playbook.id, step_id=step.id, reason=result.abort_reason
                    )
                    self._logger.error("Run aborted: %s", result.abort_reason)
                    break

        self._audit.log_event(
            "run_finished",
            playbook_id=playbook.id,
            aborted=result.aborted,
            total_steps=len(result.outcomes),
            succeeded=len(result.succeeded_steps),
            failed=len(result.failed_steps),
            skipped=len(result.skipped_steps),
        )
        self._logger.info(
            "Run of playbook '%s' finished (aborted=%s, succeeded=%d, failed=%d, skipped=%d)",
            playbook.id,
            result.aborted,
            len(result.succeeded_steps),
            len(result.failed_steps),
            len(result.skipped_steps),
        )
        return result

    # -- internal ----------------------------------------------------------

    def _run_step(
        self,
        phase_name: str,
        step: Any,
        guard: RunGuard,
        step_results: dict[str, ActionResult],
        incident_context: dict[str, Any],
        dry_run: bool,
    ) -> StepOutcome:
        try:
            action_class = get_action_class(step.action_type)
        except KeyError as exc:
            self._logger.error(str(exc))
            failure = ActionResult(status="failure", error=str(exc), dry_run=dry_run)
            self._audit.log_event(
                "action_result", step_id=step.id, phase=phase_name, action_type=step.action_type,
                status="failure", error=str(exc),
            )
            return StepOutcome(
                step_id=step.id, phase=phase_name, action_type=step.action_type,
                ran=False, decision_reason="Unknown action_type", result=failure, attempts=0,
            )

        warn_if_dangerous(step.id, step.risk, self._config, self._logger)

        decision = decide(step, action_class, self._config, step_results, interactive=self._interactive)
        self._audit.log_event(
            "decision", step_id=step.id, phase=phase_name, action_type=step.action_type,
            risk=step.risk, should_run=decision.should_run, approved=decision.approved,
            auto_approved=decision.auto_approved, reason=decision.reason,
        )

        if not decision.should_run:
            return StepOutcome(
                step_id=step.id, phase=phase_name, action_type=step.action_type,
                ran=False, decision_reason=decision.reason, result=None, attempts=0,
            )

        if not decision.approved:
            denied = ActionResult(status="skipped", error="Not approved", dry_run=dry_run)
            self._audit.log_event(
                "action_result", step_id=step.id, phase=phase_name, action_type=step.action_type,
                status="skipped", error="Not approved",
            )
            return StepOutcome(
                step_id=step.id, phase=phase_name, action_type=step.action_type,
                ran=False, decision_reason=decision.reason, result=denied, attempts=0,
            )

        try:
            guard.consume(step.id)
        except SafetyError as exc:
            self._logger.error(str(exc))
            failure = ActionResult(status="failure", error=str(exc), dry_run=dry_run)
            self._audit.log_event(
                "action_result", step_id=step.id, phase=phase_name, action_type=step.action_type,
                status="failure", error=str(exc),
            )
            return StepOutcome(
                step_id=step.id, phase=phase_name, action_type=step.action_type,
                ran=False, decision_reason="Run guard ceiling reached", result=failure, attempts=0,
            )

        try:
            rendered_inputs = render_inputs(step.inputs, incident_context)
        except TemplateRenderError as exc:
            self._logger.error(str(exc))
            failure = ActionResult(status="failure", error=str(exc), dry_run=dry_run)
            self._audit.log_event(
                "action_result", step_id=step.id, phase=phase_name, action_type=step.action_type,
                status="failure", error=str(exc),
            )
            return StepOutcome(
                step_id=step.id, phase=phase_name, action_type=step.action_type,
                ran=True, decision_reason=decision.reason, result=failure, attempts=0,
            )

        action = action_class()
        configured_retries = step.retries if step.retries is not None else self._config.execution.max_retries
        max_attempts = 1 + configured_retries
        timeout = step.timeout_seconds or self._config.execution.default_timeout_seconds

        attempt = 0
        action_result: ActionResult | None = None
        while attempt < max_attempts:
            attempt += 1
            action_result = action.run(rendered_inputs, self._config, dry_run=dry_run, timeout_seconds=timeout)
            self._audit.log_event(
                "action_result", step_id=step.id, phase=phase_name, action_type=step.action_type,
                attempt=attempt, max_attempts=max_attempts, status=action_result.status,
                dry_run=action_result.dry_run, duration_ms=action_result.duration_ms,
                error=action_result.error,
                data=redact_sensitive(action_result.data) if action_result.data else {},
            )
            if action_result.succeeded or dry_run:
                break
            if attempt < max_attempts:
                backoff = self._config.execution.retry_backoff_seconds
                self._logger.warning(
                    "Step '%s' attempt %d/%d failed (%s); retrying in %.1fs",
                    step.id, attempt, max_attempts, action_result.error, backoff,
                )
                time.sleep(backoff)

        return StepOutcome(
            step_id=step.id, phase=phase_name, action_type=step.action_type,
            ran=True, decision_reason=decision.reason, result=action_result, attempts=attempt,
        )
