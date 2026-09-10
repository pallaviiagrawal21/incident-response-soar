"""
Decision engine: evaluates a playbook step's `condition` guard and decides
whether the step requires human approval before it may run for real.

Two separate concerns live here, both kept deliberately simple and
auditable:

1. `evaluate_condition` — a small, safe, regex-based evaluator for guard
   expressions like `steps.correlate_auth_logs.result.suspicious == true`.
   There is NO `eval()` anywhere in this module, on principle: playbook
   YAML is treated as semi-trusted configuration, not as code, even though
   in this project it is authored by the same person running the engine.

2. `decide` — combines the step's own `requires_approval` flag, the
   category-level policy (`config.approval.require_for_containment` /
   `require_for_enrichment`), and the global risk floor
   (`config.approval.auto_approve_risk_below`) into a single approval
   decision, prompting the operator interactively when needed (or
   respecting `--full-auto`, per `utils/safety.py`).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from ir_soar.actions.base import BaseAction
from ir_soar.config.schema import AppConfig
from ir_soar.models.action_result import ActionResult
from ir_soar.models.playbook import Step
from ir_soar.utils.safety import prompt_confirmation, risk_at_or_above

_CONDITION_RE = re.compile(
    r"^steps\.(?P<step_id>[a-z][a-z0-9_]*)\.result\.(?P<field>[a-zA-Z0-9_.]+)"
    r"(?:\s*(?P<op>==|!=)\s*(?P<rhs>.+))?$"
)


class ConditionError(RuntimeError):
    """Raised when a step's `condition` string cannot be parsed."""


def _parse_literal(raw: str) -> Any:
    raw = raw.strip()
    if raw.lower() == "true":
        return True
    if raw.lower() == "false":
        return False
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in ("'", '"'):
        return raw[1:-1]
    try:
        return float(raw) if "." in raw else int(raw)
    except ValueError as exc:
        raise ConditionError(f"Cannot parse literal '{raw}' in condition") from exc


def _get_field(data: dict[str, Any], dotted_field: str) -> Any:
    cursor: Any = data
    for part in dotted_field.split("."):
        if not isinstance(cursor, dict) or part not in cursor:
            return None
        cursor = cursor[part]
    return cursor


def evaluate_condition(condition: str | None, step_results: dict[str, ActionResult]) -> bool:
    """Evaluate a `condition` guard string against prior step results.

    Returns True (step should run) if `condition` is None. If the
    referenced step never ran successfully (skipped, failed, or simply
    hasn't executed), returns False — a condition can only gate forward on
    a successfully-evaluated prior result; it never raises over a missing
    dependency, since "the prerequisite didn't happen" is itself a valid,
    common outcome (e.g. an earlier enrichment step failed).

    Raises:
        ConditionError: if `condition` is non-None but doesn't match the
            supported `steps.<id>.result.<field> [== | != <literal>]`
            grammar, or if the literal on the right-hand side can't be
            parsed.
    """
    if condition is None:
        return True

    match = _CONDITION_RE.match(condition.strip())
    if not match:
        raise ConditionError(
            f"Unsupported condition syntax: '{condition}'. Expected "
            "'steps.<id>.result.<field>' optionally followed by '==' or '!=' and a literal."
        )

    step_id = match.group("step_id")
    field = match.group("field")
    op = match.group("op")
    rhs_raw = match.group("rhs")

    result = step_results.get(step_id)
    if result is None or result.status != "success":
        return False

    value = _get_field(result.data, field)

    if op is None:
        return bool(value)

    rhs = _parse_literal(rhs_raw)
    return value == rhs if op == "==" else value != rhs


@dataclass
class Decision:
    """The outcome of evaluating one step's guard + approval gate."""

    should_run: bool
    approved: bool
    auto_approved: bool
    reason: str


def decide(
    step: Step,
    action_class: type[BaseAction],
    config: AppConfig,
    step_results: dict[str, ActionResult],
    *,
    interactive: bool,
) -> Decision:
    """Decide whether `step` should run at all, and whether it is approved.

    `approved` is meaningless (always True) whenever `should_run` is False,
    and is always True in dry-run mode, since nothing has a real side
    effect to approve.
    """
    try:
        should_run = evaluate_condition(step.condition, step_results)
    except ConditionError as exc:
        return Decision(should_run=False, approved=False, auto_approved=False, reason=f"Condition error: {exc}")

    if not should_run:
        return Decision(
            should_run=False, approved=False, auto_approved=False, reason="Condition evaluated to false; step skipped"
        )

    if config.mode == "dry-run":
        return Decision(should_run=True, approved=True, auto_approved=True, reason="Dry-run mode: no approval needed")

    category_requires_approval = (
        config.approval.require_for_containment
        if action_class.category == "containment"
        else config.approval.require_for_enrichment
    )
    needs_approval = step.requires_approval or category_requires_approval

    # The global risk floor can auto-approve a step regardless of the above
    # flags — this is deliberate operator-controlled policy (see
    # config.approval.auto_approve_risk_below in the approved Phase 1 plan),
    # not a bug: an environment can choose to move the floor up to relax
    # approval requirements for genuinely low-risk steps.
    if not risk_at_or_above(step.risk, config.approval.auto_approve_risk_below):
        needs_approval = False

    if not needs_approval:
        return Decision(
            should_run=True, approved=True, auto_approved=True,
            reason="Auto-approved (approval not required for this step/category/risk)",
        )

    if config.full_auto:
        return Decision(
            should_run=True, approved=True, auto_approved=True,
            reason="Full-auto mode: interactive approval bypassed per operator acknowledgement",
        )

    if not interactive:
        return Decision(
            should_run=True, approved=False, auto_approved=False,
            reason="Approval required but running non-interactively; denied by default",
        )

    approved = prompt_confirmation(
        f"Step '{step.id}' ({step.action_type}, risk={step.risk}) requires approval. Proceed?"
    )
    reason = "Operator approved interactively" if approved else "Operator denied interactively"
    return Decision(should_run=True, approved=approved, auto_approved=False, reason=reason)
