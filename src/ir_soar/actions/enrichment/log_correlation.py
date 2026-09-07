"""
Enrichment action: simulated log correlation for a user over a time window.

Real implementations would query a SIEM/log platform (Splunk, Elastic,
Sentinel, etc.) via a connector; this default simulated implementation
lets playbooks and the engine be fully exercised (including the
`condition:` branching that depends on this action's `suspicious` field)
without any real log infrastructure being present. See docs/extending.md
for how a real log-source connector would slot in here.
"""

from __future__ import annotations

from typing import Any

from ir_soar.actions.base import BaseAction, register_action
from ir_soar.actions.enrichment._simulation import simulated_bool, stable_int
from ir_soar.config.schema import AppConfig
from ir_soar.utils.validation import ValidationError, validate_username

_MIN_WINDOW_MINUTES = 1
_MAX_WINDOW_MINUTES = 1440  # 24 hours — a sane upper bound for a single correlation query


@register_action("log_correlation")
class LogCorrelationAction(BaseAction):
    description = "Correlate authentication/access logs for a user over a time window."
    default_risk = "low"

    def validate_inputs(self, inputs: dict[str, Any]) -> dict[str, Any]:
        user = inputs.get("user")
        if not user:
            raise ValidationError("log_correlation requires a non-empty 'user' input")
        username = validate_username(user)

        window_raw = inputs.get("window_minutes", 60)
        try:
            window = int(window_raw)
        except (TypeError, ValueError) as exc:
            raise ValidationError(f"'window_minutes' must be an integer, got {window_raw!r}") from exc
        if not (_MIN_WINDOW_MINUTES <= window <= _MAX_WINDOW_MINUTES):
            raise ValidationError(
                f"'window_minutes' must be between {_MIN_WINDOW_MINUTES} and {_MAX_WINDOW_MINUTES}, got {window}"
            )
        return {"user": username, "window_minutes": window}

    def dry_run_preview(self, inputs: dict[str, Any]) -> dict[str, Any]:
        return {
            "would_execute": self.action_name,
            "user": inputs["user"],
            "window_minutes": inputs["window_minutes"],
        }

    def execute(self, inputs: dict[str, Any], config: AppConfig) -> dict[str, Any]:
        seed = f"{inputs['user']}:{inputs['window_minutes']}"
        suspicious = simulated_bool(seed, probability_pct=35)
        matched_events = stable_int(seed, 12) if suspicious else stable_int(seed, 3)

        sample_events: list[str] = []
        if suspicious:
            sample_events = [
                f"Anomalous sign-in for '{inputs['user']}' from an unfamiliar network location",
                f"Sign-in for '{inputs['user']}' outside typical business hours",
            ][: max(1, min(2, matched_events))]

        return {
            "user": inputs["user"],
            "window_minutes": inputs["window_minutes"],
            "suspicious": suspicious,
            "matched_events": matched_events,
            "sample_events": sample_events,
            "source": "simulated_log_correlation",
        }
