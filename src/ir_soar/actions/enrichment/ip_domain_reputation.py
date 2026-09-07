"""
Enrichment action: IP / domain reputation lookup.

Abstracted behind `config.enrichment_providers.ip_reputation.type` so a
real provider (AbuseIPDB, VirusTotal, etc.) can be plugged in later without
changing this action's interface or any playbook that references it — see
docs/extending.md.
"""

from __future__ import annotations

from typing import Any

from ir_soar.actions.base import BaseAction, register_action
from ir_soar.actions.enrichment._simulation import simulated_verdict
from ir_soar.config.schema import AppConfig
from ir_soar.utils.validation import ValidationError, is_valid_ip, validate_domain, validate_ip


@register_action("ip_domain_reputation")
class IpDomainReputationAction(BaseAction):
    description = "Look up reputation for an IP address or domain name."
    default_risk = "low"

    def validate_inputs(self, inputs: dict[str, Any]) -> dict[str, Any]:
        target = inputs.get("target")
        if not target:
            raise ValidationError("ip_domain_reputation requires a non-empty 'target' input")
        if is_valid_ip(target):
            return {"target": validate_ip(target), "target_type": "ip"}
        try:
            return {"target": validate_domain(target), "target_type": "domain"}
        except ValidationError as exc:
            raise ValidationError(f"'{target}' is neither a valid IP address nor a valid domain") from exc

    def dry_run_preview(self, inputs: dict[str, Any]) -> dict[str, Any]:
        return {
            "would_execute": self.action_name,
            "target": inputs["target"],
            "target_type": inputs["target_type"],
        }

    def execute(self, inputs: dict[str, Any], config: AppConfig) -> dict[str, Any]:
        provider = config.enrichment_providers.ip_reputation
        if provider.type != "simulated":
            raise NotImplementedError(
                f"Enrichment provider type '{provider.type}' is not yet implemented. "
                "See docs/extending.md for how to add a real provider connector."
            )
        verdict, score = simulated_verdict(inputs["target"])
        return {
            "target": inputs["target"],
            "target_type": inputs["target_type"],
            "verdict": verdict,
            "score": score,
            "provider": "simulated",
        }
