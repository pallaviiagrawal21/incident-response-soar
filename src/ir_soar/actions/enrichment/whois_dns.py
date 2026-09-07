"""
Enrichment action: basic WHOIS / DNS lookup for a domain.

Abstracted behind `config.enrichment_providers.whois_dns.type` so a real
WHOIS/DNS provider can be plugged in later without changing this action's
interface or any playbook that references it — see docs/extending.md.
"""

from __future__ import annotations

from typing import Any

from ir_soar.actions.base import BaseAction, register_action
from ir_soar.actions.enrichment._simulation import simulated_age_days, stable_int
from ir_soar.config.schema import AppConfig
from ir_soar.utils.validation import ValidationError, validate_domain

_RECENTLY_REGISTERED_THRESHOLD_DAYS = 30


@register_action("whois_dns")
class WhoisDnsAction(BaseAction):
    description = "Basic WHOIS/DNS lookup for a domain (registrar, age, name servers)."
    default_risk = "low"

    def validate_inputs(self, inputs: dict[str, Any]) -> dict[str, Any]:
        target = inputs.get("target")
        if not target:
            raise ValidationError("whois_dns requires a non-empty 'target' input")
        return {"target": validate_domain(target)}

    def dry_run_preview(self, inputs: dict[str, Any]) -> dict[str, Any]:
        return {"would_execute": self.action_name, "target": inputs["target"]}

    def execute(self, inputs: dict[str, Any], config: AppConfig) -> dict[str, Any]:
        provider = config.enrichment_providers.whois_dns
        if provider.type != "simulated":
            raise NotImplementedError(
                f"Enrichment provider type '{provider.type}' is not yet implemented. "
                "See docs/extending.md for how to add a real provider connector."
            )
        target = inputs["target"]
        age_days = simulated_age_days(target)
        registrar = f"Simulated Registrar {stable_int(target, 20) + 1}"
        name_servers = [f"ns{i}.simulated-dns.example" for i in (1, 2)]
        return {
            "target": target,
            "registrar": registrar,
            "domain_age_days": age_days,
            "recently_registered": age_days < _RECENTLY_REGISTERED_THRESHOLD_DAYS,
            "name_servers": name_servers,
            "provider": "simulated",
        }
