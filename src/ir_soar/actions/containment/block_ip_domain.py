"""
Containment action: block an IP address or domain at the perimeter.

Medium-risk, human-approval-required by default. Delegates to whichever
`FirewallConnector` is configured (`config.connectors.firewall.type`) —
`simulated` by default.
"""

from __future__ import annotations

from typing import Any

from ir_soar.actions.base import BaseAction, register_action
from ir_soar.config.schema import AppConfig
from ir_soar.connectors import get_firewall_connector
from ir_soar.utils.validation import ValidationError, ensure_no_shell_metacharacters, is_valid_ip, validate_domain, validate_ip


@register_action("block_ip_domain")
class BlockIpDomainAction(BaseAction):
    description = "Block an IP address or domain at the network perimeter."
    default_risk = "medium"
    category = "containment"

    def validate_inputs(self, inputs: dict[str, Any]) -> dict[str, Any]:
        target = inputs.get("target")
        if not target:
            raise ValidationError("block_ip_domain requires a non-empty 'target' input")
        if is_valid_ip(target):
            normalized, target_type = validate_ip(target), "ip"
        else:
            try:
                normalized, target_type = validate_domain(target), "domain"
            except ValidationError as exc:
                raise ValidationError(f"'{target}' is neither a valid IP address nor a valid domain") from exc
        ensure_no_shell_metacharacters(normalized)
        return {"target": normalized, "target_type": target_type}

    def dry_run_preview(self, inputs: dict[str, Any]) -> dict[str, Any]:
        target = inputs["target"]
        return {
            "would_execute": self.action_name,
            "target": target,
            "target_type": inputs["target_type"],
            "effect": f"'{target}' would be blocked at the perimeter. No real action taken.",
        }

    def execute(self, inputs: dict[str, Any], config: AppConfig) -> dict[str, Any]:
        connector = get_firewall_connector(config)
        result = connector.block(inputs["target"])
        result["target_type"] = inputs["target_type"]
        return result
