"""
Containment action: network-isolate a host.

High-risk, human-approval-required by default (see risk/requires_approval
in config/playbooks/*.yaml). Delegates the actual isolation call to
whichever `IsolationConnector` is configured
(`config.connectors.isolation.type`) — `simulated` by default.
"""

from __future__ import annotations

from typing import Any

from ir_soar.actions.base import BaseAction, register_action
from ir_soar.config.schema import AppConfig
from ir_soar.connectors import get_isolation_connector
from ir_soar.utils.validation import ValidationError, ensure_no_shell_metacharacters, validate_hostname


@register_action("isolate_host")
class IsolateHostAction(BaseAction):
    description = "Network-isolate a host to stop further attacker activity or lateral movement."
    default_risk = "high"

    def validate_inputs(self, inputs: dict[str, Any]) -> dict[str, Any]:
        hostname = inputs.get("hostname")
        if not hostname:
            raise ValidationError("isolate_host requires a non-empty 'hostname' input")
        normalized = validate_hostname(hostname)
        ensure_no_shell_metacharacters(normalized)
        return {"hostname": normalized}

    def dry_run_preview(self, inputs: dict[str, Any]) -> dict[str, Any]:
        hostname = inputs["hostname"]
        return {
            "would_execute": self.action_name,
            "hostname": hostname,
            "effect": f"Host '{hostname}' would be network-isolated. No real action taken.",
        }

    def execute(self, inputs: dict[str, Any], config: AppConfig) -> dict[str, Any]:
        connector = get_isolation_connector(config)
        return connector.isolate_host(inputs["hostname"])
