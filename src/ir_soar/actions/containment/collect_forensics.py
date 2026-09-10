"""
Containment/eradication-support action: collect basic forensic artifacts
from a host before rebuild or remediation.

Medium-risk, human-approval-required by default (collection itself is
lower-risk than isolation/account-disable, but still touches a
potentially-compromised host, so it stays gated). Delegates to whichever
`IsolationConnector` is configured — the same connector that performs
isolation, since forensic collection is typically EDR-backed too.
"""

from __future__ import annotations

from typing import Any

from ir_soar.actions.base import BaseAction, register_action
from ir_soar.config.schema import AppConfig
from ir_soar.connectors import get_isolation_connector
from ir_soar.utils.validation import ValidationError, ensure_no_shell_metacharacters, validate_hostname


@register_action("collect_forensics")
class CollectForensicsAction(BaseAction):
    description = "Collect basic forensic artifacts from a host (process list, network connections, file metadata)."
    default_risk = "medium"
    category = "containment"

    def validate_inputs(self, inputs: dict[str, Any]) -> dict[str, Any]:
        hostname = inputs.get("hostname")
        if not hostname:
            raise ValidationError("collect_forensics requires a non-empty 'hostname' input")
        normalized = validate_hostname(hostname)
        ensure_no_shell_metacharacters(normalized)
        return {"hostname": normalized}

    def dry_run_preview(self, inputs: dict[str, Any]) -> dict[str, Any]:
        hostname = inputs["hostname"]
        return {
            "would_execute": self.action_name,
            "hostname": hostname,
            "effect": f"Forensic artifacts would be collected from '{hostname}'. No real action taken.",
        }

    def execute(self, inputs: dict[str, Any], config: AppConfig) -> dict[str, Any]:
        connector = get_isolation_connector(config)
        return connector.collect_forensics(inputs["hostname"])
