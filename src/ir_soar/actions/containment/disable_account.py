"""
Containment action: disable a user account.

High-risk, human-approval-required by default. Delegates to whichever
`IdentityConnector` is configured (`config.connectors.identity.type`) —
`simulated` by default.
"""

from __future__ import annotations

from typing import Any

from ir_soar.actions.base import BaseAction, register_action
from ir_soar.config.schema import AppConfig
from ir_soar.connectors import get_identity_connector
from ir_soar.utils.validation import ValidationError, ensure_no_shell_metacharacters, validate_username


@register_action("disable_account")
class DisableAccountAction(BaseAction):
    description = "Disable a user account to stop further use of compromised credentials."
    default_risk = "high"
    category = "containment"

    def validate_inputs(self, inputs: dict[str, Any]) -> dict[str, Any]:
        username = inputs.get("username")
        if not username:
            raise ValidationError("disable_account requires a non-empty 'username' input")
        normalized = validate_username(username)
        ensure_no_shell_metacharacters(normalized)
        return {"username": normalized}

    def dry_run_preview(self, inputs: dict[str, Any]) -> dict[str, Any]:
        username = inputs["username"]
        return {
            "would_execute": self.action_name,
            "username": username,
            "effect": f"Account '{username}' would be disabled. No real action taken.",
        }

    def execute(self, inputs: dict[str, Any], config: AppConfig) -> dict[str, Any]:
        connector = get_identity_connector(config)
        return connector.disable_account(inputs["username"])
