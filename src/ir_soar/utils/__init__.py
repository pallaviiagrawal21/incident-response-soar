"""
Cross-cutting utilities used by every layer of ir_soar: structured logging
(including the hash-chained audit trail), strict input validation, and the
safety guardrails (full-auto acknowledgement, human approval prompts, the
hard max-actions-per-run ceiling, and secret redaction).

Nothing in engine/, actions/, or cli.py should re-implement logic that
belongs here — these are the single implementations relied on everywhere.
"""

from __future__ import annotations

from ir_soar.utils.logging import AuditLogger, setup_logging
from ir_soar.utils.safety import (
    RunGuard,
    SafetyError,
    enforce_full_auto_safety,
    is_dangerous_action,
    prompt_confirmation,
    redact_sensitive,
    risk_at_or_above,
)
from ir_soar.utils.validation import (
    ValidationError,
    ensure_no_shell_metacharacters,
    is_valid_domain,
    is_valid_hash,
    is_valid_hostname,
    is_valid_ip,
    is_valid_username,
    validate_domain,
    validate_hash,
    validate_hostname,
    validate_ip,
    validate_username,
)

__all__ = [
    "AuditLogger",
    "setup_logging",
    "RunGuard",
    "SafetyError",
    "enforce_full_auto_safety",
    "is_dangerous_action",
    "prompt_confirmation",
    "redact_sensitive",
    "risk_at_or_above",
    "ValidationError",
    "ensure_no_shell_metacharacters",
    "is_valid_domain",
    "is_valid_hash",
    "is_valid_hostname",
    "is_valid_ip",
    "is_valid_username",
    "validate_domain",
    "validate_hash",
    "validate_hostname",
    "validate_ip",
    "validate_username",
]
