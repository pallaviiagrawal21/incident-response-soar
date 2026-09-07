"""
Strict input validation helpers for ir_soar.

These exist to guarantee that malformed or malicious input never reaches an
action's execute() method. Enrichment and containment actions frequently
accept attacker-influenced strings (a phishing sender's domain, a hostname
pulled from a log line, a username parsed from an alert) as input — every
such value is validated BEFORE it is used, never "best effort" parsed.

Convention used throughout this module:
    validate_*(value) -> str   returns a normalized value, raises
                                ValidationError on anything invalid
    is_valid_*(value) -> bool  convenience boolean wrapper, never raises
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

_HOSTNAME_LABEL_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")
_USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_SHELL_METACHARACTERS = set(';&|`$()<>\\"\'\n\r')

_HASH_LENGTHS: dict[int, str] = {32: "md5", 40: "sha1", 64: "sha256"}


class ValidationError(ValueError):
    """Raised when an input value fails strict validation."""


def validate_ip(value: str) -> str:
    """Validate an IPv4 or IPv6 address string; returns it normalized."""
    if not isinstance(value, str) or not value.strip():
        raise ValidationError("IP address must be a non-empty string")
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError as exc:
        raise ValidationError(f"'{value}' is not a valid IP address") from exc


def is_valid_ip(value: str) -> bool:
    try:
        validate_ip(value)
        return True
    except ValidationError:
        return False


def validate_domain(value: str) -> str:
    """Validate a DNS domain name (e.g. 'evil-example.com'). Requires >= 2 labels."""
    if not isinstance(value, str) or not value.strip():
        raise ValidationError("Domain must be a non-empty string")
    candidate = value.strip().rstrip(".").lower()
    if len(candidate) > 253:
        raise ValidationError(f"Domain '{value}' exceeds maximum length of 253 characters")
    labels = candidate.split(".")
    if len(labels) < 2:
        raise ValidationError(f"'{value}' is not a valid domain (must have at least two labels)")
    for label in labels:
        if not _HOSTNAME_LABEL_RE.match(label):
            raise ValidationError(f"'{value}' contains an invalid label: '{label}'")
    return candidate


def is_valid_domain(value: str) -> bool:
    try:
        validate_domain(value)
        return True
    except ValidationError:
        return False


def validate_hostname(value: str) -> str:
    """Validate a single- or multi-label hostname (more permissive than a public domain)."""
    if not isinstance(value, str) or not value.strip():
        raise ValidationError("Hostname must be a non-empty string")
    candidate = value.strip().rstrip(".")
    if len(candidate) > 253:
        raise ValidationError(f"Hostname '{value}' exceeds maximum length of 253 characters")
    for label in candidate.split("."):
        if not _HOSTNAME_LABEL_RE.match(label):
            raise ValidationError(f"'{value}' contains an invalid hostname label: '{label}'")
    return candidate


def is_valid_hostname(value: str) -> bool:
    try:
        validate_hostname(value)
        return True
    except ValidationError:
        return False


def validate_hash(value: str, expected_algo: str | None = None) -> str:
    """Validate a file hash string (md5/sha1/sha256), returning it lowercased."""
    if not isinstance(value, str) or not value.strip():
        raise ValidationError("Hash must be a non-empty string")
    candidate = value.strip().lower()
    if not re.fullmatch(r"[a-f0-9]+", candidate):
        raise ValidationError(f"'{value}' is not valid hexadecimal")
    algo = _HASH_LENGTHS.get(len(candidate))
    if algo is None:
        raise ValidationError(
            f"'{value}' has length {len(candidate)}; expected 32 (md5), 40 (sha1), "
            "or 64 (sha256) hex characters"
        )
    if expected_algo and algo != expected_algo.lower():
        raise ValidationError(f"'{value}' looks like {algo}, expected {expected_algo}")
    return candidate


def is_valid_hash(value: str, expected_algo: str | None = None) -> bool:
    try:
        validate_hash(value, expected_algo)
        return True
    except ValidationError:
        return False


def validate_username(value: str) -> str:
    """Validate an account/username identifier."""
    if not isinstance(value, str) or not value.strip():
        raise ValidationError("Username must be a non-empty string")
    candidate = value.strip()
    if not _USERNAME_RE.match(candidate):
        raise ValidationError(
            f"'{value}' is not a valid username (alphanumeric, '.', '_', '-' only, max 64 chars, "
            "must not start with a separator)"
        )
    return candidate


def is_valid_username(value: str) -> bool:
    try:
        validate_username(value)
        return True
    except ValidationError:
        return False


def ensure_no_shell_metacharacters(value: str) -> str:
    """
    Defense-in-depth check for any value that might later be passed into a
    real connector's shell command or API call. Rejects characters commonly
    used for command/argument injection.

    This does NOT replace using subprocess argument lists (never
    `shell=True`) in real connector implementations — it is a second layer,
    never the only layer, of protection against injection.
    """
    if not isinstance(value, str):
        raise ValidationError("Value must be a string")
    found = _SHELL_METACHARACTERS.intersection(value)
    if found:
        raise ValidationError(f"Value contains disallowed characters {sorted(found)!r}: '{value}'")
    return value


def require_fields(inputs: dict[str, Any], required: list[str]) -> None:
    """Raise ValidationError listing every missing required input key at once."""
    missing = [key for key in required if key not in inputs or inputs[key] in (None, "")]
    if missing:
        raise ValidationError(f"Missing required input field(s): {', '.join(missing)}")
