"""
Abstract connector interfaces — the extension point for real backend
integrations (EDR, IAM, firewall/network).

Containment actions never talk to a real system directly. Instead, each
action resolves a connector instance via the resolver functions in
`ir_soar.connectors` (based on `config.connectors.<x>.type`) and calls its
domain-specific interface methods.

Adding a real integration later means implementing one of these interfaces
(e.g. `CrowdStrikeIsolationConnector(IsolationConnector)`) and wiring its
`type:` name into config — no action code changes required. See
`connectors/README.md` and `docs/extending.md`.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class ConnectorError(RuntimeError):
    """Raised when a connector cannot complete a requested operation."""


class IsolationConnector(ABC):
    """Endpoint isolation and forensic collection (typically EDR-backed)."""

    @abstractmethod
    def isolate_host(self, hostname: str) -> dict[str, Any]:
        """Network-isolate `hostname`. Returns a result dict on success."""
        raise NotImplementedError

    @abstractmethod
    def collect_forensics(self, hostname: str) -> dict[str, Any]:
        """Collect basic forensic artifacts from `hostname`."""
        raise NotImplementedError


class IdentityConnector(ABC):
    """Account lifecycle actions (typically IAM/IdP-backed)."""

    @abstractmethod
    def disable_account(self, username: str) -> dict[str, Any]:
        """Disable `username`'s account."""
        raise NotImplementedError


class FirewallConnector(ABC):
    """Network-level blocking (typically firewall/proxy-backed)."""

    @abstractmethod
    def block(self, target: str) -> dict[str, Any]:
        """Block `target` (an IP or domain) at the perimeter."""
        raise NotImplementedError
