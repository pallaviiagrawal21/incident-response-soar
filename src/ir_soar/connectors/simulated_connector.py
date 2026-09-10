"""
Simulated connectors — the safe, side-effect-free default for every
containment action, used whenever `config.connectors.<x>.type: simulated`
(the default in every provided environment overlay).

These never touch a real system. They exist so the full engine — including
containment actions, playbook branching, and the audit trail — can be
exercised end to end in a lab with zero real infrastructure. Real
connectors (EDR/IAM/firewall) implement the same interfaces from
`base_connector.py` and are wired in purely through config.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from ir_soar.connectors.base_connector import FirewallConnector, IdentityConnector, IsolationConnector

logger = logging.getLogger("ir_soar.connectors.simulated")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class SimulatedIsolationConnector(IsolationConnector):
    def isolate_host(self, hostname: str) -> dict[str, Any]:
        logger.info("[SIMULATED] would isolate host '%s'", hostname)
        return {
            "hostname": hostname,
            "isolated": True,
            "connector": "simulated",
            "timestamp": _now(),
        }

    def collect_forensics(self, hostname: str) -> dict[str, Any]:
        logger.info("[SIMULATED] would collect forensic artifacts from '%s'", hostname)
        return {
            "hostname": hostname,
            "artifacts_collected": [
                "process_list.json",
                "network_connections.json",
                "file_metadata.json",
            ],
            "connector": "simulated",
            "timestamp": _now(),
        }


class SimulatedIdentityConnector(IdentityConnector):
    def disable_account(self, username: str) -> dict[str, Any]:
        logger.info("[SIMULATED] would disable account '%s'", username)
        return {
            "username": username,
            "disabled": True,
            "connector": "simulated",
            "timestamp": _now(),
        }


class SimulatedFirewallConnector(FirewallConnector):
    def block(self, target: str) -> dict[str, Any]:
        logger.info("[SIMULATED] would block '%s' at the perimeter", target)
        return {
            "target": target,
            "blocked": True,
            "connector": "simulated",
            "timestamp": _now(),
        }
