"""
Connector resolution: maps `config.connectors.<x>.type` to a concrete
connector instance. This is the ONLY place in the codebase that knows how
to go from a config string to an object — containment actions never
construct a connector themselves, they always call one of these resolvers.

Adding a real connector later means:
  1. Implement the relevant interface from `base_connector.py`.
  2. Add an `elif connector_type == "your_type": return YourConnector(config)`
     branch below.
  3. Set `type: your_type` in config for the relevant environment.
No action code changes required. See `connectors/README.md`.
"""

from __future__ import annotations

from ir_soar.config.schema import AppConfig
from ir_soar.connectors.base_connector import (
    ConnectorError,
    FirewallConnector,
    IdentityConnector,
    IsolationConnector,
)
from ir_soar.connectors.simulated_connector import (
    SimulatedFirewallConnector,
    SimulatedIdentityConnector,
    SimulatedIsolationConnector,
)

__all__ = [
    "ConnectorError",
    "FirewallConnector",
    "IdentityConnector",
    "IsolationConnector",
    "get_firewall_connector",
    "get_identity_connector",
    "get_isolation_connector",
]


def get_isolation_connector(config: AppConfig) -> IsolationConnector:
    connector_type = config.connectors.isolation.type
    if connector_type == "simulated":
        return SimulatedIsolationConnector()
    raise NotImplementedError(
        f"Isolation connector type '{connector_type}' is not yet implemented. "
        "See connectors/README.md and docs/extending.md for how to add a real connector."
    )


def get_identity_connector(config: AppConfig) -> IdentityConnector:
    connector_type = config.connectors.identity.type
    if connector_type == "simulated":
        return SimulatedIdentityConnector()
    raise NotImplementedError(
        f"Identity connector type '{connector_type}' is not yet implemented. "
        "See connectors/README.md and docs/extending.md for how to add a real connector."
    )


def get_firewall_connector(config: AppConfig) -> FirewallConnector:
    connector_type = config.connectors.firewall.type
    if connector_type == "simulated":
        return SimulatedFirewallConnector()
    raise NotImplementedError(
        f"Firewall connector type '{connector_type}' is not yet implemented. "
        "See connectors/README.md and docs/extending.md for how to add a real connector."
    )
