# Connectors

This directory holds the boundary between ir_soar's containment actions and
whatever actually performs a real-world effect (an EDR product, an IAM/IdP,
a firewall/proxy).

## What exists today

- `base_connector.py` — abstract interfaces: `IsolationConnector`,
  `IdentityConnector`, `FirewallConnector`.
- `simulated_connector.py` — safe, side-effect-free implementations of all
  three interfaces. This is the default (`type: simulated`) in every
  provided environment overlay.
- `__init__.py` — resolver functions (`get_isolation_connector`,
  `get_identity_connector`, `get_firewall_connector`) that read
  `config.connectors.<x>.type` and return the right connector instance.

## Adding a real connector

1. **Implement the interface.** For example, a real EDR isolation
   connector:

   ```python
   # connectors/crowdstrike_connector.py
   from ir_soar.connectors.base_connector import IsolationConnector, ConnectorError

   class CrowdStrikeIsolationConnector(IsolationConnector):
       def __init__(self, endpoint: str, api_key: str) -> None:
           self._endpoint = endpoint
           self._api_key = api_key

       def isolate_host(self, hostname: str) -> dict:
           # real API call here, using a request-level timeout of its own
           # as defense in depth on top of the action's timeout
           ...

       def collect_forensics(self, hostname: str) -> dict:
           ...
   ```

2. **Wire it into the resolver** in `connectors/__init__.py`:

   ```python
   def get_isolation_connector(config: AppConfig) -> IsolationConnector:
       connector_type = config.connectors.isolation.type
       if connector_type == "simulated":
           return SimulatedIsolationConnector()
       if connector_type == "edr_api":
           import os
           api_key = os.environ.get(config.connectors.isolation.api_key_env, "")
           if not api_key:
               raise ConnectorError(
                   f"{config.connectors.isolation.api_key_env} is not set in the environment"
               )
           return CrowdStrikeIsolationConnector(config.connectors.isolation.endpoint, api_key)
       raise NotImplementedError(...)
   ```

3. **Set `type: edr_api`** (or whatever you named it) in the relevant
   environment overlay (`config/config.production-like.yaml`, typically —
   never in `config.lab.yaml`), and set the endpoint/API key env var in
   your real `.env`.

## Rules every real connector must follow

- **No secrets in code.** Read credentials only from the environment
  variable named in `config.connectors.<x>.api_key_env` — never hardcode a
  key, never read it from anywhere else.
- **Never `shell=True`.** If a connector shells out at all, use an argument
  list (`subprocess.run([...], shell=False)`), and still validate every
  input with `ir_soar.utils.validation` before it reaches the command line.
- **Set your own timeout.** The action layer bounds a single attempt with
  `config.execution.default_timeout_seconds`, but a real HTTP/API call
  should set its own request-level timeout too, as defense in depth.
- **Raise `ConnectorError` (or let the real exception propagate)** on
  failure — never silently return a "success" result for something that
  didn't actually happen. `BaseAction.run()` turns any exception into a
  clean `status="failure"` result automatically.
