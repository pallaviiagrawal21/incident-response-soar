# Extending ir_soar

Three things you'll likely want to add over time, each requiring **zero changes to the engine**.

---

## 1. Add a new playbook

A playbook is just two files sharing an `id`.

**`config/playbooks/insider_threat.yaml`** (machine-readable):

```yaml
id: insider_threat
name: "Insider Threat: Anomalous Data Access"
version: "1.0"
description: "..."

mitre_attack:
  - tactic: "Collection"
    technique: "T1213"
    technique_name: "Data from Information Repositories"

phases:
  - name: preparation
    steps: []
  - name: identification
    steps:
      - id: correlate_access_logs
        action_type: log_correlation
        inputs:
          user: "{{ incident.affected_user }}"
          window_minutes: 120
        requires_approval: false
        risk: low
  - name: containment
    steps:
      - id: disable_account
        action_type: disable_account
        inputs:
          username: "{{ incident.affected_user }}"
        condition: "steps.correlate_access_logs.result.suspicious == true"
        requires_approval: true
        risk: high
  - name: eradication
    steps: []
  - name: recovery
    steps: []
  - name: lessons_learned
    steps: []
```

**`playbooks/insider_threat.md`** — follow the structure of the two existing playbooks (Overview, Roles, Preparation, Identification with a decision tree, Containment, Eradication, Recovery, Lessons Learned, Communication Plan, Evidence Handling, MITRE mapping, Automation Cross-Reference table matching the step `id`s above).

Then:

```bash
ir-soar validate-playbook insider_threat   # schema + condition-reference check
ir-soar run --playbook insider_threat --dry-run --incident-file incident.json
```

The `id` field inside the YAML **must match the filename** (without `.yaml`) — the loader enforces this so a copy-pasted playbook can't silently declare the wrong id.

---

## 2. Add a new action

Subclass `BaseAction`, implement two methods, decorate it. Example — a new enrichment action checking a URL sandbox verdict:

```python
# src/ir_soar/actions/enrichment/url_sandbox.py
from __future__ import annotations
from typing import Any

from ir_soar.actions.base import BaseAction, register_action
from ir_soar.config.schema import AppConfig
from ir_soar.utils.validation import ValidationError


@register_action("url_sandbox")
class UrlSandboxAction(BaseAction):
    description = "Detonate a URL in a sandbox and return the verdict."
    default_risk = "low"
    # category defaults to "enrichment" (set on BaseAction) — override to
    # "containment" only for state-changing actions.

    def validate_inputs(self, inputs: dict[str, Any]) -> dict[str, Any]:
        url = inputs.get("url")
        if not url or not url.startswith(("http://", "https://")):
            raise ValidationError("url_sandbox requires a non-empty http(s) 'url' input")
        return {"url": url}

    def execute(self, inputs: dict[str, Any], config: AppConfig) -> dict[str, Any]:
        # real implementation would call a sandbox API here
        return {"url": inputs["url"], "verdict": "malicious", "provider": "simulated"}
```

Then register it by importing the module in `actions/enrichment/__init__.py` (add it to the import list and `__all__`) — that import is what actually populates `ACTION_REGISTRY`.

```bash
ir-soar list-actions   # your new action now appears
```

Reference it from any playbook step with `action_type: url_sandbox`.

**Rules every action should follow** (enforced by `BaseAction.run()`, but worth restating):
- `validate_inputs()` must raise `ValidationError` (from `ir_soar.utils.validation`) on anything invalid — never silently coerce a bad value into something plausible.
- `execute()` should raise on failure, not return an ambiguous "maybe it worked" result.
- Never call a real API/system directly from an action — delegate to a connector (see below) if the action needs to.

---

## 3. Add a real connector

Containment actions never talk to real infrastructure directly; they resolve a connector from `ir_soar.connectors` based on config. Adding a real EDR isolation connector:

```python
# src/ir_soar/connectors/crowdstrike_connector.py
from __future__ import annotations
import os
from typing import Any

from ir_soar.connectors.base_connector import ConnectorError, IsolationConnector


class CrowdStrikeIsolationConnector(IsolationConnector):
    def __init__(self, endpoint: str, api_key: str) -> None:
        self._endpoint = endpoint
        self._api_key = api_key

    def isolate_host(self, hostname: str) -> dict[str, Any]:
        # real HTTP call here, with its OWN request-level timeout as
        # defense in depth on top of the action's timeout
        ...

    def collect_forensics(self, hostname: str) -> dict[str, Any]:
        ...
```

Wire it into the resolver in `connectors/__init__.py`:

```python
def get_isolation_connector(config: AppConfig) -> IsolationConnector:
    connector_type = config.connectors.isolation.type
    if connector_type == "simulated":
        return SimulatedIsolationConnector()
    if connector_type == "edr_api":
        api_key = os.environ.get(config.connectors.isolation.api_key_env, "")
        if not api_key:
            raise ConnectorError(f"{config.connectors.isolation.api_key_env} is not set")
        return CrowdStrikeIsolationConnector(config.connectors.isolation.endpoint, api_key)
    raise NotImplementedError(...)
```

Then in your **production-like** overlay only (never in `config.lab.yaml`):

```yaml
connectors:
  isolation:
    type: edr_api
    endpoint: "${EDR_API_ENDPOINT:-}"
    api_key_env: EDR_API_KEY
```

And set the real values in your `.env` (never in a YAML file — see `connectors/README.md` for the full checklist every real connector must follow: no secrets in code, never `shell=True`, set your own request timeout, never silently fake success).

---

## What you should never need to touch

- `engine/executor.py`, `engine/decision.py`, `engine/playbook_loader.py`
- `actions/base.py`
- `cli.py`

If adding something requires editing any of these, that's a signal the change is a genuine engine feature (new condition grammar, new CLI command) rather than routine extension — worth a second look before proceeding.
