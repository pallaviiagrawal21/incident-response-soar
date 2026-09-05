"""
Pydantic schema for machine-readable playbooks (config/playbooks/*.yaml).

This is the CONTRACT between human-authored playbook files and the engine:
the engine (built in a later step) only ever consumes a validated `Playbook`
instance, never raw YAML. Adding a new playbook means writing a new YAML
file that satisfies this schema — no engine code changes required, which is
the core "add playbooks without rewriting the engine" requirement.

Notes on fields that look like they should be richer:
- `inputs` values are plain strings/numbers/bools at this layer, including
  unrendered Jinja-style placeholders like "{{ incident.sender_domain }}".
  Template rendering happens at execution time (once an incident context
  exists), not at load time — see engine/executor.py in a later build step.
- `condition` is a plain string expression (e.g.
  "steps.correlate_auth_logs.result.suspicious == true"), evaluated by the
  executor's decision logic at run time, not parsed into an AST here. The
  loader only performs a light, best-effort consistency check that any
  `steps.<id>.` reference points at an id that actually exists earlier in
  the playbook — see `Playbook.validate_step_references`.
"""

from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

RiskLevel = Literal["low", "medium", "high"]
OnSuccess = Literal["continue", "continue_with_warning", "abort_run"]
OnFailure = Literal["continue", "continue_with_warning", "abort_run"]

# Standard MITRE ATT&CK Enterprise tactic names (as of the matrix this
# project targets). Kept as a closed set so a typo'd tactic name fails
# validation instead of silently producing a wrong mapping.
MitreTactic = Literal[
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]

_TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
_ID_RE = re.compile(r"^[a-z][a-z0-9_]*$")


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class MitreMapping(_StrictModel):
    """A single MITRE ATT&CK tactic/technique mapping for this playbook."""

    tactic: MitreTactic
    technique: str = Field(description="e.g. 'T1566.002'")
    technique_name: str | None = Field(default=None, description="Human-readable technique name")

    @field_validator("technique")
    @classmethod
    def _validate_technique_id(cls, value: str) -> str:
        if not _TECHNIQUE_ID_RE.match(value):
            raise ValueError(f"'{value}' is not a valid MITRE technique ID (expected e.g. 'T1566' or 'T1566.002')")
        return value


class Step(_StrictModel):
    """A single automatable (or explicitly manual) step within a phase."""

    id: str
    action_type: str = Field(description="Key into the action registry, e.g. 'isolate_host'")
    inputs: dict[str, Any] = Field(default_factory=dict)
    requires_approval: bool = True
    risk: RiskLevel = "medium"
    condition: str | None = Field(
        default=None,
        description="Optional guard expression referencing prior steps, e.g. "
        "'steps.correlate_auth_logs.result.suspicious == true'. Step runs only if true.",
    )
    on_success: OnSuccess = "continue"
    on_failure: OnFailure = "continue_with_warning"
    timeout_seconds: float | None = Field(default=None, gt=0, le=600)
    retries: int | None = Field(default=None, ge=0, le=10)
    description: str | None = None

    @field_validator("id")
    @classmethod
    def _validate_id(cls, value: str) -> str:
        if not _ID_RE.match(value):
            raise ValueError(f"Step id '{value}' must be lowercase snake_case (e.g. 'isolate_affected_host')")
        return value


class Phase(_StrictModel):
    """One phase of the IR lifecycle (identification, containment, etc.)."""

    name: Literal[
        "preparation",
        "identification",
        "containment",
        "eradication",
        "recovery",
        "lessons_learned",
    ]
    steps: list[Step] = Field(default_factory=list)

    @field_validator("steps")
    @classmethod
    def _validate_unique_step_ids_in_phase(cls, steps: list[Step]) -> list[Step]:
        seen = set()
        for step in steps:
            if step.id in seen:
                raise ValueError(f"Duplicate step id '{step.id}' within phase")
            seen.add(step.id)
        return steps


class Playbook(_StrictModel):
    """The full machine-readable playbook — the engine's unit of execution."""

    id: str
    name: str
    version: str
    description: str = ""
    mitre_attack: list[MitreMapping] = Field(default_factory=list)
    phases: list[Phase] = Field(default_factory=list)

    @field_validator("id")
    @classmethod
    def _validate_id(cls, value: str) -> str:
        if not _ID_RE.match(value):
            raise ValueError(f"Playbook id '{value}' must be lowercase snake_case")
        return value

    @model_validator(mode="after")
    def _validate_globally_unique_step_ids(self) -> "Playbook":
        seen: dict[str, str] = {}
        for phase in self.phases:
            for step in phase.steps:
                if step.id in seen:
                    raise ValueError(
                        f"Duplicate step id '{step.id}' across phases "
                        f"('{seen[step.id]}' and '{phase.name}') — step ids must be "
                        "globally unique within a playbook so conditions can reference them unambiguously"
                    )
                seen[step.id] = phase.name
        return self

    def all_steps(self) -> list[Step]:
        """Flat list of every step across every phase, in execution order."""
        return [step for phase in self.phases for step in phase.steps]

    def get_step(self, step_id: str) -> Step | None:
        for step in self.all_steps():
            if step.id == step_id:
                return step
        return None

    def validate_step_references(self) -> list[str]:
        """
        Best-effort consistency check: every `steps.<id>.` reference inside a
        `condition` expression should point at a step id that appears
        EARLIER in the playbook (conditions can only look backward in a
        linear execution model — no forward references, no cycles).

        Returns a list of human-readable warning strings; does not raise,
        since condition expressions are free-form and this check is a
        convenience, not a full expression parser.
        """
        warnings: list[str] = []
        seen_ids: set[str] = set()
        reference_re = re.compile(r"steps\.([a-z][a-z0-9_]*)\.")
        for step in self.all_steps():
            if step.condition:
                for referenced_id in reference_re.findall(step.condition):
                    if referenced_id not in seen_ids:
                        warnings.append(
                            f"Step '{step.id}' condition references 'steps.{referenced_id}.' "
                            "which is not an earlier step id in this playbook (typo, or forward reference?)"
                        )
            seen_ids.add(step.id)
        return warnings
