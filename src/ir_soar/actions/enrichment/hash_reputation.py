"""
Enrichment action: file hash reputation lookup.

Abstracted behind `config.enrichment_providers.hash_reputation.type` so a
real provider (VirusTotal, etc.) can be plugged in later without changing
this action's interface or any playbook that references it — see
docs/extending.md.
"""

from __future__ import annotations

from typing import Any

from ir_soar.actions.base import BaseAction, register_action
from ir_soar.actions.enrichment._simulation import simulated_verdict
from ir_soar.config.schema import AppConfig
from ir_soar.utils.validation import ValidationError, validate_hash

_ALGO_BY_LENGTH = {32: "md5", 40: "sha1", 64: "sha256"}


@register_action("hash_reputation")
class HashReputationAction(BaseAction):
    description = "Look up reputation for a file hash (md5/sha1/sha256)."
    default_risk = "low"

    def validate_inputs(self, inputs: dict[str, Any]) -> dict[str, Any]:
        raw_hash = inputs.get("hash")
        if not raw_hash:
            raise ValidationError("hash_reputation requires a non-empty 'hash' input")
        return {"hash": validate_hash(raw_hash)}

    def dry_run_preview(self, inputs: dict[str, Any]) -> dict[str, Any]:
        return {"would_execute": self.action_name, "hash": inputs["hash"]}

    def execute(self, inputs: dict[str, Any], config: AppConfig) -> dict[str, Any]:
        provider = config.enrichment_providers.hash_reputation
        if provider.type != "simulated":
            raise NotImplementedError(
                f"Enrichment provider type '{provider.type}' is not yet implemented. "
                "See docs/extending.md for how to add a real provider connector."
            )
        verdict, score = simulated_verdict(inputs["hash"])
        return {
            "hash": inputs["hash"],
            "algo": _ALGO_BY_LENGTH[len(inputs["hash"])],
            "verdict": verdict,
            "score": score,
            "provider": "simulated",
        }
