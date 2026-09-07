"""
Pydantic configuration schema for ir_soar.

This module is the SINGLE SOURCE OF TRUTH for every configurable setting in
the system. Nothing outside of this schema (and its defaults) should be
hardcoded elsewhere in the codebase — actions, the executor, and the CLI all
read their behavior from an `AppConfig` instance passed in at runtime.

Design notes:
- All enums are closed (`Literal[...]`) so invalid values fail fast at load
  time, not deep inside a running incident response.
- No field ever holds a secret value. Credential fields are always
  `*_api_key_env: str`, i.e. the NAME of an environment variable, resolved
  lazily by connectors at call time — never eagerly loaded into this model.
- Every field has a safe default so `AppConfig()` alone (no files, no env)
  still produces a usable, dry-run, simulated-only configuration.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Environment = Literal["lab", "home", "production-like"]
RunMode = Literal["dry-run", "interactive", "live"]
RiskLevel = Literal["low", "medium", "high"]
LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR"]
LogFormat = Literal["json", "text"]
ConnectorType = Literal["simulated", "edr_api", "okta_api", "firewall_api"]
EnrichmentProviderType = Literal["simulated", "abuseipdb", "virustotal", "whois_api"]


class _StrictModel(BaseModel):
    """Base model: reject unknown fields so config typos fail loudly."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class LoggingConfig(_StrictModel):
    level: LogLevel = "INFO"
    format: LogFormat = "json"
    log_dir: str = "./logs"
    audit_log_path: str = "./logs/audit.jsonl"


class ExecutionConfig(_StrictModel):
    default_timeout_seconds: float = Field(default=30, gt=0, le=600)
    max_retries: int = Field(default=2, ge=0, le=10)
    retry_backoff_seconds: float = Field(default=5, ge=0, le=120)
    # Hard ceiling on total actions executed in a single run. This is one of
    # the architectural guarantees against runaway execution — combined with
    # bounded retries and per-action timeouts, no code path in the engine
    # can loop indefinitely.
    max_actions_per_run: int = Field(default=100, ge=1, le=10_000)


class ApprovalConfig(_StrictModel):
    require_for_containment: bool = True
    require_for_enrichment: bool = False
    auto_approve_risk_below: RiskLevel = "low"


class ConnectorConfig(_StrictModel):
    type: ConnectorType = "simulated"
    endpoint: str = ""
    api_key_env: str = ""


class ConnectorsConfig(_StrictModel):
    isolation: ConnectorConfig = Field(default_factory=lambda: ConnectorConfig(api_key_env="EDR_API_KEY"))
    identity: ConnectorConfig = Field(
        default_factory=lambda: ConnectorConfig(api_key_env="IDENTITY_API_KEY")
    )
    firewall: ConnectorConfig = Field(
        default_factory=lambda: ConnectorConfig(api_key_env="FIREWALL_API_KEY")
    )


class EnrichmentProviderConfig(_StrictModel):
    type: EnrichmentProviderType = "simulated"
    api_key_env: str = ""


class EnrichmentProvidersConfig(_StrictModel):
    ip_reputation: EnrichmentProviderConfig = Field(
        default_factory=lambda: EnrichmentProviderConfig(api_key_env="ABUSEIPDB_API_KEY")
    )
    hash_reputation: EnrichmentProviderConfig = Field(
        default_factory=lambda: EnrichmentProviderConfig(api_key_env="VT_API_KEY")
    )
    whois_dns: EnrichmentProviderConfig = Field(
        default_factory=lambda: EnrichmentProviderConfig(api_key_env="WHOIS_API_KEY")
    )


class PathsConfig(_StrictModel):
    playbooks_dir: str = "./config/playbooks"
    evidence_dir: str = "./evidence"


class SafetyConfig(_StrictModel):
    full_auto_requires_ack_env: bool = True
    dangerous_action_risk_floor: RiskLevel = "medium"


class AppConfig(_StrictModel):
    """The fully merged, validated runtime configuration for ir_soar."""

    environment: Environment = "lab"
    mode: RunMode = "dry-run"

    # full_auto is deliberately NOT part of `mode`. It is an explicit,
    # separate opt-in (set only via the --full-auto CLI flag, never via
    # config.yaml) that removes the interactive approval prompt for
    # approved-risk steps. It does NOT bypass validation, timeouts, retry
    # limits, or audit logging — see utils/safety.py in a later build step.
    full_auto: bool = False

    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    execution: ExecutionConfig = Field(default_factory=ExecutionConfig)
    approval: ApprovalConfig = Field(default_factory=ApprovalConfig)
    connectors: ConnectorsConfig = Field(default_factory=ConnectorsConfig)
    enrichment_providers: EnrichmentProvidersConfig = Field(default_factory=EnrichmentProvidersConfig)
    paths: PathsConfig = Field(default_factory=PathsConfig)
    safety: SafetyConfig = Field(default_factory=SafetyConfig)

    @property
    def is_live(self) -> bool:
        """True only when actions may cause real side effects."""
        return self.mode == "live"

    @property
    def skips_interactive_approval(self) -> bool:
        """
        True only when the operator explicitly opted into `--full-auto`.
        This never changes validation, timeouts, retry limits, or audit
        logging — it only removes the interactive confirmation prompt for
        steps that would otherwise block waiting on a human. See
        utils/safety.py (build step 2) for the enforcement of the loud
        warning banner and the non-interactive acknowledgement gate.
        """
        return self.full_auto
