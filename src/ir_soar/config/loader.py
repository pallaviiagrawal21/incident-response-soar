"""
Layered configuration loader for ir_soar.

Precedence (highest wins), per the approved Phase 1 design:

    CLI arguments  >  environment variables  >  config.yaml (+ env overlay)  >  built-in defaults

Steps performed by `load_config`:
  1. Start from `AppConfig()` built-in defaults (as a plain dict).
  2. Deep-merge the base `config.yaml` on top.
  3. Deep-merge the environment overlay (`config.<environment>.yaml`) on top,
     where `<environment>` comes from the base file, an explicit
     `--env` CLI value, or the `IR_SOAR_ENV` environment variable.
  4. Resolve every `${VAR:-default}` string placeholder against the process
     environment (this is how paths/log-dirs avoid ever being hardcoded).
  5. Apply the small, explicit set of top-level environment variable
     overrides (IR_SOAR_MODE, IR_SOAR_LOG_LEVEL, etc.) — deliberately a
     narrow, documented list rather than "magic" env-to-field guessing.
  6. Apply CLI overrides (a plain dict of dotted keys -> values), which win
     over everything else.
  7. Validate the fully merged dict against `AppConfig` (pydantic) — any
     typo or invalid value fails loudly here, before any playbook runs.

No secrets are ever read into the config object itself; see schema.py for
why credential fields only ever hold an environment variable *name*.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv
from pydantic import ValidationError

from ir_soar.config.schema import AppConfig

# Matches ${VAR} or ${VAR:-default}
_ENV_PLACEHOLDER_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(:-(?P<default>[^}]*))?\}")

# The narrow, explicit set of environment variables that override specific
# top-level config fields. Kept small and documented deliberately — this is
# NOT a generic "IR_SOAR_<PATH>" auto-mapper, to keep behavior predictable.
_ENV_VAR_OVERRIDES: dict[str, tuple[str, ...]] = {
    "IR_SOAR_ENV": ("environment",),
    "IR_SOAR_MODE": ("mode",),
    "IR_SOAR_LOG_LEVEL": ("logging", "level"),
    "IR_SOAR_LOG_DIR": ("logging", "log_dir"),
    "IR_SOAR_AUDIT_LOG": ("logging", "audit_log_path"),
    "IR_SOAR_PLAYBOOKS_DIR": ("paths", "playbooks_dir"),
    "IR_SOAR_EVIDENCE_DIR": ("paths", "evidence_dir"),
}


class ConfigError(RuntimeError):
    """Raised when configuration cannot be loaded or fails validation."""


def _deep_merge(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    """Recursively merge `overlay` into `base`, returning a new dict.

    Dicts are merged key-by-key; any non-dict value in `overlay` replaces
    the corresponding value in `base` outright (lists are replaced, not
    concatenated — predictable beats clever for a config merger).
    """
    merged = dict(base)
    for key, overlay_value in overlay.items():
        base_value = merged.get(key)
        if isinstance(base_value, dict) and isinstance(overlay_value, dict):
            merged[key] = _deep_merge(base_value, overlay_value)
        else:
            merged[key] = overlay_value
    return merged


def _interpolate_env(value: Any) -> Any:
    """Recursively resolve ${VAR:-default} placeholders in strings/dicts/lists."""
    if isinstance(value, str):
        def _replace(match: re.Match[str]) -> str:
            var_name = match.group(1)
            default = match.group("default") if match.group("default") is not None else ""
            return os.environ.get(var_name, default)

        return _ENV_PLACEHOLDER_RE.sub(_replace, value)
    if isinstance(value, dict):
        return {k: _interpolate_env(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_interpolate_env(v) for v in value]
    return value


def _load_yaml_file(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise ConfigError(f"Configuration file not found: {path}")
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"Failed to parse YAML config {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"Config file {path} must contain a YAML mapping at the top level")
    return data


def _set_nested(d: dict[str, Any], key_path: tuple[str, ...], value: Any) -> None:
    cursor = d
    for key in key_path[:-1]:
        cursor = cursor.setdefault(key, {})
    cursor[key_path[-1]] = value


def _apply_named_env_overrides(merged: dict[str, Any]) -> dict[str, Any]:
    """Apply the narrow, documented list of top-level env var overrides."""
    result = dict(merged)
    for env_var, key_path in _ENV_VAR_OVERRIDES.items():
        if env_var in os.environ:
            _set_nested(result, key_path, os.environ[env_var])
    return result


def _apply_cli_overrides(merged: dict[str, Any], cli_overrides: dict[str, Any]) -> dict[str, Any]:
    """Apply CLI overrides given as dotted keys, e.g. {'logging.level': 'DEBUG'}."""
    result = dict(merged)
    for dotted_key, value in cli_overrides.items():
        if value is None:
            continue
        key_path = tuple(dotted_key.split("."))
        _set_nested(result, key_path, value)
    return result


def load_config(
    config_path: str | Path = "config/config.yaml",
    env: str | None = None,
    cli_overrides: dict[str, Any] | None = None,
    *,
    dotenv_path: str | Path | None = ".env",
    config_dir: str | Path | None = None,
) -> AppConfig:
    """Build the final, validated `AppConfig` for this run.

    Args:
        config_path: path to the base config.yaml.
        env: explicit environment name (lab/home/production-like) to select
            the overlay file. If None, falls back to IR_SOAR_ENV, then to
            the `environment` key inside the base config file.
        cli_overrides: dotted-path -> value overrides from the CLI, e.g.
            {"mode": "live", "logging.level": "DEBUG"}. These win over
            everything else.
        dotenv_path: optional path to a .env file to load into the process
            environment before resolving ${VAR} placeholders. Safe to omit
            or point at a nonexistent file (no-op in that case).
        config_dir: directory containing environment overlay files
            (config.<env>.yaml). Defaults to the base config file's parent
            directory.

    Returns:
        A fully validated AppConfig instance.

    Raises:
        ConfigError: if a required file is missing or malformed.
        ConfigError: if the merged configuration fails schema validation.
    """
    if dotenv_path is not None:
        # Loading a .env is best-effort and never overrides variables that
        # are already set in the real process environment (e.g. in CI).
        load_dotenv(dotenv_path=dotenv_path, override=False)

    base_path = Path(config_path)
    base_dict = _load_yaml_file(base_path)

    resolved_env = env or os.environ.get("IR_SOAR_ENV") or base_dict.get("environment", "lab")

    overlay_dir = Path(config_dir) if config_dir is not None else base_path.parent
    overlay_path = overlay_dir / f"config.{resolved_env}.yaml"
    overlay_dict = _load_yaml_file(overlay_path) if overlay_path.exists() else {}

    merged = _deep_merge(base_dict, overlay_dict)
    merged = _interpolate_env(merged)
    merged = _apply_named_env_overrides(merged)
    merged = _apply_cli_overrides(merged, cli_overrides or {})

    try:
        return AppConfig.model_validate(merged)
    except ValidationError as exc:
        raise ConfigError(f"Invalid configuration after merging all sources:\n{exc}") from exc
