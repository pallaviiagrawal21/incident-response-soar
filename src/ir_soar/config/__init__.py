"""Configuration schema and layered loader for ir_soar.

Public API:
    AppConfig    — the fully-typed, validated configuration object
    load_config  — merges defaults -> config.yaml -> env overlay -> env vars
                   -> CLI overrides, into a single AppConfig instance
"""

from __future__ import annotations

from ir_soar.config.loader import load_config
from ir_soar.config.schema import AppConfig

__all__ = ["AppConfig", "load_config"]
