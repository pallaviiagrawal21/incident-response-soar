"""Shared pytest fixtures for the ir_soar test suite."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

import ir_soar.actions  # noqa: F401 - triggers registration of all built-in actions
from ir_soar.actions.base import ACTION_REGISTRY, BaseAction, register_action
from ir_soar.config.loader import load_config
from ir_soar.config.schema import AppConfig
from ir_soar.utils.logging import AuditLogger

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = PROJECT_ROOT / "config" / "config.yaml"
PLAYBOOKS_DIR = PROJECT_ROOT / "config" / "playbooks"
MARKDOWN_DIR = PROJECT_ROOT / "playbooks"


# --- Synthetic test-only actions, registered once at import time --------
# Guarded so re-importing this module (e.g. under pytest-xdist or a
# re-run) never triggers BaseAction's duplicate-registration error.

if "test_noop" not in ACTION_REGISTRY:

    @register_action("test_noop")
    class _NoopAction(BaseAction):
        default_risk = "low"

        def validate_inputs(self, inputs):
            return inputs

        def execute(self, inputs, config):
            return {"ok": True}


if "test_flaky" not in ACTION_REGISTRY:
    _flaky_state: dict[str, int] = {}

    @register_action("test_flaky")
    class _FlakyAction(BaseAction):
        """Fails on every attempt except the last-configured one.

        Inputs: {"key": <unique str>, "fail_until_attempt": <int>}
        """

        default_risk = "low"

        def validate_inputs(self, inputs):
            return inputs

        def execute(self, inputs, config):
            key = inputs["key"]
            _flaky_state[key] = _flaky_state.get(key, 0) + 1
            if _flaky_state[key] < inputs.get("fail_until_attempt", 1):
                raise RuntimeError(f"simulated transient failure #{_flaky_state[key]}")
            return {"ok": True, "attempt": _flaky_state[key]}


if "test_always_fails" not in ACTION_REGISTRY:

    @register_action("test_always_fails")
    class _AlwaysFailsAction(BaseAction):
        default_risk = "low"

        def validate_inputs(self, inputs):
            return inputs

        def execute(self, inputs, config):
            raise RuntimeError("intentional failure for testing")


@pytest.fixture(autouse=True)
def _isolate_environment_variables():
    """Snapshot and restore the real process environment around every test.

    Some code under test — notably the CLI's config loader, via
    `python-dotenv` — legitimately mutates `os.environ` directly (that's
    how `.env` file loading actually works), which `monkeypatch.setenv`/
    `delenv` cannot undo on its own since it didn't make that change.
    Without this, one test that exercises the real CLI against the repo's
    actual `.env` file could leak `IR_SOAR_*` variables into every test
    that runs afterward in the same pytest process (file collection order
    is alphabetical, so `test_cli.py` runs before `test_config.py`).
    """
    original = dict(os.environ)
    yield
    os.environ.clear()
    os.environ.update(original)


@pytest.fixture
def project_root() -> Path:
    return PROJECT_ROOT


@pytest.fixture
def playbooks_dir() -> Path:
    return PLAYBOOKS_DIR


@pytest.fixture
def markdown_dir() -> Path:
    return MARKDOWN_DIR


@pytest.fixture
def test_config(tmp_path: Path) -> AppConfig:
    """A real AppConfig, loaded from the actual config.yaml, but redirected
    to a throwaway tmp_path for logs/audit so tests never touch the real
    project logs directory. dotenv_path=None keeps this hermetic against
    any ambient .env file on the machine running the tests (e.g. the one
    docker-compose.yml expects at the repo root)."""
    return load_config(
        config_path=str(CONFIG_PATH),
        env="lab",
        cli_overrides={
            "logging.log_dir": str(tmp_path / "logs"),
            "logging.audit_log_path": str(tmp_path / "logs" / "audit.jsonl"),
        },
        dotenv_path=None,
    )


@pytest.fixture
def audit_logger(tmp_path: Path) -> AuditLogger:
    return AuditLogger(tmp_path / "audit.jsonl")


@pytest.fixture
def sample_incident_context() -> dict[str, str]:
    return {
        "sender_domain": "phish-example.com",
        "malicious_link_domain": "creds-harvest.example.net",
        "affected_user": "jdoe",
        "affected_host": "ws-jdoe-01",
        "lateral_movement_host": "srv-file01",
        "c2_indicator": "bad-c2.example.net",
        "ransom_binary_hash": "d41d8cd98f00b204e9800998ecf8427e",
    }
