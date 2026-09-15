"""Tests for the layered configuration loader (config/loader.py)."""

from __future__ import annotations

from pathlib import Path

import pytest

from ir_soar.config.loader import ConfigError, load_config

CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "config.yaml"


def test_default_load_is_lab_and_dry_run() -> None:
    cfg = load_config(config_path=str(CONFIG_PATH), dotenv_path=None)
    assert cfg.environment == "lab"
    assert cfg.mode == "dry-run"
    assert cfg.full_auto is False


@pytest.mark.parametrize(
    ("env", "expected_mode", "expected_max_actions"),
    [
        ("lab", "dry-run", 100),
        ("home", "interactive", 50),
        ("production-like", "interactive", 25),
    ],
)
def test_environment_overlays(env: str, expected_mode: str, expected_max_actions: int) -> None:
    # dotenv_path=None: this test asserts what config.yaml + the overlay
    # alone produce, deliberately hermetic against any ambient .env file
    # (e.g. the one docker-compose.yml expects at the repo root) — env
    # vars legitimately outrank config/overlay content per the documented
    # precedence, so a real .env WOULD correctly change this test's
    # outcome, which is exactly why the test must not depend on one.
    cfg = load_config(config_path=str(CONFIG_PATH), env=env, dotenv_path=None)
    assert cfg.environment == env
    assert cfg.mode == expected_mode
    assert cfg.execution.max_actions_per_run == expected_max_actions


def test_cli_overrides_win_over_everything() -> None:
    cfg = load_config(
        config_path=str(CONFIG_PATH),
        env="home",
        cli_overrides={"mode": "live", "logging.level": "DEBUG"},
        dotenv_path=None,
    )
    assert cfg.mode == "live"
    assert cfg.logging.level == "DEBUG"


def test_env_var_interpolation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("IR_SOAR_LOG_DIR", "/tmp/custom-log-dir-for-test")
    cfg = load_config(config_path=str(CONFIG_PATH), dotenv_path=None)
    assert cfg.logging.log_dir == "/tmp/custom-log-dir-for-test"


def test_invalid_mode_rejected() -> None:
    with pytest.raises(ConfigError, match="mode"):
        load_config(config_path=str(CONFIG_PATH), cli_overrides={"mode": "super-live"}, dotenv_path=None)


def test_unknown_field_rejected() -> None:
    with pytest.raises(ConfigError):
        load_config(
            config_path=str(CONFIG_PATH), cli_overrides={"this_field_does_not_exist": True}, dotenv_path=None
        )


def test_missing_config_file_rejected(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="not found"):
        load_config(config_path=str(tmp_path / "nope.yaml"), dotenv_path=None)


def test_full_auto_defaults_false_and_is_cli_only() -> None:
    cfg = load_config(config_path=str(CONFIG_PATH), dotenv_path=None)
    assert cfg.full_auto is False
    cfg2 = load_config(config_path=str(CONFIG_PATH), cli_overrides={"full_auto": True}, dotenv_path=None)
    assert cfg2.full_auto is True
    assert cfg2.skips_interactive_approval is True


def test_explicit_env_argument_wins_over_ambient_env_var(monkeypatch: pytest.MonkeyPatch) -> None:
    """Regression test: an explicit --env argument must win over a
    same-purpose IR_SOAR_ENV environment variable for the `environment`
    field itself, even though env vars generally outrank config/overlay
    content. Without this, a stray IR_SOAR_ENV in the process environment
    (e.g. leaked from a .env file) could silently override an operator's
    explicit `--env home`, contradicting the documented CLI > env vars
    precedence for the one field --env is actually supposed to control."""
    monkeypatch.setenv("IR_SOAR_ENV", "lab")
    cfg = load_config(config_path=str(CONFIG_PATH), env="home", dotenv_path=None)
    assert cfg.environment == "home"
    assert cfg.execution.max_actions_per_run == 50  # the home overlay's setting, not lab's
