"""Smoke tests for the ir-soar CLI (cli.py), via Typer's CliRunner."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from ir_soar.cli import app

runner = CliRunner()


def test_list_playbooks() -> None:
    result = runner.invoke(app, ["list-playbooks"])
    assert result.exit_code == 0
    assert "phishing_lateral_movement" in result.stdout
    assert "ransomware" in result.stdout


def test_list_actions() -> None:
    result = runner.invoke(app, ["list-actions"])
    assert result.exit_code == 0
    assert "isolate_host" in result.stdout
    assert "ip_domain_reputation" in result.stdout


def test_validate_playbook_success() -> None:
    result = runner.invoke(app, ["validate-playbook", "ransomware"])
    assert result.exit_code == 0
    assert "OK" in result.stdout


def test_validate_playbook_nonexistent() -> None:
    result = runner.invoke(app, ["validate-playbook", "does_not_exist"])
    assert result.exit_code == 1


def test_show_playbook() -> None:
    result = runner.invoke(app, ["show-playbook", "phishing_lateral_movement"])
    assert result.exit_code == 0
    assert "MITRE ATT&CK" in result.stdout


def test_run_dry_run_end_to_end(tmp_path: Path) -> None:
    incident_file = tmp_path / "incident.json"
    incident_file.write_text(
        json.dumps(
            {
                "sender_domain": "phish-example.com",
                "malicious_link_domain": "creds-harvest.example.net",
                "affected_user": "jdoe",
                "affected_host": "ws-jdoe-01",
                "lateral_movement_host": "srv-file01",
            }
        )
    )
    report_file = tmp_path / "report.json"

    result = runner.invoke(
        app,
        [
            "run",
            "--playbook",
            "phishing_lateral_movement",
            "--dry-run",
            "--non-interactive",
            "--incident-file",
            str(incident_file),
            "--report-file",
            str(report_file),
            "--log-level",
            "ERROR",
            "--config",
            "config/config.yaml",
        ],
    )
    assert result.exit_code == 0, result.stdout
    assert report_file.exists()

    report = json.loads(report_file.read_text())
    assert report["playbook_id"] == "phishing_lateral_movement"
    assert report["aborted"] is False


def test_run_missing_incident_file_gives_clean_error() -> None:
    result = runner.invoke(
        app,
        ["run", "--playbook", "ransomware", "--dry-run", "--incident-file", "/tmp/does-not-exist-xyz.json"],
    )
    assert result.exit_code == 2


def test_run_full_auto_without_ack_is_blocked(monkeypatch) -> None:
    monkeypatch.delenv("IR_SOAR_FULL_AUTO_ACK", raising=False)
    result = runner.invoke(
        app,
        ["run", "--playbook", "ransomware", "--mode", "live", "--full-auto", "--non-interactive"],
    )
    assert result.exit_code == 3
