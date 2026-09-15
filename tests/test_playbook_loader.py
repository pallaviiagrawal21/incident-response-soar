"""Tests for the playbook loader (engine/playbook_loader.py) and schema (models/playbook.py)."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from ir_soar.engine.playbook_loader import (
    PlaybookLoadError,
    list_available_playbooks,
    load_playbook_by_id,
    load_playbook_markdown,
    load_playbook_yaml,
)


@pytest.mark.parametrize("playbook_id", ["phishing_lateral_movement", "ransomware"])
def test_real_playbooks_load_and_validate(playbook_id: str, playbooks_dir: Path) -> None:
    pb = load_playbook_by_id(playbook_id, playbooks_dir)
    assert pb.id == playbook_id
    assert len(pb.phases) == 6
    assert len(pb.all_steps()) > 0
    assert len(pb.mitre_attack) > 0
    assert pb.validate_step_references() == []  # no condition-reference warnings


@pytest.mark.parametrize("playbook_id", ["phishing_lateral_movement", "ransomware"])
def test_real_playbook_markdown_exists(playbook_id: str, markdown_dir: Path) -> None:
    text = load_playbook_markdown(playbook_id, markdown_dir)
    assert len(text) > 500
    assert "MITRE ATT&CK" in text


def test_list_available_playbooks_finds_both(playbooks_dir: Path) -> None:
    ids = list_available_playbooks(playbooks_dir)
    assert "phishing_lateral_movement" in ids
    assert "ransomware" in ids


def test_duplicate_step_id_across_phases_rejected(tmp_path: Path) -> None:
    path = tmp_path / "dup.yaml"
    path.write_text(
        """
id: dup
name: "Broken"
version: "1.0"
phases:
  - name: identification
    steps:
      - id: check_ip
        action_type: ip_domain_reputation
        inputs: {target: "1.2.3.4"}
  - name: containment
    steps:
      - id: check_ip
        action_type: isolate_host
        inputs: {hostname: "host1"}
"""
    )
    with pytest.raises(PlaybookLoadError, match="Duplicate step id"):
        load_playbook_yaml(path)


def test_invalid_mitre_technique_id_rejected(tmp_path: Path) -> None:
    path = tmp_path / "bad_mitre.yaml"
    path.write_text(
        """
id: bad_mitre
name: "Broken MITRE"
version: "1.0"
mitre_attack:
  - tactic: "Initial Access"
    technique: "NOT-A-TECHNIQUE-ID"
phases: []
"""
    )
    with pytest.raises(PlaybookLoadError, match="technique"):
        load_playbook_yaml(path)


def test_non_mapping_yaml_rejected(tmp_path: Path) -> None:
    path = tmp_path / "not_a_mapping.yaml"
    path.write_text("- just\n- a\n- list\n")
    with pytest.raises(PlaybookLoadError, match="mapping"):
        load_playbook_yaml(path)


def test_forward_reference_is_a_soft_warning_not_an_error(tmp_path: Path) -> None:
    path = tmp_path / "forward_reference.yaml"
    path.write_text(
        """
id: forward_reference
name: "Forward reference test"
version: "1.0"
phases:
  - name: identification
    steps:
      - id: step_a
        action_type: log_correlation
        inputs: {user: "x"}
        condition: "steps.step_b.result.suspicious == true"
      - id: step_b
        action_type: log_correlation
        inputs: {user: "x"}
"""
    )
    pb = load_playbook_yaml(path)  # must not raise
    warnings = pb.validate_step_references()
    assert len(warnings) == 1
    assert "step_b" in warnings[0]


def test_filename_id_mismatch_rejected(tmp_path: Path, playbooks_dir: Path) -> None:
    shutil.copy(playbooks_dir / "ransomware.yaml", tmp_path / "wrong_name.yaml")
    with pytest.raises(PlaybookLoadError, match="declares id"):
        load_playbook_by_id("wrong_name", tmp_path)


def test_missing_playbook_file_rejected(tmp_path: Path) -> None:
    with pytest.raises(PlaybookLoadError, match="not found"):
        load_playbook_by_id("does_not_exist", tmp_path)
