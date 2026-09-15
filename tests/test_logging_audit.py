"""Tests for the hash-chained audit trail (utils/logging.py::AuditLogger)."""

from __future__ import annotations

import json
from pathlib import Path

from ir_soar.utils.logging import AuditLogger


def test_empty_audit_log_verifies(tmp_path: Path) -> None:
    audit = AuditLogger(tmp_path / "audit.jsonl")
    assert audit.verify_chain() is True


def test_chain_verifies_after_multiple_events(tmp_path: Path) -> None:
    audit = AuditLogger(tmp_path / "audit.jsonl")
    audit.log_event("decision", step_id="a", decision="approved")
    audit.log_event("action_result", step_id="a", status="success")
    audit.log_event("decision", step_id="b", decision="denied")
    assert audit.verify_chain() is True


def test_records_are_chained_via_prev_hash(tmp_path: Path) -> None:
    audit = AuditLogger(tmp_path / "audit.jsonl")
    r1 = audit.log_event("decision", step_id="a")
    r2 = audit.log_event("decision", step_id="b")
    assert r2["prev_hash"] == r1["hash"]


def test_tampering_with_a_historical_record_is_detected(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    audit = AuditLogger(path)
    audit.log_event("decision", step_id="a", status="ok")
    audit.log_event("action_result", step_id="a", status="ok")
    audit.log_event("decision", step_id="b", status="ok")
    assert audit.verify_chain() is True

    lines = path.read_text(encoding="utf-8").splitlines()
    record = json.loads(lines[1])
    record["status"] = "TAMPERED"
    lines[1] = json.dumps(record)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    audit2 = AuditLogger(path)
    assert audit2.verify_chain() is False


def test_reopening_an_existing_log_continues_the_chain(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    audit1 = AuditLogger(path)
    audit1.log_event("decision", step_id="a")

    audit2 = AuditLogger(path)  # simulates a new process/run reopening the same file
    audit2.log_event("decision", step_id="b")

    assert audit2.verify_chain() is True
    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
