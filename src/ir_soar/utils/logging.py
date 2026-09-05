"""
Structured logging and the tamper-evident audit trail for ir_soar.

Two distinct things live here, and they are deliberately kept separate:

1. `setup_logging(config)` — the ordinary application logger ("ir_soar.*"),
   used for debugging, progress, and warnings. Console + rotating file,
   JSON or plain text per config.

2. `AuditLogger` — the incident-response audit trail. Every decision
   (approved / denied / auto-approved) and every action attempt/result is
   recorded here as an append-only, hash-chained JSON Lines file. Each
   record embeds a sha256 hash of (previous record's hash + this record's
   canonical JSON), so replaying the file with `verify_chain()` detects any
   accidental or malicious edit to a historical line. This does not make
   the file cryptographically immutable (an attacker with write access
   could rebuild the whole chain), but it is a real, meaningful integrity
   control appropriate for a portfolio SOAR tool, and mirrors the kind of
   tamper-evidence a production audit trail needs.
"""

from __future__ import annotations

import hashlib
import json
import logging
import logging.handlers
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ir_soar.config.schema import AppConfig

_GENESIS_HASH = "0" * 64


class JsonFormatter(logging.Formatter):
    """Renders each log record as a single JSON line."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        extra_fields = getattr(record, "extra_fields", None)
        if isinstance(extra_fields, dict):
            payload.update(extra_fields)
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def setup_logging(config: AppConfig, *, logger_name: str = "ir_soar") -> logging.Logger:
    """
    Configure and return the application logger described by `config`.

    Idempotent: calling this more than once (e.g. in tests) replaces the
    handlers rather than stacking duplicates.
    """
    log_dir = Path(config.logging.log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger(logger_name)
    logger.setLevel(getattr(logging, config.logging.level))
    logger.handlers.clear()
    logger.propagate = False

    formatter: logging.Formatter
    if config.logging.format == "json":
        formatter = JsonFormatter()
    else:
        formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    file_handler = logging.handlers.RotatingFileHandler(
        log_dir / f"{logger_name}.log",
        maxBytes=10_000_000,
        backupCount=5,
        encoding="utf-8",
    )
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    return logger


class AuditLogger:
    """Append-only, hash-chained structured audit trail.

    Usage:
        audit = AuditLogger(config.logging.audit_log_path)
        audit.log_event("decision", step_id="isolate_host", decision="approved", ...)
        audit.log_event("action_result", step_id="isolate_host", status="success", ...)
        assert audit.verify_chain()
    """

    def __init__(self, audit_log_path: str | Path) -> None:
        self._path = Path(audit_log_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._prev_hash = self._read_last_hash()

    def _read_last_hash(self) -> str:
        if not self._path.exists():
            return _GENESIS_HASH
        last_hash = _GENESIS_HASH
        with self._path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                last_hash = record.get("hash", last_hash)
        return last_hash

    def log_event(self, event_type: str, **fields: Any) -> dict[str, Any]:
        """Append one hash-chained audit record. Thread-safe."""
        with self._lock:
            body: dict[str, Any] = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event_type": event_type,
                **fields,
                "prev_hash": self._prev_hash,
            }
            canonical = json.dumps(body, sort_keys=True, default=str)
            record_hash = hashlib.sha256((self._prev_hash + canonical).encode("utf-8")).hexdigest()
            record = {**body, "hash": record_hash}

            with self._path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, default=str) + "\n")

            self._prev_hash = record_hash
            return record

    def verify_chain(self) -> bool:
        """Replay the audit file and verify hash-chain integrity end to end."""
        if not self._path.exists():
            return True
        prev_hash = _GENESIS_HASH
        with self._path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    return False
                stored_hash = record.get("hash")
                stored_prev = record.get("prev_hash")
                if stored_prev != prev_hash:
                    return False
                body = {k: v for k, v in record.items() if k != "hash"}
                canonical = json.dumps(body, sort_keys=True, default=str)
                expected_hash = hashlib.sha256((prev_hash + canonical).encode("utf-8")).hexdigest()
                if expected_hash != stored_hash:
                    return False
                prev_hash = stored_hash
        return True

    @property
    def path(self) -> Path:
        return self._path
