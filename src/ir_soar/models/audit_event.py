"""
Typed representation of a significant event during a run (a decision, an
action result, or a run-level milestone).

This does NOT replace `AuditLogger.log_event()` in utils/logging.py, which
writes the actual hash-chained, on-disk audit trail using plain dicts.
`AuditEvent` exists so the executor's own in-memory bookkeeping (building
the final run summary) is typed and consistent, rather than passing raw
dicts around internally.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

AuditEventType = Literal["run_started", "decision", "action_result", "run_finished", "run_aborted"]


class AuditEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_type: AuditEventType
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    step_id: str | None = None
    playbook_id: str | None = None
    data: dict[str, Any] = Field(default_factory=dict)
