"""
Standard result envelope returned by every action's `run()` call.

Kept intentionally small and uniform so the executor, the audit logger, and
the CLI can all handle any action's result identically, regardless of
whether it's an enrichment lookup or a containment action.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

ActionStatus = Literal["success", "failure", "skipped"]


class ActionResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: ActionStatus
    data: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None
    duration_ms: float = Field(default=0.0, ge=0)
    dry_run: bool = False

    @property
    def succeeded(self) -> bool:
        return self.status == "success"
