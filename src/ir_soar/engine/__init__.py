"""
The generic playbook interpreter. Nothing in this package knows anything
about phishing or ransomware specifically — all scenario knowledge lives in
data (config/playbooks/*.yaml). This package only knows how to load,
validate, decide, and execute a `Playbook`.
"""

from __future__ import annotations

from ir_soar.engine.decision import ConditionError, Decision, decide, evaluate_condition
from ir_soar.engine.executor import Executor, RunResult, StepOutcome
from ir_soar.engine.playbook_loader import (
    PlaybookLoadError,
    get_playbook_markdown_path,
    list_available_playbooks,
    load_playbook_by_id,
    load_playbook_markdown,
    load_playbook_yaml,
)
from ir_soar.engine.templating import TemplateRenderError, render_inputs

__all__ = [
    "ConditionError",
    "Decision",
    "decide",
    "evaluate_condition",
    "Executor",
    "RunResult",
    "StepOutcome",
    "PlaybookLoadError",
    "get_playbook_markdown_path",
    "list_available_playbooks",
    "load_playbook_by_id",
    "load_playbook_markdown",
    "load_playbook_yaml",
    "TemplateRenderError",
    "render_inputs",
]
