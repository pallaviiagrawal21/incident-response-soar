"""
The generic playbook interpreter. Nothing in this package knows anything
about phishing or ransomware specifically — all scenario knowledge lives in
data (config/playbooks/*.yaml). This package only knows how to load,
validate, and (in later build steps) execute a `Playbook`.
"""

from __future__ import annotations

from ir_soar.engine.playbook_loader import (
    PlaybookLoadError,
    get_playbook_markdown_path,
    list_available_playbooks,
    load_playbook_by_id,
    load_playbook_markdown,
    load_playbook_yaml,
)

__all__ = [
    "PlaybookLoadError",
    "get_playbook_markdown_path",
    "list_available_playbooks",
    "load_playbook_by_id",
    "load_playbook_markdown",
    "load_playbook_yaml",
]
