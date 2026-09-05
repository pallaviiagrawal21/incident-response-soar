"""
Action plugins: enrichment (read-only, safe by nature) and containment
(state-changing, higher-risk) actions.

Importing this package registers every built-in action into
`ir_soar.actions.base.ACTION_REGISTRY`. The executor (a later build step)
never imports a specific action module directly — it always resolves
`action_type` strings from a playbook through `get_action_class()`.
"""

from __future__ import annotations

from ir_soar.actions.base import ACTION_REGISTRY, ActionTimeoutError, BaseAction, get_action_class, register_action

__all__ = [
    "ACTION_REGISTRY",
    "ActionTimeoutError",
    "BaseAction",
    "get_action_class",
    "register_action",
]
