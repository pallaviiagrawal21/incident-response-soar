"""
Containment actions: state-changing, higher-risk actions (isolate, disable,
block, collect forensics). Importing this subpackage registers every
built-in containment action into `ir_soar.actions.base.ACTION_REGISTRY`.

Every action here delegates the real side effect to a connector resolved
from `ir_soar.connectors` — none of these classes talk to a real system
directly, and all default to `requires_approval: true` at the playbook
level (see config/playbooks/*.yaml).
"""

from __future__ import annotations

from ir_soar.actions.containment.block_ip_domain import BlockIpDomainAction
from ir_soar.actions.containment.collect_forensics import CollectForensicsAction
from ir_soar.actions.containment.disable_account import DisableAccountAction
from ir_soar.actions.containment.isolate_host import IsolateHostAction

__all__ = [
    "BlockIpDomainAction",
    "CollectForensicsAction",
    "DisableAccountAction",
    "IsolateHostAction",
]
