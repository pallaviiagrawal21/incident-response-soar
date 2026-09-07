"""
Enrichment actions: read-only lookups with no side effects (reputation,
WHOIS/DNS, log correlation).

Importing this subpackage registers every built-in enrichment action into
`ir_soar.actions.base.ACTION_REGISTRY`. These are the actions a playbook
step can reference via `action_type`. By default (see
`config.approval.require_for_enrichment`), enrichment steps do not require
human approval, since they have no side effects — only containment actions
do, by default.
"""

from __future__ import annotations

from ir_soar.actions.enrichment.hash_reputation import HashReputationAction
from ir_soar.actions.enrichment.ip_domain_reputation import IpDomainReputationAction
from ir_soar.actions.enrichment.log_correlation import LogCorrelationAction
from ir_soar.actions.enrichment.whois_dns import WhoisDnsAction

__all__ = [
    "HashReputationAction",
    "IpDomainReputationAction",
    "LogCorrelationAction",
    "WhoisDnsAction",
]
