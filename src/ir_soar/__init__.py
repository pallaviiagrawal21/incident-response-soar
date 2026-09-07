"""
ir_soar — Lightweight Incident Response Playbook + SOAR-style automation
framework.

This package is organized as:

    config/      configuration schema + layered loader (yaml + env + CLI)
    engine/      playbook loading, decision logic, and the executor
    actions/     enrichment and containment action plugins
    connectors/  simulated + (future) real backend integrations
    models/      shared pydantic data models (playbook, results, audit)
    utils/       logging, validation, and safety helpers
    cli.py       the `ir-soar` command line entrypoint

See docs/architecture.md for the full design and docs/extending.md for how
to add new playbooks, actions, and connectors without modifying the engine.
"""

from __future__ import annotations

__version__ = "0.1.0"
