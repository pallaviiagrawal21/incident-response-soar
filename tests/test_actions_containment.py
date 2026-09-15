"""Tests for the four built-in containment actions."""

from __future__ import annotations

import pytest

from ir_soar.actions.base import get_action_class


def test_isolate_host_dry_run_and_live(test_config) -> None:
    action = get_action_class("isolate_host")()
    r_dry = action.run({"hostname": "ws-jdoe-01"}, test_config, dry_run=True)
    assert r_dry.dry_run is True
    assert r_dry.succeeded

    r_live = action.run({"hostname": "ws-jdoe-01"}, test_config, dry_run=False)
    assert r_live.succeeded
    assert r_live.data["isolated"] is True
    assert r_live.data["connector"] == "simulated"


def test_isolate_host_rejects_invalid_hostname(test_config) -> None:
    action = get_action_class("isolate_host")()
    r = action.run({"hostname": "bad host!"}, test_config, dry_run=False)
    assert r.status == "failure"


def test_disable_account_dry_run_and_live(test_config) -> None:
    action = get_action_class("disable_account")()
    r_dry = action.run({"username": "jdoe"}, test_config, dry_run=True)
    assert r_dry.dry_run is True

    r_live = action.run({"username": "jdoe"}, test_config, dry_run=False)
    assert r_live.succeeded
    assert r_live.data["disabled"] is True


def test_disable_account_rejects_shell_metacharacters(test_config) -> None:
    action = get_action_class("disable_account")()
    r = action.run({"username": "evil;rm -rf /"}, test_config, dry_run=False)
    assert r.status == "failure"


def test_block_ip_domain_accepts_ip_and_domain(test_config) -> None:
    action = get_action_class("block_ip_domain")()
    r_ip = action.run({"target": "198.51.100.23"}, test_config, dry_run=False)
    assert r_ip.succeeded
    assert r_ip.data["target_type"] == "ip"

    r_domain = action.run({"target": "evil-example.com"}, test_config, dry_run=False)
    assert r_domain.succeeded
    assert r_domain.data["target_type"] == "domain"


def test_block_ip_domain_rejects_invalid_target(test_config) -> None:
    action = get_action_class("block_ip_domain")()
    r = action.run({"target": "not valid !!"}, test_config, dry_run=False)
    assert r.status == "failure"


def test_collect_forensics_dry_run_and_live(test_config) -> None:
    action = get_action_class("collect_forensics")()
    r_dry = action.run({"hostname": "ws-jdoe-01"}, test_config, dry_run=True)
    assert r_dry.dry_run is True

    r_live = action.run({"hostname": "ws-jdoe-01"}, test_config, dry_run=False)
    assert r_live.succeeded
    assert "artifacts_collected" in r_live.data


@pytest.mark.parametrize(
    ("action_name", "inputs", "connector_field", "connector_type"),
    [
        ("isolate_host", {"hostname": "ws1"}, "isolation", "edr_api"),
        ("disable_account", {"username": "jdoe"}, "identity", "okta_api"),
        ("block_ip_domain", {"target": "1.2.3.4"}, "firewall", "firewall_api"),
        ("collect_forensics", {"hostname": "ws1"}, "isolation", "edr_api"),
    ],
)
def test_unimplemented_connector_fails_live_but_not_dry_run(
    test_config, action_name: str, inputs: dict, connector_field: str, connector_type: str
) -> None:
    connectors = test_config.connectors.model_copy(
        update={
            connector_field: getattr(test_config.connectors, connector_field).model_copy(
                update={"type": connector_type}
            )
        }
    )
    cfg = test_config.model_copy(update={"connectors": connectors})

    action = get_action_class(action_name)()
    r_live = action.run(inputs, cfg, dry_run=False)
    assert r_live.status == "failure"
    assert "not yet implemented" in r_live.error

    r_dry = action.run(inputs, cfg, dry_run=True)
    assert r_dry.succeeded  # dry-run must be unaffected by connector config
