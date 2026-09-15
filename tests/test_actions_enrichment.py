"""Tests for the four built-in enrichment actions."""

from __future__ import annotations

import pytest

from ir_soar.actions.base import get_action_class


def test_ip_domain_reputation_accepts_ip_and_domain(test_config) -> None:
    action = get_action_class("ip_domain_reputation")()
    r_ip = action.run({"target": "203.0.113.55"}, test_config, dry_run=False)
    assert r_ip.succeeded
    assert r_ip.data["target_type"] == "ip"

    r_domain = action.run({"target": "evil-example.com"}, test_config, dry_run=False)
    assert r_domain.succeeded
    assert r_domain.data["target_type"] == "domain"


def test_ip_domain_reputation_rejects_invalid_target(test_config) -> None:
    action = get_action_class("ip_domain_reputation")()
    r = action.run({"target": "not a domain !!"}, test_config, dry_run=False)
    assert r.status == "failure"


def test_ip_domain_reputation_is_deterministic(test_config) -> None:
    action = get_action_class("ip_domain_reputation")()
    r1 = action.run({"target": "evil-example.com"}, test_config, dry_run=False)
    r2 = action.run({"target": "evil-example.com"}, test_config, dry_run=False)
    assert r1.data == r2.data


def test_ip_domain_reputation_dry_run_has_no_verdict(test_config) -> None:
    action = get_action_class("ip_domain_reputation")()
    r = action.run({"target": "evil-example.com"}, test_config, dry_run=True)
    assert r.dry_run is True
    assert "verdict" not in r.data  # dry-run never computes real data


def test_hash_reputation_detects_algo(test_config) -> None:
    action = get_action_class("hash_reputation")()
    r = action.run({"hash": "d41d8cd98f00b204e9800998ecf8427e"}, test_config, dry_run=False)
    assert r.succeeded
    assert r.data["algo"] == "md5"


def test_hash_reputation_rejects_invalid_hash(test_config) -> None:
    action = get_action_class("hash_reputation")()
    r = action.run({"hash": "nothex"}, test_config, dry_run=False)
    assert r.status == "failure"


def test_whois_dns_returns_expected_fields(test_config) -> None:
    action = get_action_class("whois_dns")()
    r = action.run({"target": "freshly-registered-phish.com"}, test_config, dry_run=False)
    assert r.succeeded
    assert "domain_age_days" in r.data
    assert "recently_registered" in r.data
    assert "name_servers" in r.data


def test_whois_dns_rejects_single_label(test_config) -> None:
    action = get_action_class("whois_dns")()
    r = action.run({"target": "localhost"}, test_config, dry_run=False)
    assert r.status == "failure"


def test_log_correlation_returns_suspicious_field(test_config) -> None:
    action = get_action_class("log_correlation")()
    r = action.run({"user": "jdoe", "window_minutes": 60}, test_config, dry_run=False)
    assert r.succeeded
    assert "suspicious" in r.data
    assert isinstance(r.data["suspicious"], bool)


def test_log_correlation_rejects_out_of_range_window(test_config) -> None:
    action = get_action_class("log_correlation")()
    r = action.run({"user": "jdoe", "window_minutes": 9999}, test_config, dry_run=False)
    assert r.status == "failure"


def test_log_correlation_rejects_invalid_username(test_config) -> None:
    action = get_action_class("log_correlation")()
    r = action.run({"user": "-bad-user"}, test_config, dry_run=False)
    assert r.status == "failure"


def test_unimplemented_provider_type_fails_live_but_not_dry_run(test_config) -> None:
    cfg = test_config.model_copy(
        update={
            "enrichment_providers": test_config.enrichment_providers.model_copy(
                update={
                    "ip_reputation": test_config.enrichment_providers.ip_reputation.model_copy(
                        update={"type": "abuseipdb"}
                    )
                }
            )
        }
    )
    action = get_action_class("ip_domain_reputation")()
    r_live = action.run({"target": "8.8.8.8"}, cfg, dry_run=False)
    assert r_live.status == "failure"
    assert "not yet implemented" in r_live.error

    r_dry = action.run({"target": "8.8.8.8"}, cfg, dry_run=True)
    assert r_dry.succeeded  # dry-run never calls execute(), so this is unaffected
