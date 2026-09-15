"""Tests for strict input validators (utils/validation.py)."""

from __future__ import annotations

import pytest

from ir_soar.utils import validation as v


@pytest.mark.parametrize("value", ["192.168.1.10", "8.8.8.8", "::1", "2001:db8::1"])
def test_validate_ip_accepts_valid(value: str) -> None:
    assert v.is_valid_ip(value)
    assert v.validate_ip(value)


@pytest.mark.parametrize("value", ["999.1.1.1", "not-an-ip", "", "1.2.3"])
def test_validate_ip_rejects_invalid(value: str) -> None:
    assert not v.is_valid_ip(value)
    with pytest.raises(v.ValidationError):
        v.validate_ip(value)


@pytest.mark.parametrize("value", ["evil-example.com", "sub.mal.co.uk", "a-b.example.org"])
def test_validate_domain_accepts_valid(value: str) -> None:
    assert v.is_valid_domain(value)


@pytest.mark.parametrize("value", ["localhost", "bad_label!.com", "-startswithdash.com", ""])
def test_validate_domain_rejects_invalid(value: str) -> None:
    assert not v.is_valid_domain(value)
    with pytest.raises(v.ValidationError):
        v.validate_domain(value)


@pytest.mark.parametrize(
    ("value", "expected_algo"),
    [
        ("d41d8cd98f00b204e9800998ecf8427e", "md5"),
        ("da39a3ee5e6b4b0d3255bfef95601890afd80709", "sha1"),
        ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "sha256"),
    ],
)
def test_validate_hash_detects_algo(value: str, expected_algo: str) -> None:
    normalized = v.validate_hash(value)
    assert normalized == value
    assert v.validate_hash(value, expected_algo=expected_algo) == value


@pytest.mark.parametrize("value", ["nothex", "abc123", "z" * 32, ""])
def test_validate_hash_rejects_invalid(value: str) -> None:
    with pytest.raises(v.ValidationError):
        v.validate_hash(value)


def test_validate_hash_wrong_expected_algo_rejected() -> None:
    md5_value = "d41d8cd98f00b204e9800998ecf8427e"
    with pytest.raises(v.ValidationError):
        v.validate_hash(md5_value, expected_algo="sha256")


@pytest.mark.parametrize("value", ["jdoe", "svc-account.01", "user_name"])
def test_validate_username_accepts_valid(value: str) -> None:
    assert v.is_valid_username(value)


@pytest.mark.parametrize("value", ["", "-badstart", ".badstart", "a" * 100])
def test_validate_username_rejects_invalid(value: str) -> None:
    assert not v.is_valid_username(value)


def test_ensure_no_shell_metacharacters_passes_safe_value() -> None:
    assert v.ensure_no_shell_metacharacters("normal-value_123") == "normal-value_123"


@pytest.mark.parametrize(
    "value",
    ["evil; rm -rf /", "a && b", "$(whoami)", "a | b", "a > b", "a`b`"],
)
def test_ensure_no_shell_metacharacters_rejects_dangerous(value: str) -> None:
    with pytest.raises(v.ValidationError):
        v.ensure_no_shell_metacharacters(value)


def test_require_fields_lists_all_missing_at_once() -> None:
    with pytest.raises(v.ValidationError, match="b, c"):
        v.require_fields({"a": 1}, ["a", "b", "c"])


def test_require_fields_passes_when_all_present() -> None:
    v.require_fields({"a": 1, "b": 2}, ["a", "b"])  # should not raise
