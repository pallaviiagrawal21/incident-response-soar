"""
Deterministic pseudo-random simulation helpers, shared by every enrichment
action when `type: simulated` (the default).

These are NOT real threat intelligence. Values are derived from a stable
hash of the input, so the SAME input always produces the SAME simulated
result — useful for demos, dry-runs, and reproducible tests, without
needing network access or an API key. Swap `type: simulated` for a real
provider type in config once a real connector is implemented for that
enrichment provider — see docs/extending.md.
"""

from __future__ import annotations

import hashlib


def stable_int(seed: str, modulo: int) -> int:
    """A deterministic, uniformly-distributed-enough integer in [0, modulo)."""
    digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()
    return int(digest[:8], 16) % modulo


def simulated_verdict(seed: str) -> tuple[str, int]:
    """Return (verdict, score 0-100) deterministically derived from `seed`."""
    score = stable_int(seed, 101)
    if score >= 80:
        verdict = "malicious"
    elif score >= 40:
        verdict = "suspicious"
    else:
        verdict = "clean"
    return verdict, score


def simulated_bool(seed: str, probability_pct: int = 30) -> bool:
    """Deterministic boolean, true roughly `probability_pct`% of the time across seeds."""
    return stable_int(seed, 100) < probability_pct


def simulated_age_days(seed: str, max_days: int = 3650) -> int:
    return stable_int(seed, max_days) + 1
