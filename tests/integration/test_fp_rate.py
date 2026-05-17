"""
False-positive gate — Stage 0.10 of IMPLEMENTATION_PLAN.md.

Runs Shadow Stalker against curated safe-PR diff fixtures and verifies the
aggregate FP rate stays below the 8% survival threshold from the master
blueprint. CI fails if FPs creep in.

A fixture diff is a *false positive* if the rule-based verdict synthesizer
emits BLOCK or REVIEW. APPROVE = correctly classified safe.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agents.shadow_stalker.tools import run_full_scan
from agents.lead_warden.tools import synthesize_verdict


FIXTURE_DIR = Path(__file__).parent.parent / "fixtures" / "safe_prs"
FP_THRESHOLD = 0.08  # 8% — Stage-1 survival rule


def _collect_fixtures() -> list[Path]:
    if not FIXTURE_DIR.exists():
        return []
    return sorted(FIXTURE_DIR.glob("*.diff"))


@pytest.fixture(scope="module")
def fixtures() -> list[Path]:
    paths = _collect_fixtures()
    if not paths:
        pytest.skip(f"No safe-PR fixtures found in {FIXTURE_DIR}")
    return paths


def _verdict_for(diff_text: str) -> dict:
    ss = run_full_scan(diff_text, {})
    return synthesize_verdict(
        archeologist_findings=json.dumps({}),
        shadow_stalker_findings=json.dumps(ss),
        pr_metadata=json.dumps({"author": "trusted-maintainer"}),
    )


def test_safe_prs_individually(fixtures):
    """Each safe fixture must individually verdict APPROVE."""
    failures = []
    for path in fixtures:
        diff = path.read_text(encoding="utf-8")
        verdict = _verdict_for(diff)
        if verdict["verdict"] != "APPROVE":
            failures.append((path.name, verdict["verdict"], verdict["risk_score"]))

    assert not failures, (
        f"Safe-PR fixtures emitting non-APPROVE verdicts (FPs):\n"
        + "\n".join(f"  - {n}: {v} (score={s})" for n, v, s in failures)
    )


def test_aggregate_fp_rate(fixtures):
    """Aggregate FP rate across the safe-PR corpus must stay below threshold."""
    total = len(fixtures)
    fps = 0
    for path in fixtures:
        diff = path.read_text(encoding="utf-8")
        verdict = _verdict_for(diff)
        if verdict["verdict"] in ("BLOCK", "REVIEW"):
            fps += 1
    rate = fps / total if total else 0.0
    assert rate <= FP_THRESHOLD, (
        f"FP rate {rate:.1%} ({fps}/{total}) exceeds {FP_THRESHOLD:.0%} threshold"
    )
