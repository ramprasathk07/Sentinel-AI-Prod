import pytest
import json
from unittest.mock import AsyncMock, patch
from agents.lead_warden.tools import (
    synthesize_verdict, get_llm_verdict, format_verdict_output,
    emit_reward_signal, query_similar_findings,
)


# ── synthesize_verdict (pure rule-based, no LLM) ──────────────

def test_synthesize_verdict_reviews_on_single_critical_cve():
    # score=10 (CRITICAL weight) → REVIEW (BLOCK threshold is 15)
    arch = json.dumps({
        "cve_findings": [{"cve_id": "CVE-2023-1234", "package_name": "requests",
                          "version": "2.6.0", "severity": "CRITICAL"}],
        "one_week_flags": [],
        "dependencies": [],
    })
    res = synthesize_verdict(archeologist_findings=arch)
    assert res["verdict"] == "REVIEW"
    assert res["risk_score"] == 10.0
    assert res["agent_scores"]["archeologist"] == 10.0


def test_synthesize_verdict_blocks_on_two_critical_cves():
    # 2 × CRITICAL (20.0) → BLOCK
    arch = json.dumps({
        "cve_findings": [
            {"cve_id": "CVE-2023-1234", "package_name": "requests",
             "version": "2.6.0", "severity": "CRITICAL"},
            {"cve_id": "CVE-2023-5678", "package_name": "flask",
             "version": "1.0.0", "severity": "CRITICAL"},
        ],
        "one_week_flags": [],
        "dependencies": [],
    })
    res = synthesize_verdict(archeologist_findings=arch)
    assert res["verdict"] == "BLOCK"
    assert res["risk_score"] >= 15.0


def test_synthesize_verdict_reviews_on_one_week_rule():
    # score=10 (one OWF × CRITICAL) → REVIEW
    arch = json.dumps({
        "cve_findings": [],
        "one_week_flags": [{"package_name": "evil-pkg", "maintainer": "newguy",
                            "account_age_days": 2, "flagged": True}],
        "dependencies": [],
    })
    res = synthesize_verdict(archeologist_findings=arch)
    assert res["verdict"] == "REVIEW"
    assert res["agent_scores"]["archeologist"] >= 10.0
    assert any("One-Week" in r for r in res["reasoning"])


def test_synthesize_verdict_blocks_on_two_one_week_flags():
    # 2 × CRITICAL (20.0) → BLOCK
    arch = json.dumps({
        "cve_findings": [],
        "one_week_flags": [
            {"package_name": "evil-pkg1", "maintainer": "newguy1", "account_age_days": 1},
            {"package_name": "evil-pkg2", "maintainer": "newguy2", "account_age_days": 3},
        ],
        "dependencies": [],
    })
    res = synthesize_verdict(archeologist_findings=arch)
    assert res["verdict"] == "BLOCK"


def test_synthesize_verdict_reviews_on_single_homoglyph():
    # HIGH (5.0) + homoglyph bonus (5.0) = 10 → REVIEW
    ss = json.dumps({
        "findings": [
            {"technique": "homoglyph", "severity": "HIGH",
             "file": "auth.py", "line": 12, "description": "Cyrillic char"},
        ]
    })
    res = synthesize_verdict(shadow_stalker_findings=ss)
    assert res["verdict"] == "REVIEW"
    assert "homoglyph" in " ".join(res["reasoning"]).lower()


def test_synthesize_verdict_blocks_on_two_homoglyphs():
    # 2×HIGH (10.0) + bonus (5.0) = 15 → BLOCK
    ss = json.dumps({
        "findings": [
            {"technique": "homoglyph", "severity": "HIGH", "file": "auth.py", "line": 12},
            {"technique": "homoglyph", "severity": "HIGH", "file": "auth.py", "line": 20},
        ]
    })
    res = synthesize_verdict(shadow_stalker_findings=ss)
    assert res["verdict"] == "BLOCK"


def test_synthesize_verdict_approves_clean():
    arch = json.dumps({"cve_findings": [], "one_week_flags": [], "dependencies": [
        {"name": "requests", "version": "2.31.0", "ecosystem": "PyPI"},
    ]})
    res = synthesize_verdict(archeologist_findings=arch)
    assert res["verdict"] == "APPROVE"
    assert res["risk_score"] < 5.0


def test_synthesize_verdict_review_on_medium_findings():
    ss = json.dumps({
        "findings": [
            {"technique": "base64_payload", "severity": "MEDIUM",
             "file": "loader.py", "line": 5},
            {"technique": "base64_payload", "severity": "MEDIUM",
             "file": "loader.py", "line": 10},
            {"technique": "base64_payload", "severity": "MEDIUM",
             "file": "loader.py", "line": 15},
        ]
    })
    res = synthesize_verdict(shadow_stalker_findings=ss)
    assert res["verdict"] in ("REVIEW", "BLOCK")


def test_synthesize_verdict_attack_classification():
    ss = json.dumps({"findings": [
        {"technique": "install_hook", "severity": "HIGH", "file": "setup.py", "line": 1},
    ]})
    res = synthesize_verdict(shadow_stalker_findings=ss)
    assert res["attack_classification"] == "supply_chain_injection"


def test_synthesize_verdict_detonator_sandbox_escape():
    det = json.dumps({"sandbox_escape_attempted": True, "network_connections": []})
    res = synthesize_verdict(detonator_telemetry=det)
    assert res["verdict"] == "BLOCK"
    assert any("SANDBOX ESCAPE" in r for r in res["reasoning"])


def test_synthesize_verdict_graphiti_boost():
    graphiti = json.dumps({"similar_patterns": [
        {"similarity": 0.85, "finding": {"label": "known_exfil_pattern"}},
    ]})
    res = synthesize_verdict(graphiti_context=graphiti)
    assert any("70%" in r or "Graphiti" in r for r in res["reasoning"])


# ── get_llm_verdict (mocked LLM) ──────────────────────────────

LLM_VERDICT_RESPONSE = json.dumps({
    "verdict": "BLOCK",
    "confidence": 0.92,
    "severity": "CRITICAL",
    "summary": "Critical homoglyph attack detected.",
    "reasoning": ["Cyrillic char in identifier", "Matches known attack pattern"],
    "attack_classification": "code_obfuscation",
})


@pytest.mark.asyncio
async def test_get_llm_verdict_returns_structured_verdict():
    # get_llm_verdict imports llm_client inside the function → patch source module
    with patch("llm.llm_client.llm_client") as mock_client:
        mock_client.complete = AsyncMock(return_value=LLM_VERDICT_RESPONSE)
        mock_client.model = "qwen2.5-coder:7b"
        mock_client.backend = "ollama"

        findings = json.dumps([{"technique": "homoglyph", "severity": "CRITICAL"}])
        res = await get_llm_verdict(archeologist_findings=findings)

    assert "verdict_json" in res
    data = res["verdict_json"]
    assert data["verdict"] == "BLOCK"
    assert "confidence" in data
    assert "severity" in data


@pytest.mark.asyncio
async def test_get_llm_verdict_handles_llm_error():
    with patch("llm.llm_client.llm_client") as mock_client:
        mock_client.complete = AsyncMock(side_effect=Exception("connection refused"))

        res = await get_llm_verdict(archeologist_findings="{}")

    assert "error" in res


@pytest.mark.asyncio
async def test_get_llm_verdict_handles_invalid_json():
    with patch("llm.llm_client.llm_client") as mock_client:
        mock_client.complete = AsyncMock(return_value="not valid json {{")

        res = await get_llm_verdict(archeologist_findings="{}")

    assert "error" in res


# ── format_verdict_output (pure) ──────────────────────────────

def test_format_verdict_output_normalizes_fields():
    res = format_verdict_output(
        verdict="block",
        confidence=1.5,  # should clamp to 1.0
        severity="critical",
        summary="Bad PR",
        risk_score=22.5,
    )
    assert res["verdict"] == "BLOCK"
    assert res["confidence"] == 1.0
    assert res["severity"] == "CRITICAL"
    assert res["risk_score"] == 22.5


def test_format_verdict_output_parses_reasoning_json():
    reasoning_list = ["step1", "step2"]
    res = format_verdict_output(
        verdict="REVIEW", confidence=0.7, severity="HIGH",
        summary="Needs review", reasoning=json.dumps(reasoning_list),
    )
    assert res["reasoning"] == reasoning_list


# ── emit_reward_signal (pure) ─────────────────────────────────

def test_emit_reward_signal_high_reward_for_block():
    res = emit_reward_signal("shadow_stalker", "BLOCK",
                              agent_findings_count=3, agent_score_contribution=10.0)
    assert res["recorded"] is True
    assert res["signal"]["reward"] == 1.0


def test_emit_reward_signal_approve_no_findings():
    res = emit_reward_signal("archeologist", "APPROVE",
                              agent_findings_count=0, agent_score_contribution=0.0)
    assert res["signal"]["reward"] == 0.8


def test_emit_reward_signal_false_positive_negative():
    res = emit_reward_signal("detonator", "APPROVE",
                              agent_findings_count=2, agent_score_contribution=0.0,
                              was_useful=False)
    assert res["signal"]["reward"] < 0


# ── query_similar_findings ────────────────────────────────────

def test_query_similar_findings_returns_dict():
    res = query_similar_findings('{"technique": "homoglyph"}', top_k=3)
    assert "similar_patterns" in res
    assert "match_count" in res
    assert isinstance(res["similar_patterns"], list)