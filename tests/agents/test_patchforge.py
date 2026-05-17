import pytest
import json
from pathlib import Path
from unittest.mock import AsyncMock, patch
from agents.patchforge.tools import (
    generate_fix_candidates,
    test_fix_in_sandbox as _sandbox_tool,
    verify_candidate, create_remediation_pr,
)


FINDING_DYNAMIC_EXEC = json.dumps({
    "technique": "dynamic_execution",
    "type": "dynamic_execution",
    "filename": "app.py",
    "line": 5,
    "evidence": "eval(user_input)",
    "description": "User input passed directly to eval.",
    "severity": "CRITICAL",
})

SOURCE_EVAL = "def process(user_input):\n    return eval(user_input)\n"


# ── generate_fix_candidates ───────────────────────────────────

@pytest.mark.asyncio
async def test_generate_fix_candidates_fallback_when_llm_unavailable():
    """Falls back to strategy templates when LLM not running."""
    # generate_fix_candidates imports llm_client inside function → patch source module
    with patch("llm.llm_client.llm_client") as mock_client:
        mock_client.complete = AsyncMock(side_effect=Exception("no llm"))

        res = await generate_fix_candidates(
            FINDING_DYNAMIC_EXEC, SOURCE_EVAL, "app.py", num_candidates=2)

    assert "candidates" in res
    assert len(res["candidates"]) >= 1
    c = res["candidates"][0]
    assert "strategy" in c
    assert "confidence" in c
    assert "patch" in c


@pytest.mark.asyncio
async def test_generate_fix_candidates_uses_llm_response():
    llm_payload = json.dumps({"candidates": [
        {
            "strategy": "allowlist_dispatch",
            "description": "Replace eval with explicit dispatch table",
            "confidence": 0.93,
            "risk": "LOW",
            "breaking_change": False,
            "patched_source": "SAFE_FUNCS = {}\ndef process(name):\n    return SAFE_FUNCS.get(name, lambda: None)()\n",
        }
    ]})

    with patch("llm.llm_client.llm_client") as mock_client:
        mock_client.complete = AsyncMock(return_value=llm_payload)

        res = await generate_fix_candidates(
            FINDING_DYNAMIC_EXEC, SOURCE_EVAL, "app.py", num_candidates=1)

    assert len(res["candidates"]) == 1
    assert res["candidates"][0]["strategy"] == "allowlist_dispatch"
    assert res["candidates"][0]["confidence"] == 0.93


@pytest.mark.asyncio
async def test_generate_fix_candidates_invalid_finding_json():
    res = await generate_fix_candidates("not json }", SOURCE_EVAL, "app.py")
    assert "error" in res
    assert res["candidates"] == []


@pytest.mark.asyncio
async def test_generate_fix_candidates_respects_num_candidates():
    with patch("llm.llm_client.llm_client") as mock_client:
        mock_client.complete = AsyncMock(side_effect=Exception("no llm"))
        res = await generate_fix_candidates(
            FINDING_DYNAMIC_EXEC, SOURCE_EVAL, "app.py", num_candidates=1)

    assert len(res["candidates"]) <= 1


# ── sandbox testing (wraps test_fix_in_sandbox tool) ─────────

@pytest.mark.asyncio
async def test_sandbox_valid_python_syntax():
    patched = "def process(user_input):\n    return str(user_input)\n"
    res = await _sandbox_tool("fix-1", patched, "app.py")
    assert res["syntax_valid"] is True
    assert res["candidate_id"] == "fix-1"
    assert "threats_remaining" in res


@pytest.mark.asyncio
async def test_sandbox_invalid_python_syntax():
    bad_code = "def broken(\n    return 42\n"
    res = await _sandbox_tool("fix-bad", bad_code, "app.py")
    assert res["syntax_valid"] is False
    assert res["build_passed"] is False


@pytest.mark.asyncio
async def test_sandbox_non_python_passes_syntax():
    js_code = "const x = require('express');"
    res = await _sandbox_tool("fix-js", js_code, "index.js")
    assert res["syntax_valid"] is True


# ── verify_candidate (mini-verifier path) ────────────────────

@pytest.mark.asyncio
async def test_verify_candidate_mini_path_homoglyph(tmp_path):
    orig = tmp_path / "orig"
    patched = tmp_path / "patched"
    orig.mkdir(); patched.mkdir()

    # Write a file with Cyrillic char to orig, clean to patched
    (orig / "auth.py").write_text("def login(pаss): pass\n", encoding="utf-8")
    (patched / "auth.py").write_text("def login(pass_): pass\n", encoding="utf-8")

    finding = json.dumps({
        "technique": "homoglyph",
        "filename": "auth.py",
        "line": 1,
    })
    res = await verify_candidate("cand-1", finding, orig, patched)
    assert res["shannon_verdict"] == "PASS"
    assert res["candidate_id"] == "cand-1"
    assert "verification_method" in res


@pytest.mark.asyncio
async def test_verify_candidate_mini_path_homoglyph_fail(tmp_path):
    orig = tmp_path / "orig"
    patched = tmp_path / "patched"
    orig.mkdir(); patched.mkdir()

    # Both have Cyrillic → FAIL on patched
    (orig / "auth.py").write_text("def login(pаss): pass\n", encoding="utf-8")
    (patched / "auth.py").write_text("def login(pаss): pass\n", encoding="utf-8")

    finding = json.dumps({
        "technique": "homoglyph",
        "filename": "auth.py",
        "line": 1,
    })
    res = await verify_candidate("cand-2", finding, orig, patched)
    assert res["shannon_verdict"] == "FAIL"


@pytest.mark.asyncio
async def test_verify_candidate_web_class_routes_to_shannon_stub():
    finding = json.dumps({"technique": "xss", "filename": "views.py", "line": 1})
    res = await verify_candidate("cand-xss", finding, Path("."), Path("."))
    # Shannon not wired → should return stub with pending method
    assert res["candidate_id"] == "cand-xss"
    assert "shannon" in res.get("verification_method", "").lower() or \
           res.get("shannon_verdict") in ("FAIL", "INDETERMINATE")


# ── create_remediation_pr ─────────────────────────────────────

@pytest.mark.asyncio
async def test_create_remediation_pr_builds_spec():
    fix = json.dumps({
        "strategy": "allowlist_dispatch",
        "description": "Replace eval with dispatch table",
        "confidence": 0.93,
    })
    shannon = json.dumps({
        "shannon_verdict": "PASS",
        "verification_method": "mini_verifier:homoglyph_regex",
        "details": "No homoglyphs remaining.",
    })
    finding = json.dumps({
        "type": "dynamic_execution",
        "filename": "app.py",
        "line": 5,
        "severity": "CRITICAL",
        "description": "eval(user_input)",
    })

    res = await create_remediation_pr(
        "owner", "repo", "sentinel-fix/app.py-123",
        fix, shannon, finding,
    )

    assert res["pr_created"] is False  # GitHub API not wired yet
    spec = res["pr_spec"]
    assert spec["owner"] == "owner"
    assert spec["repo"] == "repo"
    assert "sentinel" in spec["title"].lower() or "fix" in spec["title"].lower()
    assert "PASS" in spec["body"] or "allowlist" in spec["body"].lower()


@pytest.mark.asyncio
async def test_create_remediation_pr_invalid_json():
    res = await create_remediation_pr(
        "o", "r", "branch", "bad json}", "{}", "{}",
    )
    assert "error" in res
    assert res["pr_created"] is False