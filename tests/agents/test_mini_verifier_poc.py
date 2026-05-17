"""
Tests for mini_verifier tools — PoC generator + per-class verifiers with LLM mocking.
"""
import pytest
import json
from unittest.mock import AsyncMock, patch
from agents.mini_verifier.tools import generate_poc, _is_safe_poc
from agents.mini_verifier.agent import MiniVerifier


# ── _is_safe_poc (AST whitelist) ──────────────────────────────

def test_is_safe_poc_accepts_clean_script():
    code = """
import importlib, sys
CANARY = "SENTINEL_CANARY=deadbeef12345678"
def main():
    mod = importlib.import_module("target")
    if hasattr(mod, "run"):
        mod.run()
    print(CANARY)
    return 0
sys.exit(main())
"""
    assert _is_safe_poc(code) is True


def test_is_safe_poc_rejects_socket_import():
    code = "import socket\nprint('hi')"
    assert _is_safe_poc(code) is False


def test_is_safe_poc_rejects_requests_import():
    code = "import requests\nrequests.get('http://evil.com')"
    assert _is_safe_poc(code) is False


def test_is_safe_poc_rejects_subprocess_import():
    code = "import subprocess\nsubprocess.run(['ls'])"
    assert _is_safe_poc(code) is False


def test_is_safe_poc_rejects_os_system():
    code = "import os\nos.system('whoami')"
    assert _is_safe_poc(code) is False


def test_is_safe_poc_rejects_urllib():
    code = "from urllib.request import urlopen\nurlopen('http://evil.com')"
    assert _is_safe_poc(code) is False


def test_is_safe_poc_rejects_syntax_error():
    code = "def broken(\n    return 42"
    assert _is_safe_poc(code) is False


# ── generate_poc (mocked LLM) ─────────────────────────────────

GOOD_POC_RESPONSE = json.dumps({
    "poc_code": (
        'import importlib, sys\n'
        'CANARY = "SENTINEL_CANARY=abcdef1234567890"\n'
        'def main():\n'
        '    mod = importlib.import_module("target")\n'
        '    print(CANARY)\n'
        '    return 0\n'
        'sys.exit(main())\n'
    ),
    "canary": "abcdef1234567890",
    "expected": "Prints SENTINEL_CANARY on success",
})


@pytest.mark.asyncio
async def test_generate_poc_returns_valid_poc(tmp_path):
    (tmp_path / "target.py").write_text("def run(): pass\n")
    finding = {
        "filename": "target.py", "line": 1,
        "technique": "dynamic_execution",
        "description": "eval call", "evidence": "eval(x)",
    }

    with patch("agents.mini_verifier.tools.llm_client") as mock_client:
        mock_client.complete = AsyncMock(return_value=GOOD_POC_RESPONSE)
        result = await generate_poc(finding, tmp_path)

    assert result["canary"] == "abcdef1234567890"
    assert "SENTINEL_CANARY=abcdef1234567890" in result["poc_code"]


@pytest.mark.asyncio
async def test_generate_poc_rejects_oversized_script(tmp_path):
    (tmp_path / "target.py").write_text("x = 1\n")
    finding = {"filename": "target.py", "line": 1, "technique": "dynamic_execution",
               "description": "", "evidence": ""}

    big_code = "\n".join([f"x_{i} = {i}" for i in range(210)])
    bad_response = json.dumps({
        "poc_code": big_code,
        "canary": "abcdef1234567890",
        "expected": "too long",
    })

    with patch("agents.mini_verifier.tools.llm_client") as mock_client:
        mock_client.complete = AsyncMock(return_value=bad_response)
        result = await generate_poc(finding, tmp_path)

    assert result == {}


@pytest.mark.asyncio
async def test_generate_poc_rejects_missing_canary(tmp_path):
    (tmp_path / "target.py").write_text("x = 1\n")
    finding = {"filename": "target.py", "line": 1, "technique": "dynamic_execution",
               "description": "", "evidence": ""}

    # canary not in poc_code
    bad_response = json.dumps({
        "poc_code": "print('hello')\n",
        "canary": "abcdef1234567890",
        "expected": "canary absent from code",
    })

    with patch("agents.mini_verifier.tools.llm_client") as mock_client:
        mock_client.complete = AsyncMock(return_value=bad_response)
        result = await generate_poc(finding, tmp_path)

    assert result == {}


@pytest.mark.asyncio
async def test_generate_poc_rejects_unsafe_poc(tmp_path):
    (tmp_path / "target.py").write_text("x = 1\n")
    finding = {"filename": "target.py", "line": 1, "technique": "dynamic_execution",
               "description": "", "evidence": ""}

    unsafe_response = json.dumps({
        "poc_code": (
            'import socket\n'
            'CANARY = "SENTINEL_CANARY=abcdef1234567890"\n'
            'print(CANARY)\n'
        ),
        "canary": "abcdef1234567890",
        "expected": "socket used",
    })

    with patch("agents.mini_verifier.tools.llm_client") as mock_client:
        mock_client.complete = AsyncMock(return_value=unsafe_response)
        result = await generate_poc(finding, tmp_path)

    assert result == {}


@pytest.mark.asyncio
async def test_generate_poc_handles_llm_failure(tmp_path):
    (tmp_path / "target.py").write_text("x = 1\n")
    finding = {"filename": "target.py", "line": 1, "technique": "dynamic_execution",
               "description": "", "evidence": ""}

    with patch("agents.mini_verifier.tools.llm_client") as mock_client:
        mock_client.complete = AsyncMock(side_effect=Exception("LLM down"))
        result = await generate_poc(finding, tmp_path)

    assert result == {}


# ── MiniVerifier dispatch ──────────────────────────────────────

@pytest.mark.asyncio
async def test_mini_verifier_indeterminate_unknown_technique(tmp_path):
    mv = MiniVerifier()
    finding = {"technique": "sql_injection", "filename": "db.py", "line": 1}
    res = await mv.verify(finding, tmp_path, tmp_path)
    assert res.shannon_verdict == "INDETERMINATE"
    assert "no_verifier_for_class" in res.verification_method


@pytest.mark.asyncio
async def test_mini_verifier_indeterminate_on_missing_file(tmp_path):
    mv = MiniVerifier()
    finding = {"technique": "homoglyph", "filename": "nonexistent.py", "line": 1}
    res = await mv.verify(finding, tmp_path, tmp_path)
    assert res.shannon_verdict == "INDETERMINATE"


@pytest.mark.asyncio
async def test_mini_verifier_proof_in_details(tmp_path):
    (tmp_path / "clean.py").write_text("def login(password): pass\n")
    mv = MiniVerifier()
    finding = {"technique": "homoglyph", "filename": "clean.py", "line": 1}
    res = await mv.verify(finding, tmp_path, tmp_path)
    assert "proof=" in res.details


@pytest.mark.asyncio
async def test_mini_verifier_cve_missing_fields(tmp_path):
    mv = MiniVerifier()
    # Missing cve_id and package_name → INDETERMINATE
    finding = {"technique": "cve", "filename": "requirements.txt", "line": 1}
    res = await mv.verify(finding, tmp_path, tmp_path)
    assert res.shannon_verdict == "INDETERMINATE"