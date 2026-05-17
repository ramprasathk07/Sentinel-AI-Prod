"""
Tests for llm/llm_client.py — covers both Ollama and vLLM paths with httpx mocking.
"""
import pytest
import json
from unittest.mock import AsyncMock, MagicMock, patch
from llm.llm_client import LLMClient


def _make_mock_response(status_code: int, body: dict):
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = body
    resp.raise_for_status = MagicMock()
    return resp


# ── Ollama backend ────────────────────────────────────────────

@pytest.mark.asyncio
async def test_ollama_complete_returns_text():
    client = LLMClient(model="qwen2.5-coder:7b", backend="ollama",
                       base_url="http://localhost:11434")
    mock_resp = _make_mock_response(200, {"response": "Hello from ollama"})

    with patch("llm.llm_client.httpx.AsyncClient") as mock_cls:
        mock_http = AsyncMock()
        mock_http.__aenter__ = AsyncMock(return_value=mock_http)
        mock_http.__aexit__ = AsyncMock(return_value=False)
        mock_http.post = AsyncMock(return_value=mock_resp)
        mock_cls.return_value = mock_http

        result = await client.complete("Say hello")

    assert result == "Hello from ollama"


@pytest.mark.asyncio
async def test_ollama_complete_json_mode_sets_format():
    client = LLMClient(model="qwen2.5-coder:7b", backend="ollama",
                       base_url="http://localhost:11434")
    mock_resp = _make_mock_response(200, {"response": '{"key": "val"}'})
    captured_payload = {}

    async def capture_post(url, json=None, **kwargs):
        captured_payload.update(json or {})
        return mock_resp

    with patch("llm.llm_client.httpx.AsyncClient") as mock_cls:
        mock_http = AsyncMock()
        mock_http.__aenter__ = AsyncMock(return_value=mock_http)
        mock_http.__aexit__ = AsyncMock(return_value=False)
        mock_http.post = capture_post
        mock_cls.return_value = mock_http

        await client.complete("Return JSON", json_mode=True)

    assert captured_payload.get("format") == "json"


@pytest.mark.asyncio
async def test_ollama_complete_http_error_returns_error_json():
    import httpx
    client = LLMClient(model="qwen2.5-coder:7b", backend="ollama",
                       base_url="http://localhost:11434")

    with patch("llm.llm_client.httpx.AsyncClient") as mock_cls:
        mock_http = AsyncMock()
        mock_http.__aenter__ = AsyncMock(return_value=mock_http)
        mock_http.__aexit__ = AsyncMock(return_value=False)
        mock_http.post = AsyncMock(side_effect=httpx.HTTPError("connect error"))
        mock_cls.return_value = mock_http

        result = await client.complete("hello")

    data = json.loads(result)
    assert "error" in data


# ── vLLM backend ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_vllm_complete_returns_content():
    client = LLMClient(model="qwen2.5-coder:7b", backend="vllm",
                       base_url="http://localhost:8000")
    body = {"choices": [{"message": {"content": "vLLM reply"}}]}
    mock_resp = _make_mock_response(200, body)

    with patch("llm.llm_client.httpx.AsyncClient") as mock_cls:
        mock_http = AsyncMock()
        mock_http.__aenter__ = AsyncMock(return_value=mock_http)
        mock_http.__aexit__ = AsyncMock(return_value=False)
        mock_http.post = AsyncMock(return_value=mock_resp)
        mock_cls.return_value = mock_http

        result = await client.complete("Say something", system_prompt="You are helpful")

    assert result == "vLLM reply"


@pytest.mark.asyncio
async def test_vllm_complete_json_mode_sets_response_format():
    client = LLMClient(model="qwen2.5-coder:7b", backend="vllm",
                       base_url="http://localhost:8000")
    body = {"choices": [{"message": {"content": "{}"}}]}
    mock_resp = _make_mock_response(200, body)
    captured = {}

    async def capture_post(url, json=None, **kwargs):
        captured.update(json or {})
        return mock_resp

    with patch("llm.llm_client.httpx.AsyncClient") as mock_cls:
        mock_http = AsyncMock()
        mock_http.__aenter__ = AsyncMock(return_value=mock_http)
        mock_http.__aexit__ = AsyncMock(return_value=False)
        mock_http.post = capture_post
        mock_cls.return_value = mock_http

        await client.complete("Return JSON", json_mode=True)

    assert captured.get("response_format") == {"type": "json_object"}


@pytest.mark.asyncio
async def test_vllm_complete_includes_system_message():
    client = LLMClient(model="qwen2.5-coder:7b", backend="vllm",
                       base_url="http://localhost:8000")
    body = {"choices": [{"message": {"content": "ok"}}]}
    mock_resp = _make_mock_response(200, body)
    captured = {}

    async def capture_post(url, json=None, **kwargs):
        captured.update(json or {})
        return mock_resp

    with patch("llm.llm_client.httpx.AsyncClient") as mock_cls:
        mock_http = AsyncMock()
        mock_http.__aenter__ = AsyncMock(return_value=mock_http)
        mock_http.__aexit__ = AsyncMock(return_value=False)
        mock_http.post = capture_post
        mock_cls.return_value = mock_http

        await client.complete("hello", system_prompt="Be concise")

    messages = captured.get("messages", [])
    roles = [m["role"] for m in messages]
    assert "system" in roles
    assert "user" in roles


# ── fallback backend ──────────────────────────────────────────

@pytest.mark.asyncio
async def test_fallback_returns_error_json():
    client = LLMClient(model="any", backend="unknown_backend")
    result = await client.complete("hello")
    data = json.loads(result)
    assert "error" in data


# ── health_check ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_health_check_ollama_healthy():
    client = LLMClient(model="qwen2.5-coder:7b", backend="ollama",
                       base_url="http://localhost:11434")
    mock_resp = _make_mock_response(200, {"models": []})

    with patch("llm.llm_client.httpx.AsyncClient") as mock_cls:
        mock_http = AsyncMock()
        mock_http.__aenter__ = AsyncMock(return_value=mock_http)
        mock_http.__aexit__ = AsyncMock(return_value=False)
        mock_http.get = AsyncMock(return_value=mock_resp)
        mock_cls.return_value = mock_http

        result = await client.health_check()

    assert result["healthy"] is True
    assert result["backend"] == "ollama"


@pytest.mark.asyncio
async def test_health_check_unreachable():
    client = LLMClient(model="qwen2.5-coder:7b", backend="ollama",
                       base_url="http://localhost:11434")

    with patch("llm.llm_client.httpx.AsyncClient") as mock_cls:
        mock_http = AsyncMock()
        mock_http.__aenter__ = AsyncMock(return_value=mock_http)
        mock_http.__aexit__ = AsyncMock(return_value=False)
        mock_http.get = AsyncMock(side_effect=Exception("connection refused"))
        mock_cls.return_value = mock_http

        result = await client.health_check()

    assert result["healthy"] is False
    assert "error" in result


@pytest.mark.asyncio
async def test_health_check_unknown_backend():
    client = LLMClient(model="any", backend="unknown")
    result = await client.health_check()
    assert result["healthy"] is False