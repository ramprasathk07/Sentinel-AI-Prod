"""
LLM Client Abstraction — Ollama / vLLM / Google Generative AI

Provides a unified interface for LLM completions used by the Lead Warden's
verdict engine. Supports multiple backends:

  Stage 1: Ollama (Qwen2.5-Coder-7B local)
  Stage 2: vLLM server or Google Gemini
  Stage 3: M-GRPO trained adapter (same interface, swapped model)
"""

from __future__ import annotations

import json
from typing import Optional

import httpx

from core.config import settings


class LLMClient:
    """Unified LLM client supporting Ollama, vLLM, and AISA.one backends."""

    def __init__(
        self,
        model: Optional[str] = None,
        backend: Optional[str] = None,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
    ):
        self.backend = backend or settings.LLM_BACKEND

        if self.backend == "aisa":
            self.model = model or "gpt-4o-mini"
            self.base_url = base_url or settings.AISA_BASE_URL
            self.api_key = api_key or settings.AISA_API_KEY
        elif self.backend == "vllm":
            self.model = model or settings.VERDICT_MODEL
            self.base_url = base_url or settings.VLLM_BASE_URL
            self.api_key = api_key or ""
        else:  # ollama
            self.model = model or settings.VERDICT_MODEL
            self.base_url = base_url or settings.OLLAMA_BASE_URL
            self.api_key = ""

    async def complete(
        self,
        prompt: str,
        system_prompt: str = "",
        temperature: float = 0.1,
        max_tokens: int = 2048,
        json_mode: bool = False,
    ) -> str:
        """
        Run an LLM completion.

        Args:
            prompt:        User prompt text.
            system_prompt: System/instruction prompt.
            temperature:   Sampling temperature (0.0 = deterministic).
            max_tokens:    Maximum tokens to generate.
            json_mode:     If True, request JSON-formatted output.

        Returns:
            The generated text string.
        """
        if self.backend == "ollama":
            return await self._ollama_complete(
                prompt, system_prompt, temperature, max_tokens, json_mode)
        elif self.backend in ("vllm", "aisa"):
            return await self._vllm_complete(
                prompt, system_prompt, temperature, max_tokens, json_mode)
        else:
            return await self._fallback_complete(prompt, system_prompt)

    async def _ollama_complete(
        self, prompt, system_prompt, temperature, max_tokens, json_mode,
    ) -> str:
        """Ollama /api/generate endpoint."""
        payload = {
            "model": self.model,
            "prompt": prompt,
            "system": system_prompt,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
            },
        }
        if json_mode:
            payload["format"] = "json"

        try:
            async with httpx.AsyncClient(timeout=120.0) as client:
                resp = await client.post(
                    f"{self.base_url}/api/generate", json=payload)
                resp.raise_for_status()
                data = resp.json()
                content = data.get("response", "")
                if json_mode:
                    content = self._extract_json_from_response(content)
                return content
        except httpx.HTTPError as exc:
            return json.dumps({"error": f"Ollama API error: {exc}"})

    @staticmethod
    def _is_reasoning_model(model_name: str) -> bool:
        name = model_name.lower()
        return any(k in name for k in ("deepseek-r1", "deepseek_r1", "qwq", "r1-distill"))

    @staticmethod
    def _is_anthropic_model(model_name: str) -> bool:
        name = model_name.lower()
        return name.startswith("claude-") or "anthropic" in name

    @staticmethod
    def _clean_bpe_artifacts(text: str) -> str:
        """Replace BPE tokenizer artifacts with standard ASCII equivalents."""
        return (text
                .replace("Ġ", " ")   # Ġ → space (GPT BPE word-start token)
                .replace("Ċ", "\n")  # Ċ → newline (GPT BPE newline token)
                .replace("ĉ", "\t")  # ĉ → tab
                )

    @staticmethod
    def _extract_json_from_response(text: str) -> str:
        """Strip <think>...</think> blocks, clean BPE artifacts, extract JSON."""
        import re
        # Clean BPE artifacts first
        text = LLMClient._clean_bpe_artifacts(text)
        # Remove thinking blocks
        text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()
        # Find first { or [ and extract to matching close
        for start_char, end_char in (("{", "}"), ("[", "]")):
            idx = text.find(start_char)
            if idx == -1:
                continue
            depth = 0
            in_string = False
            escape_next = False
            for i, ch in enumerate(text[idx:], start=idx):
                if escape_next:
                    escape_next = False
                    continue
                if ch == "\\" and in_string:
                    escape_next = True
                    continue
                if ch == '"':
                    in_string = not in_string
                    continue
                if not in_string:
                    if ch == start_char:
                        depth += 1
                    elif ch == end_char:
                        depth -= 1
                        if depth == 0:
                            return text[idx:i + 1]
        return text

    async def _vllm_complete(
        self, prompt, system_prompt, temperature, max_tokens, json_mode,
    ) -> str:
        """vLLM OpenAI-compatible /v1/chat/completions endpoint."""
        is_reasoning = self._is_reasoning_model(self.model)
        is_anthropic = self._is_anthropic_model(self.model)
        # Anthropic via OpenAI-compat gateways often rejects/ignores response_format.
        # Reasoning models produce null-filled schemas under response_format.
        skip_response_format = is_reasoning or is_anthropic

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})

        if json_mode and skip_response_format:
            prompt = prompt + "\n\nRespond with valid JSON only. No prose, no markdown fences, no commentary outside the JSON object."

        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if json_mode and not skip_response_format:
            payload["response_format"] = {"type": "json_object"}

        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        try:
            async with httpx.AsyncClient(timeout=120.0) as client:
                url = f"{self.base_url}/chat/completions" if self.base_url.endswith("/v1") else f"{self.base_url}/v1/chat/completions"
                resp = await client.post(url, json=payload, headers=headers)
                resp.raise_for_status()
                data = resp.json()
                content = data["choices"][0]["message"]["content"]
                if json_mode:
                    content = self._extract_json_from_response(content)
                return content
        except (httpx.HTTPError, KeyError, IndexError) as exc:
            return json.dumps({"error": f"LLM API error ({self.backend}): {exc}"})

    async def _fallback_complete(self, prompt, system_prompt) -> str:
        """Fallback when no backend is available."""
        return json.dumps({
            "error": "No LLM backend available",
            "note": "Configure OLLAMA_BASE_URL or use vLLM backend",
            "prompt_preview": prompt[:200],
        })

    async def health_check(self) -> dict:
        """Check if the LLM backend is reachable."""
        headers = {}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                if self.backend == "ollama":
                    resp = await client.get(f"{self.base_url}/api/tags")
                elif self.backend in ("vllm", "aisa"):
                    url = f"{self.base_url}/models" if self.base_url.endswith("/v1") else f"{self.base_url}/v1/models"
                    resp = await client.get(url, headers=headers)
                else:
                    return {"healthy": False, "backend": self.backend,
                            "error": "Unknown backend"}

                return {
                    "healthy": resp.status_code == 200,
                    "backend": self.backend,
                    "model": self.model,
                    "base_url": self.base_url,
                }
        except Exception as exc:
            return {"healthy": False, "backend": self.backend,
                    "error": str(exc)}


# Module-level default client
llm_client = LLMClient()
