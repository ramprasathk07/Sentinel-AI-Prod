"""
SentinelAgent — provider-agnostic agent base replacing google.adk.agents.Agent.

Wraps LLMClient (Ollama / vLLM / AISA.one) so agent definitions are decoupled
from any specific provider. Model is resolved at runtime from settings or the
per-request override propagated by scan.py.
"""
from __future__ import annotations

import json
from typing import Optional, List, Callable


class SentinelAgent:
    """Drop-in replacement for google.adk.agents.Agent using LLMClient."""

    def __init__(
        self,
        name: str,
        model: Optional[str] = None,
        description: str = "",
        instruction: str = "",
        tools: Optional[List[Callable]] = None,
    ):
        self.name = name
        self.model = model
        self.description = description
        self.instruction = instruction
        self.tools = tools or []

    async def run(
        self,
        message: str,
        context: Optional[dict] = None,
        llm_client_override=None,
    ) -> str:
        """Send message to LLM with instruction as system prompt, return response."""
        from llm.llm_client import llm_client as _default, LLMClient

        if llm_client_override is not None:
            client = llm_client_override
        elif self.model:
            client = LLMClient(model=self.model)
        else:
            client = _default

        prompt = message
        if context:
            prompt += f"\n\nContext:\n```json\n{json.dumps(context, indent=2)}\n```"

        return await client.complete(
            prompt,
            system_prompt=self.instruction,
            json_mode=True,
        )
