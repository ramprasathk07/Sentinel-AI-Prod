"""
PatchForge A2A Wrapper (SentinelAgent)
"""
from __future__ import annotations

import json
from typing import Optional

from agents.patchforge.agent import root_agent
from core.schemas import AgentRequest, AgentResponse
from utils.logger import logger


class PatchForgeA2AWrapper:
    def __init__(self) -> None:
        logger.info("PatchForgeA2AWrapper initialized (SentinelAgent mode)")

    async def handle_request(
        self,
        request: AgentRequest,
        *,
        session_id: Optional[str] = None,
    ) -> AgentResponse:
        logger.info(f"PatchForge A2A ▶ agent_id={request.agent_id}")
        user_message = request.task
        context = request.context or {}
        try:
            output = await root_agent.run(user_message, context=context)
            return AgentResponse(
                agent_id=request.agent_id,
                status="success",
                output=output,
            )
        except Exception as exc:
            logger.error(f"PatchForge A2A failed: {exc}")
            return AgentResponse(
                agent_id=request.agent_id,
                status="error",
                output=json.dumps({"error": str(exc)}),
            )
