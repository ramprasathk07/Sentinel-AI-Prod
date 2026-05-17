"""
Shadow Stalker A2A Wrapper (Bypass Mode)
"""

import json
from typing import Optional

from agents.shadow_stalker.tools import run_full_scan
from core.schemas import AgentRequest, AgentResponse
from utils.logger import logger


class ShadowStalkerA2AWrapper:
    def __init__(self) -> None:
        logger.info("ShadowStalkerA2AWrapper initialized (bypass mode)")

    async def handle_request(
        self,
        request: AgentRequest,
        *,
        session_id: Optional[str] = None,
    ) -> AgentResponse:
        logger.info(f"ShadowStalker A2A (bypass) ▶ agent_id={request.agent_id}")

        diff_content = request.context.get("diff", "")
        file_contents = request.context.get("file_contents", {})
        
        # run_full_scan is a comprehensive tool that handles all 3 stages internally
        results = run_full_scan(diff_content, file_contents)

        output = json.dumps(results, indent=2)
        return AgentResponse(
            agent_id=request.agent_id,
            status="success",
            output=output,
        )
