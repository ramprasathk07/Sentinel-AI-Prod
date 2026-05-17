"""
Lead Warden A2A Wrapper (Bypass Mode)
"""

import json
from typing import Optional

from agents.lead_warden.tools import get_llm_verdict
from core.schemas import AgentRequest, AgentResponse
from utils.logger import logger


class LeadWardenA2AWrapper:
    def __init__(self) -> None:
        logger.info("LeadWardenA2AWrapper initialized (bypass mode)")

    async def handle_request(
        self,
        request: AgentRequest,
        *,
        session_id: Optional[str] = None,
    ) -> AgentResponse:
        logger.info(f"LeadWarden A2A (bypass) ▶ agent_id={request.agent_id}")

        arch_findings = request.context.get("archeologist_findings", "")
        stalker_findings = request.context.get("shadow_stalker_findings", "")
        pr_metadata = request.context.get("pr_metadata", {})

        # Query the local LLM directly using the specific tool
        try:
            verdict_json = await get_llm_verdict(
                archeologist_findings=arch_findings,
                shadow_stalker_findings=stalker_findings,
                pr_metadata=json.dumps(pr_metadata)
            )
            output = verdict_json.get("verdict_json", "{}")
        except Exception as exc:
            logger.error(f"Failed to get LLM verdict: {exc}")
            output = json.dumps({"verdict": "REVIEW", "confidence": 0.5, "severity": "UNKNOWN", "summary": "Failed to get LLM verdict."})

        return AgentResponse(
            agent_id=request.agent_id,
            status="success",
            output=output,
        )
