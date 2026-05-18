"""
PatchForge vLLM Wrapper (Bypass Mode)

Calls run_remediation directly using vLLM — no Google ADK required.
"""

from __future__ import annotations

import json
from typing import Optional

from agents.patchforge.tools import run_remediation
from core.schemas import AgentRequest, AgentResponse
from llm.llm_client import LLMClient
from utils.logger import logger


class PatchForgeVLLMWrapper:
    def __init__(self) -> None:
        logger.info("PatchForgeVLLMWrapper initialized (vLLM bypass mode)")

    async def handle_request(
        self,
        request: AgentRequest,
        *,
        session_id: Optional[str] = None,
    ) -> AgentResponse:
        logger.info(f"[patchforge] START agent_id={request.agent_id}")

        ctx = request.context or {}
        finding_json = ctx.get("finding_json", "")
        source_code = ctx.get("source_code", "")
        filename = ctx.get("filename", "unknown")
        repo_owner = ctx.get("repo_owner", "")
        repo_name = ctx.get("repo_name", "")

        if not finding_json:
            logger.warning("[patchforge] no finding_json in context — skipping")
            return AgentResponse(
                agent_id=request.agent_id,
                status="skipped",
                output=json.dumps({"error": "No finding provided for remediation"}),
            )

        llm_provider = ctx.get("llm_provider") or None
        llm_model = ctx.get("llm_model") or None
        llm_key = ctx.get("llm_key") or None
        llm = LLMClient(model=llm_model, backend=llm_provider, api_key=llm_key) if llm_provider else None
        logger.info(f"[patchforge] remediating finding in '{filename}' repo={repo_owner}/{repo_name} llm={llm.backend if llm else 'default'}/{llm.model if llm else 'default'}")

        try:
            result = await run_remediation(
                finding_json=finding_json,
                source_code=source_code,
                filename=filename,
                repo_owner=repo_owner,
                repo_name=repo_name,
                llm_client_override=llm,
            )
            logger.info(f"[patchforge] DONE success={result.get('success')} "
                        f"pr_url={(result.get('pr_result') or {}).get('pr_url', 'none')}")
            return AgentResponse(
                agent_id=request.agent_id,
                status="success",
                output=json.dumps(result, indent=2),
            )
        except Exception as exc:
            logger.error(f"[patchforge] failed: {exc}")
            return AgentResponse(
                agent_id=request.agent_id,
                status="error",
                output=json.dumps({"error": str(exc)}),
            )
