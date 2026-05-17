"""
Archeologist A2A Wrapper (Bypass Mode)
"""

import json
from typing import Optional

from agents.archeologist.tools import parse_lockfile, query_osv, check_npm_maintainer, check_pypi_package
from core.schemas import AgentRequest, AgentResponse
from utils.logger import logger


class ArcheologistA2AWrapper:
    def __init__(self) -> None:
        logger.info("ArcheologistA2AWrapper initialized (bypass mode)")

    async def handle_request(
        self,
        request: AgentRequest,
        *,
        session_id: Optional[str] = None,
    ) -> AgentResponse:
        logger.info(f"Archeologist A2A (bypass) ▶ agent_id={request.agent_id}")

        lockfiles = request.context.get("lockfiles", {})
        if not lockfiles:
            return AgentResponse(
                agent_id=request.agent_id,
                status="success",
                output=json.dumps({"findings": [], "message": "No lockfiles provided for analysis."})
            )
        
        
            
        findings = []
        for filename, content in lockfiles.items():
            parsed = parse_lockfile(content, filename)
            for dep in parsed.get("dependencies", []):
                ecosystem = dep.get("ecosystem", "")
                
                osv_res = query_osv(dep["name"], dep["version"], ecosystem)
                if osv_res.get("count", 0) > 0:
                    findings.append({"type": "vulnerability", "details": osv_res})
                    
                if ecosystem.lower() == "npm":
                    m_res = check_npm_maintainer(dep["name"])
                    if m_res.get("flagged_count", 0) > 0:
                        findings.append({"type": "maintainer_risk", "details": m_res})
                elif ecosystem.lower() == "pypi":
                    p_res = check_pypi_package(dep["name"])
                    if p_res.get("flagged"):
                        findings.append({"type": "maintainer_risk", "details": p_res})

        output = json.dumps({"findings": findings}, indent=2)
        return AgentResponse(
            agent_id=request.agent_id,
            status="success",
            output=output,
        )
