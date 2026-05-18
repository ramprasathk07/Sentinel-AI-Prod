"""
RL Trace Generator

Generates a reasoning trace explaining why the original code failed,
how the patch fixes it, and extracts the lesson.
"""

from __future__ import annotations

import json
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from core.schemas import ReasoningBlock, ReasoningGenerator, ReasoningTrace
from core.config import settings
from llm.llm_client import llm_client
from agents.rl_trace.model_router import resolve_trace_model
from utils.logger import logger


_PROMPTS_DIR = Path(".prompts")

async def generate_reasoning_trace(
    finding: dict,
    original_code: str,
    patched_code: str,
    unified_diff: str,
    override_client=None,
    force_backend: str = "",
) -> ReasoningBlock:
    """
    Generate an RL reasoning trace via LLM.
    """
    if not settings.SENTINEL_RL_TRACE_ENABLED:
        logger.debug("[rl_trace] trace generation disabled")
        return _static_trace_from_finding(finding)

    router_res = await resolve_trace_model(force_backend)
    model = router_res["model"]
    backend = router_res["backend"]
    
    from llm.llm_client import LLMClient
    client = override_client or LLMClient(model=model, backend=backend)
    
    if backend == "none":
        logger.warning("[rl_trace] no available backend for trace, using static stub")
        return _static_trace_from_finding(finding)

    # ── Load System Prompt ──
    prompt_path = Path("agents/rl_trace/prompts/trace.system.txt")
    if not prompt_path.exists():
        system_prompt = (
            "You are an expert security researcher creating reasoning traces for RL training. "
            "Analyze the vulnerable code, the applied patch, and the finding details. "
            "Output strictly valid JSON matching the ReasoningTrace schema: "
            "{root_cause: str, exploit_path: [str], why_patch_fixes: str, residual_risks: [str], lesson: str, tags: [str]} "
            "Keep the output concise (under 400 tokens) and focus on the technical mechanisms."
        )
    else:
        system_prompt = prompt_path.read_text(encoding="utf-8")

    # ── Build User Prompt ──
    technique = finding.get("technique") or finding.get("type") or "unknown"
    desc = finding.get("description", "")
    line = finding.get("line", "?")
    
    user_prompt = f"""\
Please analyze the following security fix and provide the reasoning trace.

**Finding details:**
- Type: {technique}
- Line: {line}
- Description: {desc}

**Unified Diff:**
```diff
{unified_diff}
```
"""

    prompt_hash = hashlib.sha256((system_prompt + user_prompt).encode()).hexdigest()
    _PROMPTS_DIR.mkdir(exist_ok=True)
    (_PROMPTS_DIR / f"{prompt_hash}.txt").write_text(f"SYSTEM:\n{system_prompt}\n\nUSER:\n{user_prompt}", encoding="utf-8")

    # ── LLM Call ──
    try:
        temp = 0.3
        resp_text = await client.complete(
            prompt=user_prompt,
            system_prompt=system_prompt,
            temperature=temp,
            max_tokens=600,
            json_mode=True
        )
        
        # Some models wrap json in markdown
        if resp_text.startswith("```json"):
            resp_text = resp_text[7:]
        if resp_text.endswith("```"):
            resp_text = resp_text[:-3]
        
        trace_dict = json.loads(resp_text)
        if isinstance(trace_dict, dict) and "error" in trace_dict:
            raise ValueError(f"LLM API returned error: {trace_dict['error']}")
            
        # Support both a nested trace dictionary or top-level dictionary
        actual_trace = trace_dict.get("trace") if isinstance(trace_dict, dict) and "trace" in trace_dict else trace_dict
        if not isinstance(actual_trace, dict):
            actual_trace = {}
            
        trace = ReasoningTrace(
            root_cause=actual_trace.get("root_cause", "Analysis failed"),
            exploit_path=actual_trace.get("exploit_path", []),
            why_patch_fixes=actual_trace.get("why_patch_fixes", "Patch applied"),
            residual_risks=actual_trace.get("residual_risks", []),
            lesson=actual_trace.get("lesson", ""),
            tags=actual_trace.get("tags", [technique]),
        )
        
        gen = ReasoningGenerator(
            model=model,
            backend=backend,
            prompt_sha256=prompt_hash,
            temperature=temp,
            tokens_in=len(user_prompt) // 4,  # rough
            tokens_out=len(resp_text) // 4,
        )
        
        return ReasoningBlock(
            generated_at=datetime.now(timezone.utc),
            generator=gen,
            trace=trace,
            confidence_self_reported=0.85
        )
        
    except Exception as exc:
        logger.error(f"[rl_trace] LLM generation failed: {exc}")
        return _static_trace_from_finding(finding)


def _static_trace_from_finding(finding: dict) -> ReasoningBlock:
    """Fallback if LLM fails or is disabled."""
    technique = finding.get("technique") or finding.get("type") or "unknown"
    desc = finding.get("description", "")
    
    trace = ReasoningTrace(
        root_cause=desc,
        exploit_path=[f"Attacker exploits {technique}"],
        why_patch_fixes="Removes the vulnerability pattern",
        residual_risks=["Static fallback — requires human review"],
        lesson="Always validate input and follow secure coding practices.",
        tags=[technique, "static_fallback"]
    )
    
    gen = ReasoningGenerator(
        model="static-stub",
        backend="none",
        prompt_sha256="",
        temperature=0.0
    )
    
    return ReasoningBlock(
        generated_at=datetime.now(timezone.utc),
        generator=gen,
        trace=trace,
        confidence_self_reported=0.0
    )
