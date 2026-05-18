"""
RL Trace Model Router

Selects the best available model for generating reasoning traces.
Order: AISA → vLLM → Ollama → Static stub
"""

from __future__ import annotations

import httpx
import time
from typing import Dict, Any

from core.config import settings
from utils.logger import logger

_HEALTH_CACHE: dict[str, dict] = {}
_CACHE_TTL = 60  # seconds


async def _check_health(backend: str, base_url: str) -> bool:
    """Check if a backend is healthy, with caching."""
    now = time.time()
    cached = _HEALTH_CACHE.get(backend)
    if cached and now - cached["ts"] < _CACHE_TTL:
        return cached["healthy"]

    healthy = False
    if backend == "aisa" and settings.AISA_API_KEY:
        healthy = True # Assume AISA is healthy if key is present
    elif backend == "vllm" and base_url:
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                # Basic healthcheck for vLLM
                resp = await client.get(f"{base_url}/health")
                if resp.status_code == 200:
                    healthy = True
        except Exception:
            pass
    elif backend == "ollama" and base_url:
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                resp = await client.get(f"{base_url}/api/version")
                if resp.status_code == 200:
                    healthy = True
        except Exception:
            pass

    _HEALTH_CACHE[backend] = {"healthy": healthy, "ts": now}
    return healthy


async def resolve_trace_model(force_backend: str = "") -> Dict[str, Any]:
    """
    Resolve the backend and model to use for trace generation.
    """
    target_backend = force_backend or settings.SENTINEL_RL_TRACE_FORCE_BACKEND

    # 1. Check AISA
    if (not target_backend or target_backend == "aisa") and settings.AISA_API_KEY:
        return {
            "backend": "aisa",
            "model": settings.SENTINEL_RL_TRACE_MODEL_AISA or "deepseek-r1",
        }

    # 2. Check vLLM
    if (not target_backend or target_backend == "vllm") and settings.VLLM_BASE_URL:
        if await _check_health("vllm", settings.VLLM_BASE_URL):
            return {
                "backend": "vllm",
                "model": settings.SENTINEL_RL_TRACE_MODEL_VLLM or settings.VERDICT_MODEL,
            }

    # 3. Check Ollama
    if (not target_backend or target_backend == "ollama") and settings.OLLAMA_BASE_URL:
        if await _check_health("ollama", settings.OLLAMA_BASE_URL):
            return {
                "backend": "ollama",
                "model": settings.SENTINEL_RL_TRACE_MODEL_OLLAMA or settings.VERDICT_MODEL,
            }

    # 4. Fallback
    logger.warning("[model_router] No healthy backend found for trace generation.")
    return {
        "backend": "none",
        "model": "static-stub",
    }
