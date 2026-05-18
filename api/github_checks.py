"""
GitHub Check Runs API Client

Creates and updates check runs in the repository's Checks tab.
Gated by SENTINEL_GH_CHECKS_ENABLED flag — all functions are no-ops when disabled.
"""

from __future__ import annotations

from typing import Optional, List
import httpx

from core.config import settings
from utils.logger import logger


# ── Helpers ───────────────────────────────────────────────────


def _headers(token: str) -> dict:
    return {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
    }


# ── Public API ─────────────────────────────────────────────────


async def create_check_run(
    repo_full_name: str,
    head_sha: str,
    token: str,
    name: str = "Sentinel-AI Security",
) -> Optional[int]:
    """
    Create a new in-progress check run on the PR.

    Returns the check_run_id on success, None if disabled or on error.
    """
    if not settings.SENTINEL_GH_CHECKS_ENABLED:
        logger.debug("[checks] SENTINEL_GH_CHECKS_ENABLED=false — skipping create_check_run")
        return None

    url = f"https://api.github.com/repos/{repo_full_name}/check-runs"
    payload = {
        "name": name,
        "head_sha": head_sha,
        "status": "in_progress",
    }
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(url, headers=_headers(token), json=payload)
            if resp.status_code in (200, 201):
                data = resp.json()
                run_id = data.get("id")
                logger.info(f"[checks] Created check run {run_id} on {repo_full_name}@{head_sha[:7]}")
                return run_id
            logger.error(f"[checks] create_check_run failed: {resp.status_code} {resp.text[:200]}")
    except Exception as exc:
        logger.error(f"[checks] create_check_run exception: {exc}")
    return None


async def update_check_run(
    repo_full_name: str,
    check_run_id: int,
    token: str,
    conclusion: str,
    title: str,
    summary: str,
    text: str = "",
    annotations: Optional[List[dict]] = None,
    actions: Optional[List[dict]] = None,
) -> bool:
    """
    Update an existing check run with final conclusion and output.

    Args:
        conclusion:   "success" | "failure" | "neutral" | "action_required"
        title:        Short title shown in the Checks tab UI
        summary:      One-paragraph markdown summary (shown collapsed)
        text:         Full markdown body (shown when expanded, max 65535 chars)
        annotations:  List of per-file/per-line annotations
        actions:      List of action buttons (Skip: false positive, etc.)
    """
    if not settings.SENTINEL_GH_CHECKS_ENABLED:
        return False

    url = f"https://api.github.com/repos/{repo_full_name}/check-runs/{check_run_id}"

    # Hard cap on text to stay within GitHub's 65535 char limit
    MAX_TEXT = 60000
    if len(text) > MAX_TEXT:
        text = text[:MAX_TEXT] + "\n\n[truncated — view full report in Sentinel dashboard]"

    output: dict = {"title": title, "summary": summary}
    if text:
        output["text"] = text
    if annotations:
        output["annotations"] = annotations[:50]  # GitHub max 50 per update

    payload: dict = {
        "status": "completed",
        "conclusion": conclusion,
        "output": output,
    }
    if actions:
        payload["actions"] = actions

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.patch(url, headers=_headers(token), json=payload)
            if resp.status_code in (200, 201):
                logger.info(f"[checks] Updated check run {check_run_id} → {conclusion}")
                return True
            logger.error(f"[checks] update_check_run failed: {resp.status_code} {resp.text[:200]}")
    except Exception as exc:
        logger.error(f"[checks] update_check_run exception: {exc}")
    return False


# ── Standard dismiss-action buttons ──────────────────────────

DISMISS_ACTIONS = [
    {
        "label": "Skip: false positive",
        "description": "Mark this finding as a false positive",
        "identifier": "dismiss:false_positive",
    },
    {
        "label": "Skip: low risk",
        "description": "Acknowledge but accept the risk",
        "identifier": "dismiss:low_risk",
    },
    {
        "label": "Skip: test cred",
        "description": "This is a test/placeholder credential",
        "identifier": "dismiss:test_cred",
    },
]


def verdict_to_conclusion(verdict: str, severity: str = "") -> str:
    """Map Sentinel verdict → GitHub Check conclusion."""
    v = (verdict or "").upper()
    s = (severity or "").upper()
    if v == "BLOCK":
        return "action_required" if s in ("CRITICAL", "HIGH") else "failure"
    if v == "REVIEW":
        return "neutral"
    return "success"
