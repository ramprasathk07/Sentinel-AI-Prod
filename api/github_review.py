"""
GitHub PR Review API — inline review comments and annotations.

Maps ShadowStalker / Archeologist / Pentest findings with file+line
to inline review comments on a pull request.
"""

from __future__ import annotations

from typing import List, Optional
import httpx

from utils.logger import logger


def _headers(token: str) -> dict:
    return {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
    }


async def create_pr_review(
    repo_full_name: str,
    pr_number: int,
    commit_sha: str,
    comments: List[dict],
    token: str,
    event: str = "COMMENT",
    body: str = "",
) -> Optional[int]:
    """
    Post an inline review with per-line annotations on a pull request.

    Args:
        comments: List of {path, position, body} or {path, line, body, side}
        event:    "COMMENT" | "REQUEST_CHANGES" | "APPROVE"

    Returns:
        Review ID on success, None on failure.
    """
    if not token or not repo_full_name or not pr_number:
        return None

    url = f"https://api.github.com/repos/{repo_full_name}/pulls/{pr_number}/reviews"
    payload = {
        "commit_id": commit_sha,
        "body": body,
        "event": event,
        "comments": comments,
    }
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            resp = await client.post(url, headers=_headers(token), json=payload)
            if resp.status_code in (200, 201):
                review_id = resp.json().get("id")
                logger.info(
                    f"[review] Created PR review {review_id} on {repo_full_name}#{pr_number} "
                    f"with {len(comments)} inline comments"
                )
                return review_id
            logger.error(f"[review] create_pr_review failed: {resp.status_code} {resp.text[:200]}")
    except Exception as exc:
        logger.error(f"[review] create_pr_review exception: {exc}")
    return None


def findings_to_review_comments(findings: list, max_comments: int = 20) -> List[dict]:
    """
    Convert a list of StaticFinding-style dicts to GitHub review comment dicts.

    GitHub review comments require {path, line, side, body}.
    The `line` here is the diff line number (not file line) — we use the file line
    with side=RIGHT as a best-effort approximation.
    """
    comments = []
    seen = set()
    for f in findings[:max_comments]:
        path = f.get("file") or f.get("filename") or ""
        line = f.get("line") or 1
        technique = f.get("technique") or f.get("type") or "finding"
        severity = f.get("severity", "UNKNOWN")
        description = f.get("description", "")
        evidence = f.get("evidence", "")

        key = (path, line, technique)
        if key in seen or not path:
            continue
        seen.add(key)

        sev_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(
            (severity or "").upper(), "⚪"
        )
        body = (
            f"{sev_emoji} **Sentinel-AI [{severity}]** — `{technique}`\n\n"
            f"{description}"
            + (f"\n\n```\n{evidence[:400]}\n```" if evidence else "")
        )
        comments.append({"path": path, "line": line, "side": "RIGHT", "body": body})

    return comments


def build_check_annotations(findings: list, max_annotations: int = 50) -> List[dict]:
    """
    Convert findings to GitHub Check Run annotation objects.
    GitHub Check Run annotations: {path, start_line, end_line, annotation_level, message, title}.
    """
    level_map = {"CRITICAL": "failure", "HIGH": "failure", "MEDIUM": "warning", "LOW": "notice"}
    annotations = []
    seen = set()
    for f in findings[:max_annotations]:
        path = f.get("file") or f.get("filename") or ""
        line = f.get("line") or 1
        technique = f.get("technique") or f.get("type") or "finding"
        severity = f.get("severity", "UNKNOWN")

        key = (path, line, technique)
        if key in seen or not path:
            continue
        seen.add(key)

        annotations.append({
            "path": path,
            "start_line": line,
            "end_line": line,
            "annotation_level": level_map.get((severity or "").upper(), "warning"),
            "title": f"[{severity}] {technique}",
            "message": f.get("description", "")[:400],
            "raw_details": f.get("evidence", "")[:400],
        })
    return annotations
