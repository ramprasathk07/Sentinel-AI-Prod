"""
Finding Truncator

Deterministic, LLM-free truncation/normalization of scan findings for:
- Check Run output (60k char budget)
- RL training data (reproducible JSON)
- PentestSeed construction
"""

from __future__ import annotations

import hashlib
import json
from typing import List, Optional

# ── Constants ────────────────────────────────────────────────

MAX_EVIDENCE_CHARS = 400
MAX_CODE_CHARS = 800
TOP_K_FINDINGS = 30  # cap before feeding Check Run / pentest

# Severity ordering for scoring
_SEV_SCORE = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}


# ── Core helpers ─────────────────────────────────────────────

def _truncate_diff(text: str, max_chars: int = MAX_CODE_CHARS) -> str:
    """Truncate a diff/code block, keeping first+last section with a middle marker."""
    if not text or len(text) <= max_chars:
        return text
    half = max_chars // 2
    head = text[:half]
    tail = text[-half:]
    omitted = len(text) - max_chars
    return f"{head}\n… [{omitted} chars truncated] …\n{tail}"


def _severity_score(f: dict) -> float:
    sev = (f.get("severity") or "UNKNOWN").upper()
    conf = float(f.get("confidence") or 1.0)
    return _SEV_SCORE.get(sev, 0) * conf


def _dedup_key(f: dict) -> tuple:
    return (
        f.get("file") or f.get("filename") or "",
        f.get("line") or 0,
        f.get("technique") or f.get("type") or "",
    )


# ── Main public function ─────────────────────────────────────

def truncate_finding(
    f: dict,
    max_evidence: int = MAX_EVIDENCE_CHARS,
    max_code: int = MAX_CODE_CHARS,
) -> dict:
    """
    Return a copy of finding `f` with long strings trimmed to fit budget.

    The output dict uses sorted keys for reproducible stable JSON.
    """
    out = dict(f)

    if "evidence" in out and out["evidence"]:
        out["evidence"] = _truncate_diff(str(out["evidence"]), max_evidence)

    for key in ("code", "diff", "diff_hunk", "before", "after", "patched_source"):
        if key in out and out[key]:
            out[key] = _truncate_diff(str(out[key]), max_code)

    return out  # caller serializes with sorted keys


def truncate_and_rank_findings(
    findings: List[dict],
    top_k: int = TOP_K_FINDINGS,
    max_evidence: int = MAX_EVIDENCE_CHARS,
    max_code: int = MAX_CODE_CHARS,
) -> tuple[List[dict], dict]:
    """
    Deduplicate, rank by severity×confidence, cap at top_k, and truncate.

    Returns:
        (truncated_findings, meta) where meta contains dedup/truncation stats.
    """
    original_count = len(findings)

    # Deduplicate
    seen: dict = {}
    for f in findings:
        key = _dedup_key(f)
        existing = seen.get(key)
        if existing is None or _severity_score(f) > _severity_score(existing):
            seen[key] = f
    deduped = list(seen.values())

    # Rank
    ranked = sorted(deduped, key=_severity_score, reverse=True)

    # Cap
    capped = ranked[:top_k]
    dropped = len(ranked) - len(capped)

    # Truncate evidence
    truncated = [truncate_finding(f, max_evidence, max_code) for f in capped]

    meta = {
        "original_count": original_count,
        "after_dedup": len(deduped),
        "after_cap": len(capped),
        "dropped_by_cap": dropped,
        "top_k": top_k,
    }
    return truncated, meta


def stable_json(obj: dict) -> str:
    """Serialize a dict to stable JSON with sorted keys for RL reproducibility."""
    return json.dumps(obj, sort_keys=True, default=str)


def finding_id(f: dict) -> str:
    """Produce a stable 8-char ID for a finding from its canonical fields."""
    key_str = f"{f.get('file','')}-{f.get('line',0)}-{f.get('technique','')}"
    return "F-" + hashlib.sha256(key_str.encode()).hexdigest()[:6].upper()
