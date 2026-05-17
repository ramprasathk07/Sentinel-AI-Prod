"""
Mini-Verifier Agent
Routes findings to per-class verifier tools.
"""
from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
import secrets

from core.schemas import ShannonResult
from utils.logger import logger
from .tools import (
    verify_homoglyph, verify_base64_payload, verify_dynamic_exec,
    verify_hidden_exec, verify_install_hook, verify_cve,
)

@dataclass
class VerifierResult:
    """Internal — converted to core.schemas.ShannonResult on the way out."""
    verdict: str            # PASS | FAIL | INDETERMINATE
    method: str             # e.g. "mini_verifier:dynamic_exec"
    details: str
    confidence: float
    extra: dict = None

    def __post_init__(self):
        if self.extra is None:
            self.extra = {}


class MiniVerifier:
    """Single entry-point used by PatchForge."""

    def __init__(self):
        self._dispatch = {
            "homoglyph":           verify_homoglyph,
            "base64_payload":      verify_base64_payload,
            "dynamic_execution":   verify_dynamic_exec,
            "string_concat_eval":  verify_dynamic_exec,
            "obfuscated_import":   verify_dynamic_exec,
            "hidden_in_except":    verify_hidden_exec,
            "dead_code_payload":   verify_hidden_exec,
            "taint_propagation":   verify_hidden_exec,
            "install_hook":        verify_install_hook,
            "cve":                 verify_cve,
        }

    async def verify(self, finding: dict,
                      original_repo: Path,
                      patched_repo: Path) -> ShannonResult:
        candidate_id = finding.get("candidate_id") or _finding_id(finding)
        technique = finding.get("technique") or finding.get("type") or ""
        verifier = self._dispatch.get(technique)

        if verifier is None:
            return _build(candidate_id, "INDETERMINATE",
                           "mini_verifier:no_verifier_for_class",
                           f"No Mini-Verifier registered for technique={technique}",
                           confidence=0.0)

        try:
            r = await verifier(finding, original_repo, patched_repo)
        except Exception as exc:
            logger.exception("Mini-Verifier crashed on %s: %s", technique, exc)
            return _build(candidate_id, "INDETERMINATE",
                           f"mini_verifier:{technique}:crash",
                           str(exc), confidence=0.0)

        return _build(candidate_id, r.verdict, r.method, r.details, r.confidence)


def _build(candidate_id: str, verdict: str, method: str,
           details: str, confidence: float) -> ShannonResult:
    nonce = secrets.token_hex(8)
    proof = sha256(f"{candidate_id}|{verdict}|{nonce}".encode()).hexdigest()
    return ShannonResult(
        candidate_id=candidate_id,
        shannon_verdict=verdict,
        verification_method=method,
        details=f"{details} | proof={proof}",
        confidence=confidence,
        timestamp=datetime.now(timezone.utc),
    )


def _finding_id(finding: dict) -> str:
    base = f"{finding.get('filename','?')}:{finding.get('line',0)}:{finding.get('technique','?')}"
    return sha256(base.encode()).hexdigest()[:16]
