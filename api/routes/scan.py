from __future__ import annotations

import os
import sys
import time
import asyncio
import hmac
import json
import re
import secrets
import subprocess
from typing import Optional

import httpx
from fastapi import APIRouter, BackgroundTasks, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel

from agents.archeologist.a2a_wrapper import ArcheologistA2AWrapper
from agents.shadow_stalker.a2a_wrapper import ShadowStalkerA2AWrapper
from agents.patchforge.vllm_wrapper import PatchForgeVLLMWrapper
from agents.lead_warden.tools import synthesize_verdict, get_llm_verdict
from core.schemas import AgentRequest
from llm.llm_client import LLMClient
from storage.db import log_analysis, get_db, get_cached_scan, save_watch, delete_watch, get_watches as db_get_watches, get_recent_scans
from utils.logger import logger


def _make_llm_client(provider: Optional[str], model: Optional[str], key: Optional[str]) -> Optional[LLMClient]:
    """Return a per-request LLMClient if provider is specified, else None (uses default)."""
    if not provider:
        return None
    return LLMClient(model=model or None, backend=provider, api_key=key or None)

router = APIRouter()

_arch = ArcheologistA2AWrapper()
_ss = ShadowStalkerA2AWrapper()
_pf = PatchForgeVLLMWrapper()


def _normalize_repo(raw: str) -> str:
    """Strip GitHub URL prefix, keep only owner/repo."""
    s = raw.strip()
    s = re.sub(r'^https?://', '', s, flags=re.IGNORECASE)
    s = re.sub(r'^github\.com/', '', s, flags=re.IGNORECASE)
    s = s.rstrip('/')
    parts = s.split('/')
    return '/'.join(parts[:2])

# ── in-memory watch store ──────────────────────────────────────
_watches: dict[str, dict] = {}   # repo -> {secret, token, hook_id, webhook_url}
_results: dict[str, list] = {}   # repo -> [scan_result, ...]  newest first


def _flatten_findings(arch_data: dict, ss_data: dict) -> list:
    """Consolidate findings from multiple agents into a single list for reports."""
    findings = []
    # Shadow Stalker findings (static analysis)
    ss_f = ss_data.get("findings", [])
    if isinstance(ss_f, list):
        findings.extend(ss_f)
    
    # Archeologist findings (dependency vulnerabilities)
    # The archeologist output might be nested or a list depending on its structure
    arch_v = arch_data.get("vulnerabilities", [])
    if not arch_v and "findings" in arch_data:
        arch_v = arch_data["findings"]
        
    if isinstance(arch_v, list):
        for f in arch_v:
            findings.append({
                "severity": f.get("severity", "MEDIUM"),
                "technique": f.get("advisory_id", f.get("type", "CVE")),
                "description": f.get("summary", f.get("description", "Vulnerability in dependency")),
                "filename": f.get("package", f.get("filename", "lockfile")),
                "line": f.get("line", 0),
                "before": f.get("vulnerable_range", f.get("evidence", ""))
            })
    return findings



# ── Pydantic models ────────────────────────────────────────────
class ScanRequest(BaseModel):
    repo: str
    pr_number: int
    github_token: Optional[str] = None
    llm_provider: Optional[str] = None   # "vllm" | "aisa"
    llm_model: Optional[str] = None      # model id
    llm_key: Optional[str] = None        # API key (required for aisa)
    user_email: Optional[str] = None
    include_cpg: Optional[bool] = False
    force_rescan: Optional[bool] = False


class RepoScanRequest(BaseModel):
    repo: str
    github_token: Optional[str] = None
    max_prs: int = 5
    llm_provider: Optional[str] = None
    llm_model: Optional[str] = None
    llm_key: Optional[str] = None
    user_email: Optional[str] = None


class ScanResponse(BaseModel):
    verdict: str
    confidence: float
    severity: str
    risk_score: float
    summary: str
    reasoning: list
    attack_classification: Optional[str] = None
    agent_scores: Optional[dict] = {}
    archeologist_findings: Optional[dict] = {}
    shadow_stalker_findings: Optional[dict] = {}
    pr_url: Optional[str] = None
    verdict_engine: Optional[str] = None
    patch_result: Optional[dict] = None
    author: Optional[str] = None
    pr_title: Optional[str] = None
    findings_count: Optional[dict] = None
    findings: Optional[list] = None
    graph_name: Optional[str] = None
    cached: Optional[bool] = False



class FixRequest(BaseModel):
    repo: str
    pr_number: Optional[int] = None
    finding_json: str
    filename: str
    source_code: str
    github_token: str
    llm_provider: Optional[str] = None
    llm_model: Optional[str] = None
    llm_key: Optional[str] = None


class LocalPatchRequest(BaseModel):
    filename: str
    patched_source: str


class SaveTokenRequest(BaseModel):
    user_email: str
    github_token: str

class SuggestFixRequest(BaseModel):
    repo: str
    pr_number: int
    filename: str
    line: int
    patched_code: str
    description: str = ""
    github_token: str


class WatchRequest(BaseModel):

    repo: str
    github_token: str
    base_url: Optional[str] = "http://localhost:8000"
    user_email: Optional[str] = None


# ── GitHub helpers ─────────────────────────────────────────────
async def _fetch_pr_diff(repo: str, pr_number: int, token: Optional[str]) -> Optional[str]:
    headers = {"Accept": "application/vnd.github.v3.diff"}
    if token:
        headers["Authorization"] = f"token {token}"
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(f"https://api.github.com/repos/{repo}/pulls/{pr_number}", headers=headers)
            return resp.text if resp.status_code == 200 else None
    except Exception as exc:
        logger.error(f"GitHub diff fetch error: {exc}")
        return None


async def _fetch_lockfiles(repo: str, ref: str, token: Optional[str]) -> dict:
    names = ["package-lock.json", "requirements.txt", "Cargo.lock", "go.sum", "yarn.lock"]
    headers = {"Accept": "application/vnd.github.v3.raw"}
    if token:
        headers["Authorization"] = f"token {token}"
    found: dict = {}
    async with httpx.AsyncClient(timeout=15.0) as client:
        for fname in names:
            try:
                resp = await client.get(f"https://api.github.com/repos/{repo}/contents/{fname}?ref={ref}", headers=headers)
                if resp.status_code == 200:
                    found[fname] = resp.text
            except Exception:
                pass
    return found


async def _fetch_pr_metadata(repo: str, pr_number: int, token: Optional[str]) -> dict:
    headers = {"Accept": "application/vnd.github.v3+json"}
    if token:
        headers["Authorization"] = f"token {token}"
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(f"https://api.github.com/repos/{repo}/pulls/{pr_number}", headers=headers)
            return resp.json() if resp.status_code == 200 else {}
    except Exception:
        return {}

async def _fetch_github_file(repo: str, filename: str, ref: str, token: Optional[str]) -> Optional[str]:
    """Fetch the raw content of a file from GitHub."""
    headers = {"Accept": "application/vnd.github.v3.raw"}
    if token:
        headers["Authorization"] = f"token {token}"
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(f"https://api.github.com/repos/{repo}/contents/{filename}?ref={ref}", headers=headers)
            return resp.text if resp.status_code == 200 else None
    except Exception as exc:
        logger.error(f"GitHub file fetch error ({filename}): {exc}")
        return None


def _safe_json(s: str) -> dict:
    try:
        return json.loads(s)
    except Exception:
        return {}


def _compute_findings_count(ss_data: dict, arch_data: dict) -> dict:
    """Aggregate findings by severity across Shadow Stalker + Archeologist outputs."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}
    ss = ss_data or {}
    arch = arch_data or {}

    for f in ss.get("findings", []) or []:
        sev = (f.get("severity") or "UNKNOWN").lower()
        counts[sev] = counts.get(sev, 0) + 1

    # CVE findings — severity from data, fallback MEDIUM
    for cve in arch.get("cve_findings", []) or []:
        sev = (cve.get("severity") or "MEDIUM").lower()
        counts[sev] = counts.get(sev, 0) + 1

    # One-Week-Rule maintainer flags — always HIGH per blueprint
    for flag in arch.get("one_week_flags", []) or []:
        counts["high"] += 1

    # Archeologist legacy `findings[]` shape (type=vulnerability/maintainer_risk)
    for f in arch.get("findings", []) or []:
        t = f.get("type")
        if t == "vulnerability":
            sev = (f.get("details", {}).get("severity") or "MEDIUM").lower()
            counts[sev] = counts.get(sev, 0) + 1
        elif t == "maintainer_risk":
            counts["high"] += 1

    counts["total"] = sum(v for k, v in counts.items() if k != "total")
    return counts


# ── Watch helpers ──────────────────────────────────────────────
def _verify_sig(body: bytes, header: str, secret: str) -> bool:
    expected = "sha256=" + hmac.new(secret.encode(), body, digestmod="sha256").hexdigest()
    return hmac.compare_digest(expected, header or "")


async def _run_watch_scan(repo: str, pr_number: int, pr_title: str, diff: str, author: str):
    arch_req = AgentRequest(
        agent_id="archeologist",
        task=f"Scan {repo} PR #{pr_number}",
        context={"diff": diff, "lockfiles": {}, "pr_metadata": {"author": author, "repo": repo, "pr": pr_number}},
    )
    ss_req = AgentRequest(
        agent_id="shadow_stalker",
        task=f"Static analysis {repo} PR #{pr_number}",
        context={"diff": diff},
    )
    arch_res, ss_res = await asyncio.gather(_arch.handle_request(arch_req), _ss.handle_request(ss_req))
    verdict = synthesize_verdict(
        archeologist_findings=arch_res.output,
        shadow_stalker_findings=ss_res.output,
        pr_metadata=json.dumps({"author": author, "repo": repo, "pr": pr_number}),
    )
    arch_data = _safe_json(arch_res.output)
    ss_data = _safe_json(ss_res.output)
    fc = _compute_findings_count(ss_data, arch_data)
    result = {
        "pr_number": pr_number,
        "pr_title": pr_title,
        "pr_url": f"https://github.com/{repo}/pull/{pr_number}",
        "author": author,
        **verdict,
        "archeologist_findings": arch_data,
        "shadow_stalker_findings": ss_data,
        "findings_count": fc,
    }
    _results[repo] = [result] + [r for r in _results.get(repo, []) if r["pr_number"] != pr_number]
    try:
        log_analysis(
            repo_name=repo,
            pr_number=pr_number,
            verdict=verdict["verdict"],
            confidence=verdict["confidence"],
            severity=verdict["severity"],
            findings={"archeologist": arch_data, "shadow_stalker": ss_data},
            summary=verdict.get("summary", ""),
            reasoning=verdict.get("reasoning", []),
            attack_classification=verdict.get("attack_classification", ""),
            risk_score=verdict.get("risk_score", 0.0),
            findings_count=fc,
        )
    except Exception as _db_exc:
        logger.warning(f"[watch_scan] DB log failed PR #{pr_number}: {_db_exc}")
    logger.info(f"Watch scan {repo}#{pr_number}: {verdict['verdict']} score={verdict['risk_score']}")


async def _get_verdict(arch_output: str, ss_output: str, pr_meta_json: str, llm_client_override=None) -> dict:
    """Try LLM verdict first; fall back to rule-based on error."""
    backend = llm_client_override.backend if llm_client_override else "default"
    model = llm_client_override.model if llm_client_override else "default"
    logger.info(f"[verdict] calling LLM verdict backend={backend} model={model}")
    try:
        llm_result = await get_llm_verdict(
            archeologist_findings=arch_output,
            shadow_stalker_findings=ss_output,
            pr_metadata=pr_meta_json,
            llm_client_override=llm_client_override,
        )
        if "error" not in llm_result:
            vj = llm_result.get("verdict_json", {})
            if vj.get("verdict") in ("BLOCK", "REVIEW", "APPROVE"):
                logger.info(f"[verdict] LLM verdict={vj.get('verdict')} confidence={vj.get('confidence')}")
                rule_data = synthesize_verdict(
                    archeologist_findings=arch_output,
                    shadow_stalker_findings=ss_output,
                    pr_metadata=pr_meta_json,
                )
                vj.setdefault("risk_score", rule_data["risk_score"])
                vj.setdefault("agent_scores", rule_data["agent_scores"])
                vj.setdefault("reasoning", vj.get("reasoning", rule_data["reasoning"]))
                vj.setdefault("attack_classification", vj.get("attack_classification", rule_data["attack_classification"]))
                vj["verdict_engine"] = "vllm"
                return vj
        logger.warning(f"[verdict] LLM returned error: {llm_result.get('error')} — falling back to rule-based")
    except Exception as exc:
        logger.warning(f"[verdict] LLM exception: {exc} — falling back to rule-based")
    data = synthesize_verdict(
        archeologist_findings=arch_output,
        shadow_stalker_findings=ss_output,
        pr_metadata=pr_meta_json,
    )
    data["verdict_engine"] = "rule-based"
    return data


# ── SCAN single PR ─────────────────────────────────────────────
@router.post("/scan", response_model=ScanResponse)
async def scan_pr(req: ScanRequest):
    req.repo = _normalize_repo(req.repo)
    graph_name = None
    if req.include_cpg:
        parts = req.repo.split('/')
        owner = parts[0] if len(parts) > 0 else "unknown"
        repo = parts[1] if len(parts) > 1 else "repo"
        graph_name = f"repo_{owner}_{repo}_pr_{req.pr_number}"
    # ── CACHE CHECK ───────────────────────────────────────────
    if not req.force_rescan:
        cached = get_cached_scan(req.repo, req.pr_number)
        if cached:
            logger.info(f"[scan_pr] CACHE HIT for {req.repo} PR #{req.pr_number}")
            return {
                "verdict": cached["verdict"] or "REVIEW",
                "confidence": cached["confidence"] or 0.0,
                "severity": cached["severity"] or "unknown",
                "risk_score": cached["risk_score"] if cached["risk_score"] is not None else 0.0,
                "summary": cached["summary"] or "",
                "reasoning": cached["reasoning"],
                "attack_classification": cached.get("attack_classification"),
                "findings_count": cached["findings_count"],
                "findings": cached["findings"].get("shadow_stalker", {}).get("findings", []) if isinstance(cached["findings"], dict) else [],
                "archeologist_findings": cached["findings"].get("archeologist", {}) if isinstance(cached["findings"], dict) else {},
                "shadow_stalker_findings": cached["findings"].get("shadow_stalker", {}) if isinstance(cached["findings"], dict) else {},
                "pr_url": f"https://github.com/{req.repo}/pull/{req.pr_number}",
                "cached": True
            }

    req.github_token = get_effective_token(req.github_token, req.user_email)
    logger.info(f"[scan_pr] START repo='{req.repo}' pr=#{req.pr_number} token={'set' if req.github_token else 'MISSING'}")
    meta, diff = await asyncio.gather(
        _fetch_pr_metadata(req.repo, req.pr_number, req.github_token),
        _fetch_pr_diff(req.repo, req.pr_number, req.github_token),
    )
    logger.info(f"[scan_pr] fetched meta={bool(meta)} diff={'yes' if diff else 'NONE'} diff_len={len(diff) if diff else 0}")
    if not diff:
        logger.warning(f"[scan_pr] diff fetch failed for {req.repo}#{req.pr_number}")
        raise HTTPException(status_code=422, detail="Could not fetch PR diff. Check repo name, PR number, and token.")
    head_sha = meta.get("head", {}).get("sha", "HEAD")
    lockfiles = await _fetch_lockfiles(req.repo, head_sha, req.github_token)
    author = meta.get("user", {}).get("login", "unknown")
    logger.info(f"[scan_pr] author='{author}' head_sha='{head_sha}' lockfiles={list(lockfiles.keys())}")
    arch_req = AgentRequest(
        agent_id="archeologist",
        task=f"Scan {req.repo} PR #{req.pr_number}",
        context={"diff": diff, "lockfiles": lockfiles, "pr_metadata": {"author": author, "repo": req.repo, "pr": req.pr_number}},
    )
    ss_req = AgentRequest(
        agent_id="shadow_stalker",
        task=f"Static analysis of {req.repo} PR #{req.pr_number}",
        context={"diff": diff},
    )
    logger.info(f"[scan_pr] running Archeologist + ShadowStalker agents")
    arch_res, ss_res = await asyncio.gather(_arch.handle_request(arch_req), _ss.handle_request(ss_req))
    logger.info(f"[scan_pr] agents done — arch_ok={bool(arch_res.output)} ss_ok={bool(ss_res.output)}")
    pr_meta_json = json.dumps({"author": author, "repo": req.repo, "pr": req.pr_number})
    _llm = _make_llm_client(req.llm_provider, req.llm_model, req.llm_key)
    verdict_data = await _get_verdict(arch_res.output, ss_res.output, pr_meta_json, llm_client_override=_llm)
    logger.info(f"[scan_pr] verdict='{verdict_data['verdict']}' score={verdict_data.get('risk_score')} engine='{verdict_data.get('verdict_engine')}'")

    arch_data = _safe_json(arch_res.output)
    ss_data = _safe_json(ss_res.output)
    findings_count = _compute_findings_count(ss_data, arch_data)

    try:
        log_analysis(
            repo_name=req.repo,
            pr_number=req.pr_number,
            verdict=verdict_data["verdict"],
            confidence=verdict_data["confidence"],
            severity=verdict_data["severity"],
            findings={"archeologist": arch_data, "shadow_stalker": ss_data},
            summary=verdict_data.get("summary", ""),
            reasoning=verdict_data.get("reasoning", []),
            attack_classification=verdict_data.get("attack_classification", ""),
            risk_score=verdict_data.get("risk_score", 0.0),
            findings_count=findings_count,
            user_email=req.user_email or "",
            pr_title=meta.get("title", f"PR #{req.pr_number}"),
            author=author,
            pr_url=f"https://github.com/{req.repo}/pull/{req.pr_number}",
        )
    except Exception as _db_exc:
        logger.warning(f"[scan_pr] DB log failed (non-fatal): {_db_exc}")

    # ── PatchForge: run on BLOCK or High findings ───────────────
    patch_result = None
    findings = ss_data.get("findings", [])
    has_high = any(f.get("severity", "").upper() in ["HIGH", "CRITICAL"] for f in findings)

    if verdict_data["verdict"] == "BLOCK" or has_high:
        findings = ss_data.get("findings", [])
        top_finding = findings[0] if findings else None
        if top_finding:
            fname = top_finding.get("filename", "unknown")
            file_reports = ss_data.get("file_reports", {})
            full_source = file_reports.get(fname, {}).get("source", "") or "\n".join(
                l["content"] for l in
                next((f["added_lines"] for f in file_reports.values() if isinstance(f, dict)), [])
            )
            owner, repo_name = (req.repo.split("/") + [""])[:2]
            logger.info(f"[patchforge] triggering for BLOCK verdict — top finding in '{fname}'")
            pf_req = AgentRequest(
                agent_id="patchforge",
                task=f"Remediate BLOCK finding in {req.repo} PR #{req.pr_number}",
                context={
                    "finding_json": json.dumps(top_finding),
                    "source_code": full_source,
                    "filename": fname,
                    "repo_owner": owner,
                    "repo_name": repo_name,
                    "llm_provider": req.llm_provider,
                    "llm_model": req.llm_model,
                    "llm_key": req.llm_key,
                },
            )
            pf_res = await _pf.handle_request(pf_req)
            patch_result = _safe_json(pf_res.output)
            logger.info(f"[patchforge] status={pf_res.status} success={patch_result.get('success') if patch_result else 'N/A'}")
        else:
            logger.info("[patchforge] BLOCK but no findings from Shadow Stalker — skipping")

    logger.info(f"[scan_pr] DONE {req.repo}#{req.pr_number}")
    return ScanResponse(
        verdict=verdict_data["verdict"],
        confidence=verdict_data["confidence"],
        severity=verdict_data["severity"],
        risk_score=verdict_data["risk_score"],
        summary=verdict_data["summary"],
        reasoning=verdict_data["reasoning"],
        attack_classification=verdict_data["attack_classification"],
        agent_scores=verdict_data["agent_scores"],
        archeologist_findings=arch_data,
        shadow_stalker_findings=ss_data,
        pr_url=f"https://github.com/{req.repo}/pull/{req.pr_number}",
        verdict_engine=verdict_data.get("verdict_engine"),
        patch_result=patch_result,
        author=author,
        pr_title=meta.get("title", f"PR #{req.pr_number}"),
        findings_count=findings_count,
        findings=_flatten_findings(arch_data, ss_data),
        graph_name=graph_name,
    )



# ── SCAN-STREAM (SSE) ─────────────────────────────────────────
def _sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


@router.post("/scan-stream")
async def scan_stream(req: ScanRequest):
    """Server-Sent Events variant of /scan — emits stage transitions so the
    UI can animate the agent pipeline. Stages emitted (in order):

        stage:fetch_start          stage:fetch_done
        stage:archeologist_start   stage:archeologist_done
        stage:shadow_stalker_start stage:shadow_stalker_done
        stage:lead_warden_start    stage:lead_warden_done
        stage:patchforge_start     stage:patchforge_done   (only on BLOCK)
        result                     done
    """
    req.repo = _normalize_repo(req.repo)
    graph_name = None
    if req.include_cpg:
        parts = req.repo.split('/')
        owner = parts[0] if len(parts) > 0 else "unknown"
        repo = parts[1] if len(parts) > 1 else "repo"
        graph_name = f"repo_{owner}_{repo}_pr_{req.pr_number}"


    async def _gen():
        try:
            yield _sse("stage:fetch_start", {"repo": req.repo, "pr": req.pr_number})
            req.github_token = get_effective_token(req.github_token, req.user_email)
            meta, diff = await asyncio.gather(
                _fetch_pr_metadata(req.repo, req.pr_number, req.github_token),
                _fetch_pr_diff(req.repo, req.pr_number, req.github_token),
            )
            if not diff:
                yield _sse("error", {"detail": "Could not fetch PR diff"})
                return
            head_sha = meta.get("head", {}).get("sha", "HEAD")
            lockfiles = await _fetch_lockfiles(req.repo, head_sha, req.github_token)
            author = meta.get("user", {}).get("login", "unknown")
            yield _sse("stage:fetch_done", {
                "diff_bytes": len(diff),
                "lockfiles": list(lockfiles.keys()),
                "author": author,
            })

            yield _sse("stage:archeologist_start", {})
            yield _sse("stage:shadow_stalker_start", {})
            arch_req = AgentRequest(
                agent_id="archeologist",
                task=f"Scan {req.repo} PR #{req.pr_number}",
                context={"diff": diff, "lockfiles": lockfiles,
                         "pr_metadata": {"author": author, "repo": req.repo, "pr": req.pr_number}},
            )
            ss_req = AgentRequest(
                agent_id="shadow_stalker",
                task=f"Static analysis of {req.repo} PR #{req.pr_number}",
                context={"diff": diff},
            )
            arch_res, ss_res = await asyncio.gather(
                _arch.handle_request(arch_req),
                _ss.handle_request(ss_req),
            )
            ss_data = _safe_json(ss_res.output)
            arch_data = _safe_json(arch_res.output)
            yield _sse("stage:archeologist_done", {
                "cves": len((arch_data or {}).get("cve_findings", [])),
                "one_week_flags": len((arch_data or {}).get("one_week_flags", [])),
            })
            yield _sse("stage:shadow_stalker_done", {
                "findings": len((ss_data or {}).get("findings", [])),
                "risk_score": (ss_data or {}).get("risk_score", 0),
            })

            yield _sse("stage:lead_warden_start", {})
            pr_meta_json = json.dumps({"author": author, "repo": req.repo, "pr": req.pr_number})
            _llm = _make_llm_client(req.llm_provider, req.llm_model, req.llm_key)
            verdict_data = await _get_verdict(arch_res.output, ss_res.output, pr_meta_json, llm_client_override=_llm)
            yield _sse("stage:lead_warden_done", {
                "verdict": verdict_data["verdict"],
                "engine": verdict_data.get("verdict_engine"),
                "risk_score": verdict_data.get("risk_score"),
                "confidence": verdict_data.get("confidence"),
            })

            patch_result = None
            findings = (ss_data or {}).get("findings", [])
            has_high = any(f.get("severity", "").upper() in ("HIGH", "CRITICAL") for f in findings)
            if verdict_data["verdict"] == "BLOCK" or has_high:
                top = findings[0] if findings else None
                if top:
                    yield _sse("stage:patchforge_start", {"finding": top.get("technique")})
                    fname = top.get("filename", "unknown")
                    file_reports = (ss_data or {}).get("file_reports", {})
                    full_source = file_reports.get(fname, {}).get("source", "") or "\n".join(
                        l["content"] for l in
                        next((f["added_lines"] for f in file_reports.values() if isinstance(f, dict)), [])
                    )
                    owner, repo_name = (req.repo.split("/") + [""])[:2]
                    pf_req = AgentRequest(
                        agent_id="patchforge",
                        task=f"Remediate BLOCK finding in {req.repo} PR #{req.pr_number}",
                        context={
                            "finding_json": json.dumps(top),
                            "source_code": full_source,
                            "filename": fname,
                            "repo_owner": owner,
                            "repo_name": repo_name,
                            "llm_provider": req.llm_provider,
                            "llm_model": req.llm_model,
                            "llm_key": req.llm_key,
                        },
                    )
                    pf_res = await _pf.handle_request(pf_req)
                    patch_result = _safe_json(pf_res.output)
                    vr = (patch_result or {}).get("verifier_report") or {}
                    yield _sse("stage:patchforge_done", {
                        "success": (patch_result or {}).get("success"),
                        "fully_verified": vr.get("fully_verified"),
                        "blocklist": vr.get("blocklist_verdict"),
                        "shannon": vr.get("shannon_verdict"),
                    })

            response = {
                "verdict": verdict_data["verdict"],
                "confidence": verdict_data["confidence"],
                "severity": verdict_data["severity"],
                "risk_score": verdict_data["risk_score"],
                "summary": verdict_data["summary"],
                "reasoning": verdict_data["reasoning"],
                "attack_classification": verdict_data["attack_classification"],
                "agent_scores": verdict_data["agent_scores"],
                "archeologist_findings": arch_data,
                "shadow_stalker_findings": ss_data,
                "pr_url": f"https://github.com/{req.repo}/pull/{req.pr_number}",
                "verdict_engine": verdict_data.get("verdict_engine"),
                "patch_result": patch_result,
                "author": author,
                "pr_title": meta.get("title", f"PR #{req.pr_number}"),
                "findings": _flatten_findings(arch_data, ss_data),
                "graph_name": graph_name,
            }
            yield _sse("result", response)
            yield _sse("done", {"ok": True})
        except Exception as exc:
            logger.error(f"[scan-stream] error: {exc}")
            yield _sse("error", {"detail": str(exc)})

    return StreamingResponse(_gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ── SCAN all open PRs in a repo ────────────────────────────────
@router.post("/scan-repo")
async def scan_repo(req: RepoScanRequest):
    req.repo = _normalize_repo(req.repo)
    logger.info(f"[scan_repo] START repo='{req.repo}' max_prs={req.max_prs} token={'set' if req.github_token else 'MISSING'}")
    headers = {"Accept": "application/vnd.github.v3+json"}
    if req.github_token:
        headers["Authorization"] = f"token {req.github_token}"
    async with httpx.AsyncClient(timeout=15.0) as client:
        url = f"https://api.github.com/repos/{req.repo}/pulls"
        logger.info(f"[scan_repo] GET {url} params={{state=open, per_page={min(req.max_prs, 20)}}}")
        resp = await client.get(
            url,
            headers=headers,
            params={"state": "open", "per_page": min(req.max_prs, 20)},
        )
        logger.info(f"[scan_repo] GitHub response status={resp.status_code}")
        if resp.status_code == 404:
            gh_msg = resp.json().get("message", resp.text[:200]) if resp.content else "no body"
            logger.warning(f"[scan_repo] 404 from GitHub: {gh_msg}")
            raise HTTPException(status_code=404, detail=f"GitHub 404: {gh_msg} | repo='{req.repo}' | token={'set' if req.github_token else 'MISSING'}")
        if resp.status_code == 401:
            logger.warning(f"[scan_repo] 401 Unauthorized — token invalid or missing 'repo' scope")
            raise HTTPException(status_code=401, detail="GitHub 401: Bad token or missing 'repo' scope")
        if resp.status_code != 200:
            logger.error(f"[scan_repo] GitHub error {resp.status_code}: {resp.text[:200]}")
            raise HTTPException(status_code=resp.status_code, detail=f"GitHub API error: {resp.text[:200]}")
        prs = resp.json()
    logger.info(f"[scan_repo] found {len(prs)} open PRs")
    if not prs:
        return {"repo": req.repo, "message": "No open PRs", "results": []}

    async def _scan_one(pr_meta: dict) -> dict:
        pr_number = pr_meta["number"]
        author = pr_meta["user"]["login"]
        title = pr_meta.get("title", f"PR #{pr_number}")
        logger.info(f"[scan_repo] scanning PR #{pr_number} '{title}' by '{author}'")
        diff = await _fetch_pr_diff(req.repo, pr_number, req.github_token)
        if not diff:
            logger.warning(f"[scan_repo] diff fetch failed for PR #{pr_number}")
            return {"pr_number": pr_number, "title": title, "author": author, "error": "Could not fetch diff"}
        logger.info(f"[scan_repo] PR #{pr_number} diff_len={len(diff)} — running agents")
        arch_req = AgentRequest(
            agent_id="archeologist",
            task=f"Scan {req.repo} PR #{pr_number}",
            context={"diff": diff, "lockfiles": {}, "pr_metadata": {"author": author, "repo": req.repo, "pr": pr_number}},
        )
        ss_req = AgentRequest(
            agent_id="shadow_stalker",
            task=f"Static analysis {req.repo} PR #{pr_number}",
            context={"diff": diff},
        )
        arch_res, ss_res = await asyncio.gather(_arch.handle_request(arch_req), _ss.handle_request(ss_req))
        _llm = _make_llm_client(req.llm_provider, req.llm_model, req.llm_key)
        verdict = await _get_verdict(
            arch_res.output,
            ss_res.output,
            json.dumps({"author": author, "repo": req.repo, "pr": pr_number}),
            llm_client_override=_llm,
        )
        logger.info(f"[scan_repo] PR #{pr_number} DONE verdict='{verdict['verdict']}' score={verdict.get('risk_score')} engine='{verdict.get('verdict_engine')}'")
        arch_data_s = _safe_json(arch_res.output)
        ss_data_s = _safe_json(ss_res.output)
        fc = _compute_findings_count(ss_data_s, arch_data_s)
        try:
            log_analysis(
                repo_name=req.repo,
                pr_number=pr_number,
                verdict=verdict["verdict"],
                confidence=verdict["confidence"],
                severity=verdict["severity"],
                findings={"archeologist": arch_data_s, "shadow_stalker": ss_data_s},
                summary=verdict.get("summary", ""),
                reasoning=verdict.get("reasoning", []),
                attack_classification=verdict.get("attack_classification", ""),
                risk_score=verdict.get("risk_score", 0.0),
                findings_count=fc,
                user_email=req.user_email or "",
                pr_title=title,
                author=author,
                pr_url=f"https://github.com/{req.repo}/pull/{pr_number}",
            )
        except Exception as _db_exc:
            logger.warning(f"[scan_repo] DB log failed PR #{pr_number}: {_db_exc}")
        return {
            "pr_number": pr_number, "title": title, "author": author,
            "pr_url": f"https://github.com/{req.repo}/pull/{pr_number}",
            "archeologist_findings": arch_data_s,
            "shadow_stalker_findings": ss_data_s,
            "findings_count": fc,
            **verdict,
        }

    logger.info(f"[scan_repo] launching {len(prs)} parallel scans")
    results = await asyncio.gather(*[_scan_one(pr) for pr in prs])
    logger.info(f"[scan_repo] DONE {req.repo} — {len(results)} PRs scanned")
    return {"repo": req.repo, "pr_count": len(prs), "results": list(results)}


# ── WATCH: register webhook ────────────────────────────────────
@router.post("/watch")
async def watch_repo(req: WatchRequest):
    req.repo = _normalize_repo(req.repo)
    if req.repo in _watches:
        raise HTTPException(status_code=409, detail=f"Already watching {req.repo}")
    secret = secrets.token_hex(32)
    repo_key = req.repo.replace("/", "__")
    base = (req.base_url or "http://localhost:8000").rstrip("/")
    webhook_url = f"{base}/api/v1/webhook/token/{repo_key}"
    headers = {"Authorization": f"token {req.github_token}", "Accept": "application/vnd.github.v3+json"}
    payload = {
        "name": "web", "active": True, "events": ["pull_request"],
        "config": {"url": webhook_url, "content_type": "json", "secret": secret, "insecure_ssl": "0"},
    }
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.post(f"https://api.github.com/repos/{req.repo}/hooks", headers=headers, json=payload)

    if resp.status_code == 422:
        # 422 = stale/duplicate hooks on GitHub.  Purge ALL hooks whose URL
        # matches our sentinel pattern, then retry.
        logger.info(f"[watch] Got 422 for {req.repo} — purging stale hooks")
        async with httpx.AsyncClient(timeout=15.0) as client:
            list_resp = await client.get(f"https://api.github.com/repos/{req.repo}/hooks", headers=headers)
        if list_resp.status_code == 200:
            purged = 0
            async with httpx.AsyncClient(timeout=15.0) as client:
                for existing in list_resp.json():
                    # Delete any hook whose URL contains our webhook pattern
                    hook_url = (existing.get("config") or {}).get("url", "")
                    is_sentinel = "/api/v1/webhook/token/" in hook_url or "/webhook/token/" in hook_url
                    if is_sentinel:
                        del_r = await client.delete(
                            f"https://api.github.com/repos/{req.repo}/hooks/{existing['id']}",
                            headers=headers,
                        )
                        logger.info(f"Purged stale hook #{existing['id']} url={hook_url} ({del_r.status_code})")
                        purged += 1
            logger.info(f"[watch] Purged {purged} stale hooks on {req.repo}, retrying...")
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(f"https://api.github.com/repos/{req.repo}/hooks", headers=headers, json=payload)

    if resp.status_code not in (200, 201):
        try:
            gh_body = resp.json()
            gh_msg = gh_body.get("message", resp.text[:200])
            # GitHub often includes errors[] with more details
            gh_errors = gh_body.get("errors", [])
            if gh_errors:
                gh_msg += " — " + "; ".join(str(e.get("message", e)) for e in gh_errors)
        except Exception:
            gh_msg = resp.text[:200]
        hints = {
            401: "Token invalid or expired.",
            403: "Token needs 'admin:repo_hook' (or 'write:repo_hook') scope and you must be a repo admin.",
            404: "Repo not found or token lacks 'repo' read scope.",
            422: "Validation failed — GitHub could not create the webhook. Check token scopes (needs admin:repo_hook) and repo permissions.",
        }
        hint = hints.get(resp.status_code, "")
        detail = f"GitHub {resp.status_code}: {gh_msg}"
        if hint:
            detail += f" — {hint}"
        logger.warning(f"[watch] Hook creation failed for {req.repo}: {detail}")
        raise HTTPException(status_code=resp.status_code, detail=detail)
    hook = resp.json()
    _watches[req.repo] = {"secret": secret, "token": req.github_token, "hook_id": hook["id"], "webhook_url": webhook_url}
    # Persist to DB so watches survive restarts
    try:
        save_watch(req.repo, hook["id"], webhook_url, req.user_email or "")
    except Exception as exc:
        logger.warning(f"[watch] DB persist failed (non-fatal): {exc}")
    logger.info(f"Watching {req.repo} via hook #{hook['id']} → {webhook_url}")
    return {"repo": req.repo, "webhook_id": hook["id"], "webhook_url": webhook_url, "status": "watching"}


@router.delete("/watch/{owner}/{repo}")
async def unwatch_repo(owner: str, repo: str):
    full = f"{owner}/{repo}"
    watch = _watches.get(full)
    if not watch:
        # Also check DB in case server restarted
        delete_watch(full)
        return {"status": "unwatched", "repo": full}
    headers = {"Authorization": f"token {watch['token']}", "Accept": "application/vnd.github.v3+json"}
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            await client.delete(f"https://api.github.com/repos/{full}/hooks/{watch['hook_id']}", headers=headers)
    except Exception as e:
        logger.warning(f"Hook delete failed (continuing): {e}")
    del _watches[full]
    delete_watch(full)
    return {"status": "unwatched", "repo": full}


@router.get("/watches")
async def list_watches():
    # Merge in-memory watches (have tokens) with DB-persisted watches
    in_mem = {
        repo: {
            "repo": repo,
            "webhook_url": data["webhook_url"],
            "hook_id": data["hook_id"],
            "scan_count": len(_results.get(repo, [])),
            "latest": _results[repo][0] if _results.get(repo) else None,
            "active": True,
        }
        for repo, data in _watches.items()
    }
    # Add DB-only watches (from previous server session) marked as needing reconnect
    try:
        for w in db_get_watches():
            rn = w["repo_name"]
            if rn not in in_mem:
                in_mem[rn] = {
                    "repo": rn,
                    "webhook_url": w["webhook_url"],
                    "hook_id": w["hook_id"],
                    "scan_count": 0,
                    "latest": None,
                    "active": False,  # needs token re-entry to verify signatures
                }
    except Exception as exc:
        logger.warning(f"[watches] DB read failed: {exc}")
    return {"watches": list(in_mem.values())}


@router.get("/watches/{owner}/{repo}/results")
async def get_watch_results(owner: str, repo: str):
    return {"repo": f"{owner}/{repo}", "results": _results.get(f"{owner}/{repo}", [])}


@router.post("/webhook/token/{repo_key}")
async def token_webhook(repo_key: str, request: Request, background_tasks: BackgroundTasks):
    body = await request.body()
    repo = repo_key.replace("__", "/")
    watch = _watches.get(repo)
    if not watch:
        raise HTTPException(status_code=404, detail="Repo not watched")
    if not _verify_sig(body, request.headers.get("X-Hub-Signature-256", ""), watch["secret"]):
        raise HTTPException(status_code=401, detail="Invalid signature")
    event = request.headers.get("X-GitHub-Event", "")
    if event != "pull_request":
        return {"status": "ignored", "event": event}
    payload = json.loads(body)
    action = payload.get("action", "")
    if action not in ("opened", "synchronize", "reopened"):
        return {"status": "ignored", "action": action}
    pr = payload["pull_request"]
    pr_number = pr["number"]
    pr_title = pr.get("title", f"PR #{pr_number}")
    author = pr["user"]["login"]
    headers = {"Authorization": f"token {watch['token']}", "Accept": "application/vnd.github.v3.diff"}
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.get(f"https://api.github.com/repos/{repo}/pulls/{pr_number}", headers=headers)
        diff = resp.text if resp.status_code == 200 else ""
    if not diff:
        return {"status": "error", "detail": "Could not fetch diff"}
    background_tasks.add_task(_run_watch_scan, repo, pr_number, pr_title, diff, author)
    logger.info(f"Webhook triggered scan {repo}#{pr_number}")
    return {"status": "accepted", "pr": pr_number}


# ── ONE-CLICK FIX PR ──────────────────────────────────────────
class CreateFixPRRequest(BaseModel):
    repo: str
    pr_number: int
    filename: str
    patched_source: str
    fix_strategy: str = "sentinel-ai-fix"
    fix_description: str = ""
    finding: dict = {}
    verifier_report: dict = {}
    base_branch: str = "main"
    github_token: str


@router.post("/create-fix-pr")
async def create_fix_pr(req: CreateFixPRRequest):
    """One-click: open a remediation PR on GitHub with the verified patch."""
    from agents.patchforge.tools import create_remediation_pr
    req.repo = _normalize_repo(req.repo)
    owner, name = (req.repo.split("/") + [""])[:2]
    safe_fname = req.filename.replace("/", "-").replace("\\", "-")
    branch = f"sentinel-fix/{safe_fname}-{int(time.time())}"

    fix_candidate = {
        "strategy": req.fix_strategy,
        "description": req.fix_description,
        "confidence": 0.9,
        "patch": {"filename": req.filename, "patched_source": req.patched_source},
    }
    shannon_stub = {
        "shannon_verdict": req.verifier_report.get("shannon_verdict", "INDETERMINATE"),
        "verification_method": req.verifier_report.get("shannon_method", "n/a"),
        "details": req.verifier_report.get("shannon_details", "n/a"),
    }

    req.github_token = get_effective_token(req.github_token, None)
    result = await create_remediation_pr(
        repo_owner=owner,
        repo_name=name,
        branch_name=branch,
        fix_candidate_json=json.dumps(fix_candidate),
        shannon_result_json=json.dumps(shannon_stub),
        original_finding_json=json.dumps(req.finding),
        base_branch=req.base_branch,
        github_token=req.github_token,
        verifier_report=req.verifier_report,
    )
    if not result.get("pr_created"):
        raise HTTPException(status_code=502, detail=result.get("error", "PR creation failed"))
    return result


# ── PATCH ON DEMAND ───────────────────────────────────────────
class PatchRequest(BaseModel):
    finding_json: str
    source_code: str = ""
    filename: str = "unknown"
    repo: str = ""
    llm_provider: Optional[str] = None
    llm_model: Optional[str] = None
    llm_key: Optional[str] = None


@router.post("/patch")
async def patch_finding(req: PatchRequest):
    """Call PatchForge on a single finding and return the best fix candidate."""
    owner, repo_name = (req.repo.split("/") + [""])[:2]
    
    # Resolve token for GitHub fetching if needed
    token = get_effective_token(None, None) # Use global or env token if user token not in req
    
    # If source_code is just a snippet (e.g. < 5 lines or matches evidence), fetch the FULL file
    # This is CRITICAL because PatchForge needs the full file to generate a proper patch.
    if len(req.source_code.splitlines()) < 5 or req.repo:
        logger.info(f"[patch] Source code is short or repo provided. Attempting to fetch full file '{req.filename}' from GitHub.")
        # Try to get the head ref from history or just use main/master
        ref = "main" 
        full_code = await _fetch_github_file(req.repo, req.filename, ref, token)
        if full_code:
            req.source_code = full_code
            logger.info(f"[patch] Successfully fetched full file content ({len(full_code)} bytes)")

    pf_req = AgentRequest(
        agent_id="patchforge",
        task=f"Remediate finding in {req.filename}",
        context={
            "finding_json": req.finding_json,
            "source_code": req.source_code,
            "filename": req.filename,
            "repo_owner": owner,
            "repo_name": repo_name,
            "llm_provider": req.llm_provider,
            "llm_model": req.llm_model,
            "llm_key": req.llm_key,
        },
    )
    pf_res = await _pf.handle_request(pf_req)
    result = _safe_json(pf_res.output)
    if not result:
        raise HTTPException(status_code=500, detail="PatchForge returned no output")
    
    # Include the original source code used for generation so UI can diff correctly
    result["original_source"] = req.source_code
    return result


# ── TEST RESULTS ───────────────────────────────────────────────
@router.get("/test-results")
async def get_test_results():
    """Return latest test_results.json if it exists."""
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "test_results.json")
    if not os.path.isfile(path):
        return JSONResponse(status_code=404, content={"error": "No test results found. Run test_agents.py first."})
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data


@router.get("/history")
async def get_history(limit: int = 50, repo: Optional[str] = None):
    """Return recent scan history from SQLite, with reasoning and findings_count.

    Pass `repo=owner/name` to filter to one repo. Without it, returns the
    global newest-first list.
    """
    with get_db() as conn:
        cursor = conn.cursor()
        if repo:
            cursor.execute(
                "SELECT id, repo_name, pr_number, verdict, confidence, severity, "
                "summary, reasoning_json, attack_classification, risk_score, "
                "findings_count_json, findings_json, timestamp "
                "FROM analysis_logs WHERE repo_name = ? "
                "ORDER BY timestamp DESC LIMIT ?",
                (_normalize_repo(repo), limit),
            )
        else:
            cursor.execute(
                "SELECT id, repo_name, pr_number, verdict, confidence, severity, "
                "summary, reasoning_json, attack_classification, risk_score, "
                "findings_count_json, findings_json, timestamp "
                "FROM analysis_logs ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            )
        rows = cursor.fetchall()

    history = []
    for r in rows:
        d = dict(r)
        d["reasoning"] = _safe_json(d.pop("reasoning_json", "") or "[]") or []
        d["findings_count"] = _safe_json(d.pop("findings_count_json", "") or "{}") or {}
        raw_f = _safe_json(d.pop("findings_json", "") or "{}") or {}
        d["findings"] = _flatten_findings(raw_f.get("archeologist", {}), raw_f.get("shadow_stalker", {}))
        d["pr_url"] = f"https://github.com/{d['repo_name']}/pull/{d['pr_number']}"
        history.append(d)
    return {"history": history, "count": len(history)}



@router.get("/recent-scans")
async def recent_scans(limit: int = 5, user_email: Optional[str] = None):
    """Return top N recent scans (deduped by repo+PR, newest first).
    Used by the Repository tab to show persistent history on page load."""
    scans = get_recent_scans(limit=limit, user_email=user_email or "")
    return {"scans": scans, "count": len(scans)}


@router.get("/history/{owner}/{repo}/{pr_number}")
async def get_history_detail(owner: str, repo: str, pr_number: int):
    """Return full findings + reasoning for a single PR analysis (latest run)."""
    full_repo = f"{owner}/{repo}"
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, repo_name, pr_number, verdict, confidence, severity, "
            "summary, reasoning_json, attack_classification, risk_score, "
            "findings_count_json, findings_json, timestamp "
            "FROM analysis_logs WHERE repo_name = ? AND pr_number = ? "
            "ORDER BY timestamp DESC LIMIT 1",
            (full_repo, pr_number),
        )
        row = cursor.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail=f"No analysis found for {full_repo}#{pr_number}")
    d = dict(row)
    d["reasoning"] = _safe_json(d.pop("reasoning_json", "") or "[]") or []
    d["findings_count"] = _safe_json(d.pop("findings_count_json", "") or "{}") or {}
    d["findings"] = _safe_json(d.pop("findings_json", "") or "{}") or {}
    d["pr_url"] = f"https://github.com/{full_repo}/pull/{pr_number}"
    return d


@router.post("/run-tests")
async def run_tests(background_tasks: BackgroundTasks):
    """Trigger test_agents.py in background and return immediately."""
    script = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "test_agents.py")
    if not os.path.isfile(script):
        raise HTTPException(status_code=404, detail="test_agents.py not found")

    def _run():
        try:
            subprocess.run([sys.executable, script], capture_output=True, timeout=600)
            logger.info("[run-tests] test_agents.py completed")
        except Exception as exc:
            logger.error(f"[run-tests] failed: {exc}")

    background_tasks.add_task(_run)
    return {"status": "running", "message": "Tests started in background. Poll /api/v1/test-results."}


# ── ANALYTICS ─────────────────────────────────────────────────
@router.get("/analytics")
async def get_analytics():
    """Aggregated analytics across all scan history."""
    with get_db() as conn:
        c = conn.cursor()

        # Total scans
        c.execute("SELECT COUNT(*) FROM analysis_logs")
        total_scans = c.fetchone()[0]

        # Verdict distribution
        c.execute("SELECT verdict, COUNT(*) as n FROM analysis_logs GROUP BY verdict")
        verdict_dist = {r["verdict"]: r["n"] for r in c.fetchall()}

        # Avg confidence + avg risk_score
        c.execute("SELECT AVG(confidence), AVG(risk_score) FROM analysis_logs")
        row = c.fetchone()
        avg_confidence = round((row[0] or 0.0) * 100, 1)
        avg_risk_score = round(row[1] or 0.0, 2)

        # Severity totals from findings_count_json
        c.execute("SELECT findings_count_json FROM analysis_logs WHERE findings_count_json IS NOT NULL")
        sev_totals = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for row in c.fetchall():
            fc = _safe_json(row[0] or "{}")
            for k in sev_totals:
                sev_totals[k] += fc.get(k, 0)

        # Attack classifications
        c.execute("""
            SELECT attack_classification, COUNT(*) as n
            FROM analysis_logs
            WHERE attack_classification IS NOT NULL AND attack_classification != ''
            GROUP BY attack_classification
            ORDER BY n DESC
            LIMIT 10
        """)
        attack_classes = [{"name": r["attack_classification"], "count": r["n"]} for r in c.fetchall()]

        # Scans over time — last 30 days, grouped by date
        c.execute("""
            SELECT DATE(timestamp) as day,
                   COUNT(*) as total,
                   SUM(CASE WHEN verdict='BLOCK' THEN 1 ELSE 0 END) as blocks,
                   SUM(CASE WHEN verdict='REVIEW' THEN 1 ELSE 0 END) as reviews,
                   SUM(CASE WHEN verdict='APPROVE' THEN 1 ELSE 0 END) as approves,
                   AVG(risk_score) as avg_risk
            FROM analysis_logs
            WHERE timestamp >= DATE('now', '-30 days')
            GROUP BY day
            ORDER BY day ASC
        """)
        scans_over_time = [
            {
                "date": r["day"],
                "total": r["total"],
                "blocks": r["blocks"],
                "reviews": r["reviews"],
                "approves": r["approves"],
                "avg_risk": round(r["avg_risk"] or 0.0, 2),
            }
            for r in c.fetchall()
        ]

        # Top repos
        c.execute("""
            SELECT repo_name,
                   COUNT(*) as scans,
                   SUM(CASE WHEN verdict='BLOCK' THEN 1 ELSE 0 END) as blocks,
                   AVG(risk_score) as avg_risk
            FROM analysis_logs
            GROUP BY repo_name
            ORDER BY scans DESC
            LIMIT 8
        """)
        top_repos = [
            {
                "repo": r["repo_name"],
                "scans": r["scans"],
                "blocks": r["blocks"],
                "avg_risk": round(r["avg_risk"] or 0.0, 2),
            }
            for r in c.fetchall()
        ]

        # Verdict engine split — verdict_engine is not stored, approximate from confidence distribution
        c.execute("""
            SELECT
                SUM(CASE WHEN confidence >= 0.85 THEN 1 ELSE 0 END) as high_conf,
                SUM(CASE WHEN confidence < 0.85 THEN 1 ELSE 0 END) as low_conf
            FROM analysis_logs
        """)
        conf_row = c.fetchone()
        engine_split = {
            "rule_based": conf_row["high_conf"] or 0,
            "llm_assisted": conf_row["low_conf"] or 0,
        }

        # Patch acceptance from ground_truth_labels
        c.execute("""
            SELECT reaction, COUNT(*) as n
            FROM ground_truth_labels
            GROUP BY reaction
        """)
        reactions = {r["reaction"]: r["n"] for r in c.fetchall()}
        patch_acceptance = {
            "accepted": reactions.get("+1", 0),
            "rejected": reactions.get("-1", 0),
        }
        total_reactions = patch_acceptance["accepted"] + patch_acceptance["rejected"]
        patch_acceptance["acceptance_rate"] = (
            round(patch_acceptance["accepted"] / total_reactions * 100, 1) if total_reactions else None
        )

        # Risk score distribution buckets
        c.execute("""
            SELECT
                SUM(CASE WHEN risk_score >= 15 THEN 1 ELSE 0 END) as critical_risk,
                SUM(CASE WHEN risk_score >= 5 AND risk_score < 15 THEN 1 ELSE 0 END) as medium_risk,
                SUM(CASE WHEN risk_score < 5 THEN 1 ELSE 0 END) as low_risk
            FROM analysis_logs
        """)
        risk_row = c.fetchone()
        risk_dist = [
            {"bucket": "High (≥15)", "count": risk_row["critical_risk"] or 0},
            {"bucket": "Medium (5-15)", "count": risk_row["medium_risk"] or 0},
            {"bucket": "Low (<5)", "count": risk_row["low_risk"] or 0},
        ]

    return {
        "total_scans": total_scans,
        "avg_confidence": avg_confidence,
        "avg_risk_score": avg_risk_score,
        "verdict_distribution": verdict_dist,
        "severity_totals": sev_totals,
        "attack_classifications": attack_classes,
        "scans_over_time": scans_over_time,
        "top_repos": top_repos,
        "engine_split": engine_split,
        "patch_acceptance": patch_acceptance,
        "risk_distribution": risk_dist,
    }


@router.post("/apply-fix")
async def apply_fix(req: FixRequest):
    """Generate a remediation fix and apply it to the GitHub repository."""
    logger.info(f"[apply-fix] START repo={req.repo} pr=#{req.pr_number} file={req.filename}")
    
    owner, repo_name = (req.repo.split("/") + [""])[:2]
    
    # Trigger PatchForge remediation
    pf_req = AgentRequest(
        agent_id="patchforge",
        task=f"Remediate finding in {req.repo}",
        context={
            "finding_json": req.finding_json,
            "source_code": req.source_code,
            "filename": req.filename,
            "repo_owner": owner,
            "repo_name": repo_name,
            "llm_provider": req.llm_provider,
            "llm_model": req.llm_model,
            "llm_key": req.llm_key,
        },
    )
    
    pf_res = await _pf.handle_request(pf_req)
    result = _safe_json(pf_res.output)
    
    if not result.get("success"):
        raise HTTPException(status_code=500, detail=result.get("error", "Remediation failed"))

    # If it's a PR, we can post a suggestion comment
    if req.pr_number:
        try:
            branch = f"sentinel-fix-{secrets.token_hex(4)}"
            best_fix = result.get("selected_fix", {})
            
            # The tool already handles PR creation if repo info is provided
            from agents.patchforge.tools import create_remediation_pr
            
            shannon_res = result.get("verifier_report", {})
            
            pr_res = await create_remediation_pr(
                repo_owner=owner,
                repo_name=repo_name,
                branch_name=branch,
                fix_candidate_json=json.dumps(best_fix),
                shannon_result_json=json.dumps(shannon_res),
                original_finding_json=req.finding_json,
                base_branch="main", # Should ideally be the PR's base
                github_token=req.github_token
            )
            return pr_res
        except Exception as e:
            logger.error(f"[apply-fix] PR creation failed: {e}")
            raise HTTPException(status_code=500, detail=str(e))
            
    return result


@router.post("/suggest-fix")
async def suggest_fix(req: SuggestFixRequest):
    """Post a suggested change comment directly to the GitHub PR."""
    from agents.patchforge.tools import post_github_suggestion
    logger.info(f"[suggest-fix] START repo={req.repo} pr=#{req.pr_number} file={req.filename}")
    
    owner, repo_name = (req.repo.split("/") + [""])[:2]
    
    req.github_token = get_effective_token(req.github_token, None)
    res = await post_github_suggestion(
        repo_owner=owner,
        repo_name=repo_name,
        pr_number=req.pr_number,
        filename=req.filename,
        line=req.line,
        patched_code=req.patched_code,
        github_token=req.github_token,
        description=req.description
    )
    
    if "error" in res:
        raise HTTPException(status_code=500, detail=res["error"])
        
    return res


@router.post("/apply-local-patch")
async def apply_local_patch(req: LocalPatchRequest):
    """Overwrite a local file with the patched version (Local Workspace Mode)."""
    logger.info(f"[local-patch] START file={req.filename}")
    
    # Find the repo root
    root = os.getcwd()
    target_path = os.path.join(root, req.filename)
    
    # Try common workspace structures
    if not os.path.exists(target_path):
        target_path = os.path.join(os.path.dirname(root), req.filename)

    if not os.path.exists(target_path):
         raise HTTPException(status_code=404, detail=f"File not found in local workspace: {req.filename}")

    try:
        with open(target_path, "w", encoding="utf-8") as f:
            f.write(req.patched_source)
        
        logger.info(f"[local-patch] SUCCESS file={target_path}")
        return {"status": "success", "file": target_path}
    except Exception as e:
        logger.error(f"[local-patch] ERROR: {e}")
        raise HTTPException(status_code=500, detail=str(e))



@router.post("/save-token")
async def save_github_token(req: SaveTokenRequest):
    """Encrypt and save the user's GitHub token in the DB."""
    from utils.crypto import encrypt_token
    from storage.db import save_token
    
    try:
        encrypted = encrypt_token(req.github_token)
        save_token(req.user_email, encrypted)
        return {"status": "success", "message": "Token securely stored."}
    except Exception as e:
        logger.error(f"[save-token] Error: {e}")
        raise HTTPException(status_code=500, detail="Failed to store token.")


def get_effective_token(user_token_req: Optional[str], user_email: Optional[str]) -> str:
    """Helper to get token from request or fallback to secure DB storage."""
    if user_token_req and user_token_req.strip():
        return user_token_req
        
    if user_email:
        from storage.db import get_token
        from utils.crypto import decrypt_token
        enc = get_token(user_email)
        if enc:
            token = decrypt_token(enc)
            if token:
                return token
                
    # Check env fallback
    return os.getenv("GITHUB_TOKEN", "")
