"""
GitHub OAuth Connect API

Handles linking a user's local session to their GitHub account via OAuth,
allowing Sentinel-AI to perform actions (like posting reviews or PR comments)
on their behalf.
"""

import httpx
from fastapi import APIRouter, HTTPException
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from typing import Optional, List

from core.config import settings
from storage.db import save_token, get_token
from utils.crypto import encrypt_token, decrypt_token
from utils.logger import logger

router = APIRouter()


class DisconnectRequest(BaseModel):
    email: Optional[str] = None
    user_email: Optional[str] = None


@router.get("/github/auth")
@router.get("/github/connect")
async def github_connect(email: str):
    """Initiate OAuth flow."""
    if not settings.GITHUB_OAUTH_CLIENT_ID:
        raise HTTPException(status_code=500, detail="GitHub OAuth client id not configured in .env")
        
    url = (
        f"https://github.com/login/oauth/authorize"
        f"?client_id={settings.GITHUB_OAUTH_CLIENT_ID}"
        f"&scope=repo,read:org"
        f"&state={email}"
        f"&redirect_uri={settings.GITHUB_OAUTH_REDIRECT_URI}"
    )
    return RedirectResponse(url)


@router.get("/github/callback")
async def github_callback(code: str, state: str):
    """Handle OAuth callback, exchange code for token, and encrypt/store."""
    if not settings.GITHUB_OAUTH_CLIENT_ID or not settings.GITHUB_OAUTH_CLIENT_SECRET:
        raise HTTPException(status_code=500, detail="GitHub OAuth not configured")
        
    url = "https://github.com/login/oauth/access_token"
    payload = {
        "client_id": settings.GITHUB_OAUTH_CLIENT_ID,
        "client_secret": settings.GITHUB_OAUTH_CLIENT_SECRET,
        "code": code,
        "redirect_uri": settings.GITHUB_OAUTH_REDIRECT_URI,
    }
    headers = {"Accept": "application/json"}
    
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(url, json=payload, headers=headers)
            if resp.status_code != 200:
                logger.error(f"[oauth] Token exchange failed: {resp.text}")
                raise HTTPException(status_code=400, detail="OAuth token exchange failed")
                
            data = resp.json()
            access_token = data.get("access_token")
            if not access_token:
                logger.error(f"[oauth] No access token in response: {data}")
                raise HTTPException(status_code=400, detail="No access token returned")
                
            # Encrypt and save token
            enc_token = encrypt_token(access_token)
            save_token(state, enc_token)
            
            logger.info(f"[oauth] Successfully connected GitHub for {state}")
            # Redirect back to frontend Settings or GitHub tab
            return RedirectResponse("http://localhost:5173/?tab=github&status=success")
            
    except Exception as e:
        logger.error(f"[oauth] Exception during callback: {e}")
        return RedirectResponse("http://localhost:5173/?tab=github&status=error")


@router.get("/github/status")
async def github_status(email: str):
    """Get the connection status, user profile, and active installations."""
    enc_token = get_token(email)
    if not enc_token:
        return {"connected": False, "user": None, "installations": []}
        
    token = decrypt_token(enc_token)
    if not token:
        return {"connected": False, "user": None, "installations": []}
        
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
    }
    
    try:
        async with httpx.AsyncClient() as client:
            # 1. Fetch user info
            user_resp = await client.get("https://api.github.com/user", headers=headers)
            if user_resp.status_code != 200:
                return {"connected": False, "user": None, "installations": []}
            user_data = user_resp.json()
            
            # 2. Fetch installations
            inst_resp = await client.get("https://api.github.com/user/installations", headers=headers)
            installations = []
            if inst_resp.status_code == 200:
                installations = inst_resp.json().get("installations", [])
                
            return {
                "connected": True,
                "user": {
                    "login": user_data.get("login"),
                    "avatar_url": user_data.get("avatar_url"),
                    "type": user_data.get("type", "User")
                },
                "installations": installations
            }
    except Exception as e:
        logger.error(f"[github_status] error: {e}")
        return {"connected": False, "user": None, "installations": []}


@router.get("/github/installations")
async def github_installations(email: str):
    """List installations the user has access to."""
    enc_token = get_token(email)
    if not enc_token:
        raise HTTPException(status_code=404, detail="GitHub not connected")
        
    token = decrypt_token(enc_token)
    if not token:
        raise HTTPException(status_code=500, detail="Failed to decrypt token")
        
    url = "https://api.github.com/user/installations"
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
    }
    
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(url, headers=headers)
            if resp.status_code == 200:
                return resp.json()
            raise HTTPException(status_code=resp.status_code, detail="Failed to fetch installations")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/github/disconnect")
async def github_disconnect(req: DisconnectRequest):
    """Delete the user's stored token."""
    email = req.email or req.user_email
    if email:
        save_token(email, "")
    return {"status": "success"}


def normalize_repo_name(repo: str) -> str:
    """Normalize repo name from URL, git format, or standard owner/repo to just 'owner/repo'."""
    repo = repo.strip()
    if not repo:
        return ""
    if "github.com/" in repo:
        repo = repo.split("github.com/")[-1]
    elif "github.com:" in repo:
        repo = repo.split("github.com:")[-1]
    
    repo = repo.lstrip("/")
    if repo.endswith(".git"):
        repo = repo[:-4]
    repo = repo.rstrip("/")
    
    parts = repo.split("/")
    if len(parts) >= 2:
        return f"{parts[-2]}/{parts[-1]}"
    return repo


class PushReportRequest(BaseModel):
    repo: str
    pr_number: int
    email: str


@router.post("/github/push-report")
async def push_github_report(req: PushReportRequest):
    """Generate and push the cumulative scan report to the GitHub Checks tab."""
    enc_token = get_token(req.email)
    if not enc_token:
        raise HTTPException(status_code=404, detail="GitHub account not connected. Please go to the GitHub tab to link your account.")
        
    token = decrypt_token(enc_token)
    if not token:
        raise HTTPException(status_code=500, detail="Failed to decrypt GitHub token")

    norm_repo = normalize_repo_name(req.repo)

    # 1. Fetch latest analysis logs from database for this repo and PR
    from storage.db import get_db
    import json
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, verdict, confidence, severity, summary, reasoning_json, "
            "findings_count_json, findings_json "
            "FROM analysis_logs WHERE repo_name = ? AND pr_number = ? "
            "ORDER BY timestamp DESC LIMIT 1",
            (norm_repo, req.pr_number),
        )
        row = cursor.fetchone()
        
    if not row:
        raise HTTPException(
            status_code=404, 
            detail=f"No local scan history found for {norm_repo} PR #{req.pr_number}. Please run a Scan first!"
        )
        
    scan_data = dict(row)
    raw_findings = json.loads(scan_data.get("findings_json") or "{}")
    if isinstance(raw_findings, dict) and ("archeologist" in raw_findings or "shadow_stalker" in raw_findings):
        from api.routes.scan import _flatten_findings
        findings = _flatten_findings(raw_findings.get("archeologist", {}), raw_findings.get("shadow_stalker", {}))
    elif isinstance(raw_findings, list):
        findings = raw_findings
    else:
        findings = []
        
    verdict = scan_data.get("verdict") or "APPROVE"
    severity = scan_data.get("severity") or "LOW"
    scan_id = scan_data.get("id")

    # 2. Fetch the latest head SHA of the PR from GitHub Pull Request API
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
    }
    pr_url = f"https://api.github.com/repos/{norm_repo}/pulls/{req.pr_number}"
    
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            pr_resp = await client.get(pr_url, headers=headers)
            if pr_resp.status_code != 200:
                raise HTTPException(
                    status_code=pr_resp.status_code,
                    detail=f"Failed to fetch PR #{req.pr_number} metadata from GitHub: {pr_resp.text[:200]}"
                )
            pr_meta = pr_resp.json()
            head_sha = pr_meta.get("head", {}).get("sha")
            if not head_sha:
                raise HTTPException(
                    status_code=400,
                    detail="Could not retrieve head commit SHA of this Pull Request."
                )
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"GitHub connection failed while retrieving head SHA: {exc}"
        )

    # 3. Create the GitHub check run
    from api.github_checks import create_check_run, update_check_run, verdict_to_conclusion
    from utils.check_run_renderer import render_check_run_md, render_check_run_summary
    from core.config import settings
    
    check_token = token
    if settings.GITHUB_APP_ID and settings.GITHUB_PRIVATE_KEY_PATH:
        try:
            from api.github import generate_jwt
            app_jwt = generate_jwt()
            app_headers = {
                "Authorization": f"Bearer {app_jwt}",
                "Accept": "application/vnd.github.v3+json"
            }
            async with httpx.AsyncClient(timeout=10.0) as client:
                inst_url = f"https://api.github.com/repos/{norm_repo}/installation"
                inst_resp = await client.get(inst_url, headers=app_headers)
                if inst_resp.status_code == 200:
                    inst_id = inst_resp.json().get("id")
                    if inst_id:
                        tok_url = f"https://api.github.com/app/installations/{inst_id}/access_tokens"
                        tok_resp = await client.post(tok_url, headers=app_headers)
                        if tok_resp.status_code in (200, 201):
                            check_token = tok_resp.json().get("token")
                            logger.info(f"[github] Successfully retrieved App installation token for Check Runs on {norm_repo}")
        except Exception as e:
            logger.error(f"[github] Failed to resolve App installation token for {norm_repo}: {e}")
            
    # Temporarily force checks to be enabled (in case settings.SENTINEL_GH_CHECKS_ENABLED is false during manual trigger)
    prev_enabled = settings.SENTINEL_GH_CHECKS_ENABLED
    settings.SENTINEL_GH_CHECKS_ENABLED = True
    
    try:
        run_id = await create_check_run(
            repo_full_name=norm_repo,
            head_sha=head_sha,
            token=check_token,
            name="Sentinel-AI Cumulative Report"
        )
        
        # 4. Render markdown parts
        text = render_check_run_md(
            verdict=verdict,
            severity=severity,
            findings=findings,
            scan_id=scan_id,
            dashboard_url=f"http://localhost:5173/?tab=scan&repo={norm_repo}&pr={req.pr_number}"
        )
        
        if not run_id:
            # Fallback to posting a Pull Request Comment and a Commit Status!
            logger.warning(f"[github] Check Runs failed or not permitted on {norm_repo}. Falling back to PR Comment + Commit Status.")
            
            # 4a. Post the markdown report as a Pull Request Comment
            comment_url = f"https://api.github.com/repos/{norm_repo}/issues/{req.pr_number}/comments"
            comment_payload = {"body": text}
            comment_posted = False
            
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(comment_url, headers=headers, json=comment_payload)
                if resp.status_code in (200, 201):
                    comment_posted = True
                    logger.info(f"[github] Successfully posted fallback PR comment on PR #{req.pr_number}")
                else:
                    logger.error(f"[github] Failed to post fallback PR comment: {resp.status_code} {resp.text[:200]}")
                    
            # 4b. Create a Commit Status (success or failure)
            status_url = f"https://api.github.com/repos/{norm_repo}/statuses/{head_sha}"
            state_map = {
                "BLOCK": "failure" if severity in ("CRITICAL", "HIGH") else "error",
                "REVIEW": "pending",
                "APPROVE": "success"
            }
            state = state_map.get(verdict, "success")
            desc = f"Sentinel-AI: {verdict} - {len(findings)} findings found."
            status_payload = {
                "state": state,
                "target_url": f"http://localhost:5173/?tab=scan&repo={norm_repo}&pr={req.pr_number}",
                "description": desc[:139],
                "context": "Sentinel-AI Supply-Chain Guardrail"
            }
            
            status_posted = False
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(status_url, headers=headers, json=status_payload)
                if resp.status_code in (200, 201):
                    status_posted = True
                    logger.info(f"[github] Successfully created fallback commit status for {head_sha[:7]}")
                else:
                    logger.error(f"[github] Failed to create fallback commit status: {resp.status_code} {resp.text[:200]}")
                    
            if not comment_posted and not status_posted:
                raise HTTPException(
                    status_code=500,
                    detail="GitHub App permissions prevented check runs, and PR write access is missing for Comments or Commit Statuses."
                )
                
            msg = "Successfully pushed cumulative report to your Pull Request! "
            if comment_posted:
                msg += "(Posted as PR Comment) "
            if status_posted:
                msg += "(Created Commit Status)"
                
            return {
                "status": "success",
                "check_run_id": None,
                "conclusion": state,
                "message": msg
            }

        # 5. Render summary and update Check Run
        summary = render_check_run_summary(
            verdict=verdict,
            severity=severity,
            findings=findings
        )
        conclusion = verdict_to_conclusion(verdict, severity)
        
        # 6. Update and complete the check run
        ok = await update_check_run(
            repo_full_name=norm_repo,
            check_run_id=run_id,
            token=check_token,
            conclusion=conclusion,
            title="Sentinel-AI Supply-Chain Guardrail",
            summary=summary,
            text=text
        )
        
        if not ok:
            raise HTTPException(
                status_code=500,
                detail="Failed to update/complete the GitHub check run."
            )
            
        return {
            "status": "success",
            "check_run_id": run_id,
            "conclusion": conclusion,
            "message": f"Successfully posted cumulative report to GitHub Checks tab (Check Run ID: {run_id})!"
        }
        
    finally:
        # Restore settings
        settings.SENTINEL_GH_CHECKS_ENABLED = prev_enabled
