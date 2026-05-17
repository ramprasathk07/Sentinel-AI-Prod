from fastapi import APIRouter, Request, HTTPException, BackgroundTasks
import asyncio
import json
import re

from api.github import verify_signature, get_installation_token, fetch_pr_diff, post_pr_comment, get_lockfiles
from storage.logger import save_ground_truth
from storage.db import log_analysis, log_ground_truth_reaction
from utils.logger import logger
from utils.formatter import format_verdict_comment

from agents.archeologist.a2a_wrapper import ArcheologistA2AWrapper
from agents.shadow_stalker.a2a_wrapper import ShadowStalkerA2AWrapper
from agents.lead_warden.a2a_wrapper import LeadWardenA2AWrapper
from core.schemas import AgentRequest

router = APIRouter()

archeologist = ArcheologistA2AWrapper()
shadow_stalker = ShadowStalkerA2AWrapper()
lead_warden = LeadWardenA2AWrapper()


async def process_pull_request(payload: dict, diff_content: str, lockfiles: dict, token: str):
    """Run the agent pipeline and post the verdict."""
    pr_number = payload["pull_request"]["number"]
    repo_name = payload["repository"]["full_name"]
    author = payload["pull_request"]["user"]["login"]
    
    logger.info(f"Starting pipeline for {repo_name} PR #{pr_number}")

    # 1. Prepare requests
    arch_req = AgentRequest(
        agent_id="archeologist",
        task=f"Scan dependencies for PR #{pr_number}",
        context={"diff": diff_content, "lockfiles": lockfiles, "pr_metadata": {"author": author}}
    )
    
    stalker_req = AgentRequest(
        agent_id="shadow_stalker",
        task=f"Perform deep static analysis on PR #{pr_number}",
        context={"diff": diff_content}
    )

    # 2. Run Archeologist & Shadow Stalker in PARALLEL
    logger.info("Invoking Archeologist and Shadow Stalker in parallel...")
    arch_task = asyncio.create_task(archeologist.handle_request(arch_req))
    stalker_task = asyncio.create_task(shadow_stalker.handle_request(stalker_req))
    
    arch_res, stalker_res = await asyncio.gather(arch_task, stalker_task)

    # 3. Feed to Lead Warden
    logger.info("Aggregating findings for Lead Warden...")
    warden_req = AgentRequest(
        agent_id="lead_warden",
        task="Synthesize findings and issue a final verdict.",
        context={
            "archeologist_findings": arch_res.output,
            "shadow_stalker_findings": stalker_res.output,
            "pr_metadata": {"author": author, "repo": repo_name, "pr": pr_number}
        }
    )
    
    warden_res = await lead_warden.handle_request(warden_req)

    # Extract JSON verdict
    try:
        # Search for JSON block
        json_match = re.search(r'\{.*\}', warden_res.output, re.DOTALL)
        if json_match:
            verdict_data = json.loads(json_match.group(0))
        else:
            verdict_data = json.loads(warden_res.output)
    except Exception:
        verdict_data = {
            "verdict": "REVIEW",
            "confidence": 0.5,
            "severity": "UNKNOWN",
            "summary": "Failed to parse JSON output.",
            "raw": warden_res.output
        }

    # 4. Save Ground Truth Locally (JSON Files & SQLite)
    save_ground_truth(
        repo_name=repo_name,
        pr_number=pr_number,
        payload=payload,
        diff_content=diff_content,
        agent_outputs={
            "archeologist": arch_res.dict(),
            "shadow_stalker": stalker_res.dict()
        },
        final_verdict=verdict_data
    )

    log_analysis(
        repo_name=repo_name,
        pr_number=pr_number,
        verdict=verdict_data.get("verdict", "UNKNOWN"),
        confidence=verdict_data.get("confidence", 0.0),
        severity=verdict_data.get("severity", "UNKNOWN"),
        findings={"archeologist": arch_res.output, "shadow_stalker": stalker_res.output}
    )

    # 5. Extract Verdict and Post Comment
    try:
        comment_body = format_verdict_comment(verdict_data)
        await post_pr_comment(repo_name, pr_number, comment_body, token)
        logger.info(f"Pipeline complete for PR #{pr_number}")
    except Exception as e:
        logger.error(f"Failed to post PR comment: {e}")


def handle_issue_comment(payload: dict):
    """Handle thumbs up/down reaction logging from PR comments."""
    action = payload.get("action")
    if action not in ["created", "edited"]:
        return
        
    comment_body = payload.get("comment", {}).get("body", "").strip()
    user_login = payload.get("comment", {}).get("user", {}).get("login")
    
    # Check if this is on a PR (issue_comment event triggers for both issues and PRs)
    if "pull_request" not in payload.get("issue", {}):
        return
        
    repo_name = payload.get("repository", {}).get("full_name")
    pr_number = payload.get("issue", {}).get("number")
    
    reaction = None
    if comment_body in ["+1", "👍", "LGTM"]:
        reaction = "+1"
    elif comment_body in ["-1", "👎", "FP"]:
        reaction = "-1"
        
    if reaction:
        log_ground_truth_reaction(repo_name, pr_number, user_login, reaction)
        logger.info(f"Logged ground truth feedback ({reaction}) for PR #{pr_number} by {user_login}")


@router.post("/")
async def handle_webhook(request: Request, background_tasks: BackgroundTasks):
    """GitHub Webhook Endpoint."""
    
    # Verify signature
    body = await request.body()
    signature = request.headers.get("X-Hub-Signature-256")
    if not verify_signature(body, signature):
        logger.warning("Invalid webhook signature received.")
        raise HTTPException(status_code=401, detail="Invalid signature")

    event = request.headers.get("X-GitHub-Event")
    payload = json.loads(body)
    
    if event == "issue_comment":
        handle_issue_comment(payload)
        return {"status": "accepted", "message": "Comment processed for feedback"}

    if event != "pull_request":
        return {"status": "ignored", "reason": "Not a pull_request event"}

    action = payload.get("action")
    if action not in ["opened", "synchronize"]:
        return {"status": "ignored", "reason": f"Action {action} ignored"}

    installation_id = payload.get("installation", {}).get("id")
    if not installation_id:
        return {"status": "error", "reason": "No installation ID"}

    repo_name = payload["repository"]["full_name"]
    pr_number = payload["pull_request"]["number"]

    logger.info(f"Received PR #{pr_number} webhook for {repo_name} (Action: {action})")

    # Fetch installation token
    try:
        token = await get_installation_token(installation_id)
    except Exception as e:
        logger.error(f"Failed to get installation token: {e}")
        raise HTTPException(status_code=500, detail="Token exchange failed")

    # Fetch PR Diff and Lockfiles
    diff_content = await fetch_pr_diff(repo_name, pr_number, token)
    if not diff_content:
        raise HTTPException(status_code=500, detail="Failed to fetch PR diff")
        
    lockfiles = await get_lockfiles(repo_name, payload["pull_request"]["head"]["sha"], token)

    # Run the processing pipeline in the background so webhook responds 200 OK immediately
    background_tasks.add_task(process_pull_request, payload, diff_content, lockfiles, token)

    return {"status": "accepted", "message": "Pipeline triggered in background"}
