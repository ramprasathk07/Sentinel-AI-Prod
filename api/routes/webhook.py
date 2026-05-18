from fastapi import APIRouter, Request, HTTPException, BackgroundTasks
import asyncio
import json
import re

from api.github import verify_signature, get_installation_token, fetch_pr_diff, post_pr_comment, get_lockfiles, upsert_pr_comment
from storage.logger import save_ground_truth
from storage.db import log_analysis, log_ground_truth_reaction
from utils.logger import logger
from utils.formatter import format_verdict_comment

from agents.archeologist.a2a_wrapper import ArcheologistA2AWrapper
from agents.shadow_stalker.a2a_wrapper import ShadowStalkerA2AWrapper
from agents.lead_warden.a2a_wrapper import LeadWardenA2AWrapper
from core.schemas import AgentRequest
from core.config import settings

# V2 imports
from api.github_checks import create_check_run, update_check_run, verdict_to_conclusion, DISMISS_ACTIONS
from api.github_review import build_check_annotations
from utils.gh_comment_renderer import render_pr_comment
from utils.finding_truncate import truncate_and_rank_findings
from utils.check_run_renderer import render_check_run_md, render_check_run_summary
from agents.pentest.seed_from_scan import build_seed

router = APIRouter()

archeologist = ArcheologistA2AWrapper()
shadow_stalker = ShadowStalkerA2AWrapper()
lead_warden = LeadWardenA2AWrapper()


async def process_pull_request(payload: dict, diff_content: str, lockfiles: dict, token: str, check_run_id: int | None = None):

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

    # 5. Parse findings for rich comments, reviews, and checks
    findings_list = []
    try:
        ss_data = json.loads(arch_res.output) if isinstance(arch_res.output, str) else {}
    except Exception:
        ss_data = {}
    try:
        arch_data = json.loads(stalker_res.output) if isinstance(stalker_res.output, str) else {}
    except Exception:
        arch_data = {}

    # Extract ShadowStalker findings
    for f in ss_data.get("findings", []):
        findings_list.append({
            "file": f.get("file"),
            "line": f.get("line"),
            "technique": f.get("technique"),
            "severity": f.get("severity"),
            "description": f.get("description"),
            "evidence": f.get("evidence"),
        })

    # Extract Archeologist CVE findings
    for f in arch_data.get("cve_findings", []):
        findings_list.append({
            "file": f.get("package_name"),
            "line": 0,
            "technique": f"CVE-{f.get('cve_id')}",
            "severity": f.get("severity", "MEDIUM"),
            "description": f.get("summary", ""),
            "evidence": "",
        })

    # Truncate and rank findings
    truncated_findings, trunc_meta = truncate_and_rank_findings(findings_list)

    # 6. Post rich PR comment (GitGuardian-style)
    scan_id = f"sc_{repo_name.replace('/', '-')}_{pr_number}"
    comment_marker = f"<!-- sentinel-ai:scan-id={scan_id} -->"
    try:
        rich_comment = render_pr_comment(
            verdict=verdict_data.get("verdict", "UNKNOWN"),
            severity=verdict_data.get("severity", "UNKNOWN"),
            findings=truncated_findings,
            scan_id=scan_id,
            repo=repo_name,
            pr_number=pr_number,
            commit_sha=payload["pull_request"]["head"]["sha"],
        )
        await upsert_pr_comment(repo_name, pr_number, rich_comment, comment_marker, token)
        logger.info(f"Upserted rich PR comment for PR #{pr_number}")
    except Exception as e:
        logger.error(f"Failed to post rich PR comment: {e}")

    # 7. Update GitHub Check Run if enabled
    if check_run_id:
        conclusion = verdict_to_conclusion(
            verdict_data.get("verdict", "UNKNOWN"),
            verdict_data.get("severity", "UNKNOWN")
        )
        check_title = "Sentinel-AI Security Analysis"
        check_summary = render_check_run_summary(
            verdict=verdict_data.get("verdict", "UNKNOWN"),
            severity=verdict_data.get("severity", "UNKNOWN"),
            findings=truncated_findings
        )
        check_text = render_check_run_md(
            verdict=verdict_data.get("verdict", "UNKNOWN"),
            severity=verdict_data.get("severity", "UNKNOWN"),
            findings=truncated_findings,
            scan_id=scan_id,
            truncation_meta=trunc_meta
        )
        annotations = build_check_annotations(truncated_findings)
        
        await update_check_run(
            repo_full_name=repo_name,
            check_run_id=check_run_id,
            token=token,
            conclusion=conclusion,
            title=check_title,
            summary=check_summary,
            text=check_text,
            annotations=annotations,
            actions=DISMISS_ACTIONS
        )

        # 8. Check auto-pentest gate
        verdict = verdict_data.get("verdict", "UNKNOWN").upper()
        severity = verdict_data.get("severity", "UNKNOWN").upper()
        if settings.SENTINEL_PENTEST_AUTO and verdict == "BLOCK" and severity in ("HIGH", "CRITICAL"):
            logger.info("Auto-pentest triggered via webhook.")
            try:
                # Import dynamically to avoid circular dependencies
                from agents.pentest.orchestrator import run_pentest
                
                repo_url = f"https://github.com/{repo_name}"
                seed = build_seed(findings_list, repo_url)
                
                # Update check run to running pentest
                await update_check_run(
                    repo_full_name=repo_name,
                    check_run_id=check_run_id,
                    token=token,
                    conclusion="neutral",  # not final yet
                    title="Sentinel-AI Dynamic Pentest Running",
                    summary="Executing dynamic pentest agents on seed hypotheses...",
                    text=check_text + "\n\n---\n⏳ **Auto-Pentest is running in the background...**",
                )
                
                # Execute pentest orchestrator
                pentest_report = await run_pentest(seed)
                
                # Final update to check run including exploited hypotheses
                final_check_text = render_check_run_md(
                    verdict=verdict_data.get("verdict", "UNKNOWN"),
                    severity=verdict_data.get("severity", "UNKNOWN"),
                    findings=truncated_findings,
                    pentest_report=pentest_report,
                    scan_id=scan_id,
                    pentest_session_id=pentest_report.session_id,
                    truncation_meta=trunc_meta
                )
                
                await update_check_run(
                    repo_full_name=repo_name,
                    check_run_id=check_run_id,
                    token=token,
                    conclusion=conclusion,
                    title="Sentinel-AI Security Analysis + Pentest Complete",
                    summary=f"Checks complete. Pentest session: {pentest_report.session_id}",
                    text=final_check_text,
                    annotations=annotations,
                    actions=DISMISS_ACTIONS
                )
                logger.info(f"Auto-pentest complete and check run updated.")
            except Exception as e:
                logger.error(f"Auto-pentest failed: {e}")


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


async def handle_check_run_action(payload: dict, token: str):
    """Handle requested action callback (e.g. Skip buttons) from Checks tab."""
    action = payload.get("action")
    if action != "requested_action":
        return
        
    requested_action = payload.get("requested_action", {})
    action_id = requested_action.get("identifier")
    check_run = payload.get("check_run", {})
    repo_name = payload["repository"]["full_name"]
    check_run_id = check_run.get("id")
    
    logger.info(f"Received check run action {action_id} for check run {check_run_id} on {repo_name}")
    
    # Extract scan ID or run context from output text if stored, else use best effort
    # We can update the check run status to neutral to indicate skipped
    await update_check_run(
        repo_full_name=repo_name,
        check_run_id=check_run_id,
        token=token,
        conclusion="neutral",
        title="Sentinel-AI Check Skipped",
        summary=f"Skipped / Dismissed by user action: {action_id}",
        text=f"This security check run was explicitly skipped/dismissed.\nReason code: `{action_id}`"
    )
    
    # Log to sqlite DB (dismissal column update)
    # Get scan_id from output text if it has a marker
    output_text = check_run.get("output", {}).get("text", "")
    from utils.gh_comment_renderer import extract_scan_id_from_comment
    scan_id = extract_scan_id_from_comment(output_text)
    if scan_id:
        try:
            with get_db() as conn:
                conn.execute(
                    "UPDATE analysis_logs SET dismissal = ? WHERE id = (SELECT id FROM analysis_logs WHERE repo_name = ? ORDER BY timestamp DESC LIMIT 1)",
                    (action_id, repo_name)
                )
                conn.commit()
                logger.info(f"Dismissal logged in DB: {action_id}")
        except Exception as e:
            logger.error(f"Failed to log dismissal: {e}")


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

    installation_id = payload.get("installation", {}).get("id")
    if not installation_id:
        return {"status": "error", "reason": "No installation ID"}

    # Fetch installation token
    try:
        token = await get_installation_token(installation_id)
    except Exception as e:
        logger.error(f"Failed to get installation token: {e}")
        raise HTTPException(status_code=500, detail="Token exchange failed")

    if event == "check_run":
        if payload.get("action") == "requested_action":
            background_tasks.add_task(handle_check_run_action, payload, token)
            return {"status": "accepted", "message": "Check run action queued"}
        return {"status": "ignored", "reason": "Check run event type ignored"}

    if event != "pull_request":
        return {"status": "ignored", "reason": "Not a pull_request event"}

    action = payload.get("action")
    if action not in ["opened", "synchronize"]:
        return {"status": "ignored", "reason": f"Action {action} ignored"}

    repo_name = payload["repository"]["full_name"]
    pr_number = payload["pull_request"]["number"]
    head_sha = payload["pull_request"]["head"]["sha"]

    logger.info(f"Received PR #{pr_number} webhook for {repo_name} (Action: {action})")

    # 1. Create a Check Run in "in_progress" state if checks are enabled
    check_run_id = None
    if settings.SENTINEL_GH_CHECKS_ENABLED:
        check_run_id = await create_check_run(repo_name, head_sha, token)

    # Fetch PR Diff and Lockfiles
    diff_content = await fetch_pr_diff(repo_name, pr_number, token)
    if not diff_content:
        if check_run_id:
            await update_check_run(
                repo_full_name=repo_name,
                check_run_id=check_run_id,
                token=token,
                conclusion="failure",
                title="Sentinel-AI Check Run Error",
                summary="Failed to retrieve pull request diff content."
            )
        raise HTTPException(status_code=500, detail="Failed to fetch PR diff")
        
    lockfiles = await get_lockfiles(repo_name, head_sha, token)

    # Run the processing pipeline in the background so webhook responds 200 OK immediately
    background_tasks.add_task(process_pull_request, payload, diff_content, lockfiles, token, check_run_id)

    return {"status": "accepted", "message": "Pipeline triggered in background"}

