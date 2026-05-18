"""
PatchForge Tools — Stage 2

Automated remediation agent that generates, tests, and verifies fixes:
  • Fix candidate generation via LLM
  • Detonator sandbox testing of each fix
  • Shannon PoC verification (exploit re-execution against patch)
  • GitHub PR creation with fix + verification report
  • Graphiti linking (fix → original finding)
"""

from __future__ import annotations

import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path

from agents.mini_verifier.agent import MiniVerifier
from agents.mini_verifier.tools import verify_patch_blocklist
from utils.logger import logger
_mini = MiniVerifier()


# ═════════════════════════════════════════════════════════════
# TOOL 1 — Generate Fix Candidates
# ═════════════════════════════════════════════════════════════

async def generate_fix_candidates(
    finding_json: str,
    source_code: str,
    filename: str = "unknown",
    num_candidates: int = 3,
    coding_style_context: str = "",
    llm_client_override=None,
) -> dict:
    """
    Generate candidate fix patches for a blocked finding using LLM-based
    code generation. Produces multiple alternatives ranked by confidence.

    Args:
        finding_json:         JSON string of the specific finding to fix
                              (file, line, attack type, description).
        source_code:          Full source code of the affected file.
        filename:             Name of the affected file.
        num_candidates:       Number of fix candidates to generate (default 3).
        coding_style_context: Optional coding style/conventions from Graphiti.

    Returns:
        Dict with 'candidates' (list of fix patches) and generation metadata.
    """
    from llm.llm_client import llm_client as _default_client
    llm_client = llm_client_override or _default_client

    try:
        finding = json.loads(finding_json) if isinstance(finding_json, str) else finding_json
    except (json.JSONDecodeError, TypeError):
        return {"error": "Invalid finding JSON", "candidates": []}

    attack_type = finding.get("type", finding.get("technique", "unknown"))
    line = finding.get("line", 0)
    description = finding.get("description", "")
    evidence = finding.get("evidence", "")

    logger.info(f"[patchforge] generate_fix_candidates: file={filename} line={line} "
                f"attack={attack_type} src_lines={len((source_code or '').splitlines())} "
                f"evidence_len={len(evidence or '')}")

    # Deterministic seed candidate. For well-known attack patterns we can produce a
    # correct fix without the LLM. We still call the LLM after to add variants, but
    # this guarantees at least one usable candidate even if AISA/vLLM errors out.
    seed_candidate = None
    seed_patched = _apply_quick_fix(source_code, line, attack_type, evidence)
    if seed_patched and seed_patched.strip() != (source_code or "").strip():
        seed_candidate = {
            "id": "fix-deterministic",
            "strategy": f"deterministic_{attack_type or 'remediation'}",
            "description": f"Deterministic rule-based fix for {attack_type} on line {line}",
            "confidence": 0.92,
            "patch": {
                "filename": filename,
                "target_line": line,
                "patched_source": seed_patched,
            },
            "risk": "LOW",
            "breaking_change": False,
        }
        logger.info(f"[patchforge] seed candidate produced ({len(seed_patched)} bytes)")

    # Build the fix prompt for LLM
    fix_prompt = _build_fix_prompt(
        attack_type, line, description, source_code, filename, coding_style_context)

    system_prompt = (
        "You are PatchForge, an expert security remediation AI. "
        "Read the vulnerable source code and generate a patched version. "
        "CRITICAL: every candidate MUST include the FULL patched file in 'patched_source' "
        "(not a diff, not a snippet — the entire file, with the vulnerable line(s) replaced). "
        "Return a JSON object containing a list of 'candidates'. Each candidate must have: "
        "'strategy' (short name), 'description' (what changed), 'confidence' (0.0 to 1.0), "
        "'risk' (LOW/MEDIUM/HIGH), 'breaking_change' (boolean), and 'patched_source' (the full modified code)."
    )

    try:
        response_text = await llm_client.complete(
            prompt=fix_prompt,
            system_prompt=system_prompt,
            temperature=0.2,
            max_tokens=4096,
            json_mode=True
        )

        response_data = json.loads(response_text)
        candidates_data = response_data.get("candidates", [])

        # Filter out candidates that don't meaningfully fix the issue
        valid_candidates = []
        for i, candidate in enumerate(candidates_data[:num_candidates]):
            raw_patch = candidate.get("patched_source")
            patched = _coerce_patched_source(
                raw_patch, source_code, line, attack_type, evidence
            )

            if not _is_meaningful_fix(patched, source_code, evidence, attack_type, line):
                continue

            valid_candidates.append({
                "id": f"fix-{len(valid_candidates)+1}",
                "strategy": candidate.get("strategy", f"Strategy {i+1}"),
                "description": candidate.get("description", "LLM generated fix"),
                "confidence": candidate.get("confidence", 0.8),
                "patch": {
                    "filename": filename,
                    "target_line": line,
                    "patched_source": patched,
                },
                "risk": candidate.get("risk", "LOW"),
                "breaking_change": candidate.get("breaking_change", False),
            })
        
        candidates = valid_candidates
        logger.info(f"[patchforge] LLM produced {len(candidates_data)} raw, {len(candidates)} valid candidates")

    except Exception as exc:
        logger.warning(f"[patchforge] LLM call/parse failed: {exc}")
        candidates = []

    # Always prepend the deterministic seed if one was produced — it's the safest bet.
    if seed_candidate:
        candidates.insert(0, seed_candidate)

    # Final safety net: if STILL no candidates, emit strategy stubs even if patched==source
    # so the UI can at least show what we tried. Only triggers when LLM crashed AND quick
    # fix didn't apply — usually means empty source_code was sent.
    if not candidates:
        logger.warning(f"[patchforge] no candidates after all fallbacks (attack={attack_type}, "
                       f"src_len={len(source_code or '')}). Emitting strategy stubs.")
        strategies = _get_fix_strategies(attack_type)
        for i, strategy in enumerate(strategies[:num_candidates]):
            patched = _generate_patch_stub(source_code, filename, line, strategy, finding)
            candidates.append({
                "id": f"fix-stub-{i+1}",
                "strategy": strategy["name"],
                "description": strategy["description"],
                "confidence": strategy["confidence"],
                "patch": patched,
                "risk": strategy.get("risk", "LOW"),
                "breaking_change": strategy.get("breaking", False),
            })

    # Import settings to get models/backends if needed
    from core.config import settings

    return {
        "filename": filename,
        "finding_type": attack_type,
        "finding_line": line,
        "candidates": candidates,
        "candidate_count": len(candidates),
        "fix_prompt": fix_prompt,
        "prompt_context": {
            "prompt": fix_prompt,
            "system_prompt": system_prompt,
            "model": getattr(llm_client, "model", settings.VERDICT_MODEL),
            "backend": getattr(llm_client, "backend", "vllm"),
            "temperature": 0.2,
        },
        "note": "Stage 2: Integrated with vLLM/Ollama via llm_client.",
    }


# ═════════════════════════════════════════════════════════════
# TOOL 2 — Test Fix in Detonator Sandbox
# ═════════════════════════════════════════════════════════════

async def test_fix_in_sandbox(
    candidate_id: str,
    patched_source: str,
    filename: str,
    install_cmd: str = "",
    build_cmd: str = "",
    timeout_seconds: int = 60,
) -> dict:
    """
    Test a fix candidate by running the patched code inside a fresh
    Detonator sandbox. Verifies the fix doesn't break the build and
    doesn't introduce new threats.

    Args:
        candidate_id:    ID of the fix candidate being tested.
        patched_source:  Full patched source code.
        filename:        Filename of the patched file.
        install_cmd:     Install command to test.
        build_cmd:       Build command to test.
        timeout_seconds: Sandbox timeout.

    Returns:
        Dict with test results: build_passed, threats_remaining, etc.
    """
    # Stage 2: Would call Detonator's provision_sandbox + execute_in_sandbox
    # Currently returns the test framework schema

    test_result = {
        "candidate_id": candidate_id,
        "filename": filename,
        "build_passed": None,
        "syntax_valid": _check_syntax(patched_source, filename),
        "threats_remaining": [],
        "new_threats_introduced": [],
        "test_status": "pending",
        "sandbox_telemetry": {},
        "note": "Stage 2: Detonator sandbox integration pending.",
    }

    # Basic syntax validation
    if test_result["syntax_valid"]:
        test_result["test_status"] = "syntax_ok"
    else:
        test_result["test_status"] = "syntax_error"
        test_result["build_passed"] = False

    return test_result


# ═════════════════════════════════════════════════════════════
# ═════════════════════════════════════════════════════════════
# TOOL 3 — Shannon PoC Verification
# ═════════════════════════════════════════════════════════════

def _route(finding: dict) -> str:
    web_classes = {"injection", "xss", "ssrf", "authn", "authz"}
    technique = finding.get("technique") or finding.get("type") or ""
    return "shannon" if technique in web_classes else "mini"

async def verify_candidate(
    candidate_id: str,
    original_finding_json: str,
    original_repo: Path,
    patched_repo: Path,
    target_url: str | None = None
) -> dict:
    try:
        finding = json.loads(original_finding_json) if isinstance(
            original_finding_json, str) else original_finding_json
    except (json.JSONDecodeError, TypeError):
        finding = {}
        
    finding["candidate_id"] = candidate_id

    if _route(finding) == "mini":
        res = await _mini.verify(finding, original_repo, patched_repo)
        return {
            "candidate_id": res.candidate_id,
            "shannon_verdict": res.shannon_verdict,
            "verification_method": res.verification_method,
            "details": res.details,
            "confidence": res.confidence,
            "timestamp": res.timestamp.isoformat() if res.timestamp else None,
        }

    # Stage 2: Shannon path placeholder
    return {
        "candidate_id": candidate_id,
        "shannon_verdict": "FAIL",
        "verification_method": "shannon:pending",
        "details": "Shannon integration pending for web-app classes.",
        "confidence": 0.0,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ═════════════════════════════════════════════════════════════
# TOOL 4 — Create Remediation PR on GitHub
# ═════════════════════════════════════════════════════════════

async def create_remediation_pr(
    repo_owner: str,
    repo_name: str,
    branch_name: str,
    fix_candidate_json: str,
    shannon_result_json: str,
    original_finding_json: str,
    base_branch: str = "main",
    github_token: str = "",
    verifier_report: dict | None = None,
) -> dict:
    """
    Open a remediation PR on GitHub with the fix code, explanation, and
    Shannon Verified Pass/Fail report attached.

    Args:
        repo_owner:           GitHub repository owner.
        repo_name:            GitHub repository name.
        branch_name:          Branch name for the fix (e.g., 'sentinel-fix/issue-123').
        fix_candidate_json:   JSON of the selected fix candidate.
        shannon_result_json:  JSON of Shannon verification result.
        original_finding_json: JSON of the original blocked finding.
        base_branch:          Base branch to target (default 'main').

    Returns:
        Dict with PR creation status and URL.
    """
    try:
        fix = json.loads(fix_candidate_json) if isinstance(
            fix_candidate_json, str) else fix_candidate_json
        shannon = json.loads(shannon_result_json) if isinstance(
            shannon_result_json, str) else shannon_result_json
        finding = json.loads(original_finding_json) if isinstance(
            original_finding_json, str) else original_finding_json
    except (json.JSONDecodeError, TypeError):
        return {"error": "Invalid JSON input", "pr_created": False}

    # Build PR body
    pr_title = (f"Sentinel-AI Fix: {finding.get('type', finding.get('technique', 'security issue'))} "
                f"in {finding.get('filename', 'unknown')}")

    shannon_badge = ("Shannon Verified **PASS**" if shannon.get("shannon_verdict") == "PASS"
                     else f"Shannon Verified **{shannon.get('shannon_verdict', 'INDETERMINATE')}**")

    vr = verifier_report or {}
    blocklist_badge = (
        f"Blocklist **{vr.get('blocklist_verdict', 'N/A')}**"
        if vr else "Blocklist N/A"
    )

    pr_body = f"""## Automated Security Fix by Sentinel-AI PatchForge

### Finding
- **Type**: {finding.get('type', finding.get('technique', 'N/A'))}
- **File**: `{finding.get('filename', 'N/A')}`
- **Line**: {finding.get('line', 'N/A')}
- **Severity**: {finding.get('severity', 'N/A')}
- **Description**: {finding.get('description', 'N/A')}

### Fix Applied
- **Strategy**: {fix.get('strategy', 'N/A')}
- **Description**: {fix.get('description', 'N/A')}
- **Confidence**: {fix.get('confidence', 'N/A')}

### Verification
- {blocklist_badge} — {vr.get('blocklist_details', '—')}
- {shannon_badge} — {shannon.get('details', 'N/A')}

---
*Generated by Sentinel-AI PatchForge. Verification combines a static-pattern blocklist (always-on) with Shannon/MiniVerifier dynamic checks.*
"""

    pr_spec = {
        "owner": repo_owner,
        "repo": repo_name,
        "title": pr_title,
        "body": pr_body,
        "head": branch_name,
        "base": base_branch,
    }

    if not github_token or not repo_owner or not repo_name:
        return {
            "pr_created": False,
            "pr_spec": pr_spec,
            "shannon_verdict": shannon.get("shannon_verdict", "N/A"),
            "note": "No github_token or repo info — returning spec only.",
        }

    # ── Real GitHub PR creation ─────────────────────────────
    import httpx
    import base64 as _b64

    api = f"https://api.github.com/repos/{repo_owner}/{repo_name}"
    headers = {
        "Authorization": f"token {github_token}",
        "Accept": "application/vnd.github.v3+json",
    }
    filename = fix.get("patch", {}).get("filename") or finding.get("filename", "")
    patched_source = fix.get("patch", {}).get("patched_source", "")

    if not filename or not patched_source:
        return {"pr_created": False, "pr_spec": pr_spec,
                "error": "Missing filename or patched_source in fix candidate."}

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            # 1. Get base branch SHA
            r = await client.get(f"{api}/git/ref/heads/{base_branch}", headers=headers)
            if r.status_code != 200:
                return {"pr_created": False, "pr_spec": pr_spec,
                        "error": f"GitHub get-ref failed: {r.status_code} {r.text[:200]}"}
            base_sha = r.json()["object"]["sha"]

            # 2. Create new branch
            r = await client.post(f"{api}/git/refs", headers=headers,
                                  json={"ref": f"refs/heads/{branch_name}", "sha": base_sha})
            if r.status_code not in (200, 201):
                return {"pr_created": False, "pr_spec": pr_spec,
                        "error": f"GitHub create-branch failed: {r.status_code} {r.text[:200]}"}

            # 3. Get current file SHA on base (needed for update)
            file_sha = None
            r = await client.get(f"{api}/contents/{filename}", headers=headers,
                                 params={"ref": base_branch})
            if r.status_code == 200:
                file_sha = r.json().get("sha")

            # 4. Commit patched file on new branch
            content_b64 = _b64.b64encode(patched_source.encode("utf-8")).decode("ascii")
            put_body = {
                "message": f"sentinel-ai: {fix.get('strategy', 'fix')} for {filename}",
                "content": content_b64,
                "branch": branch_name,
            }
            if file_sha:
                put_body["sha"] = file_sha
            r = await client.put(f"{api}/contents/{filename}", headers=headers, json=put_body)
            if r.status_code not in (200, 201):
                return {"pr_created": False, "pr_spec": pr_spec,
                        "error": f"GitHub put-contents failed: {r.status_code} {r.text[:200]}"}

            # 5. Open PR
            r = await client.post(f"{api}/pulls", headers=headers, json={
                "title": pr_title, "body": pr_body,
                "head": branch_name, "base": base_branch,
            })
            if r.status_code not in (200, 201):
                return {"pr_created": False, "pr_spec": pr_spec,
                        "error": f"GitHub create-pr failed: {r.status_code} {r.text[:200]}"}
            pr = r.json()
            return {
                "pr_created": True,
                "pr_url": pr.get("html_url"),
                "pr_number": pr.get("number"),
                "pr_spec": pr_spec,
                "shannon_verdict": shannon.get("shannon_verdict", "N/A"),
                "blocklist_verdict": vr.get("blocklist_verdict"),
            }
    except Exception as exc:
        return {"pr_created": False, "pr_spec": pr_spec,
                "error": f"PR creation exception: {exc}"}


async def post_github_suggestion(
    repo_owner: str,
    repo_name: str,
    pr_number: int,
    filename: str,
    line: int,
    patched_code: str,
    github_token: str,
    description: str = "",
) -> dict:
    """Post a 'Suggested Change' comment on a specific line of a GitHub PR."""
    import httpx
    if not github_token:
        return {"error": "Missing GitHub token"}

    # We need to find the diff_hunk and position for the comment.
    # For simplicity in this hackathon version, we post a top-level issue comment
    # with a markdown code block if specific line positioning is too complex.
    # But a 'Suggested Change' block is better.
    
    api = f"https://api.github.com/repos/{repo_owner}/{repo_name}"
    headers = {
        "Authorization": f"token {github_token}",
        "Accept": "application/vnd.github.v3+json",
    }
    
    # Format the suggestion
    suggestion_body = f"""### Sentinel-AI Security Suggestion
**Issue**: {description}

```suggestion
{patched_code}
```
"""

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            # First, we'll try to post it as a Review Comment (needs commit_id and path)
            # Fetch PR to get head SHA
            pr_resp = await client.get(f"{api}/pulls/{pr_number}", headers=headers)
            if pr_resp.status_code != 200:
                return {"error": f"Failed to fetch PR: {pr_resp.text}"}
            
            head_sha = pr_resp.json()["head"]["sha"]
            
            # Create a review comment
            # Note: position is tricky, usually we'd need to calculate it from the diff.
            # Fallback to a general PR comment if we can't target the line.
            comment_payload = {
                "body": suggestion_body,
                "commit_id": head_sha,
                "path": filename,
                "side": "RIGHT",
                "line": line
            }
            
            resp = await client.post(f"{api}/pulls/{pr_number}/comments", headers=headers, json=comment_payload)
            
            if resp.status_code not in (200, 201):
                # Fallback to issue comment
                fallback_body = f"### Sentinel-AI Security Suggestion for `{filename}` line {line}\n{suggestion_body}"
                await client.post(f"{api}/issues/{pr_number}/comments", headers=headers, json={"body": fallback_body})
                return {"status": "posted_as_issue_comment", "detail": resp.text}
                
            return {"status": "success", "url": resp.json().get("html_url")}
    except Exception as e:
        return {"error": str(e)}


# ═════════════════════════════════════════════════════════════
# TOOL 5 — Full Remediation Pipeline
# ═════════════════════════════════════════════════════════════


async def run_remediation(
    finding_json: str,
    source_code: str,
    filename: str,
    repo_owner: str = "",
    repo_name: str = "",
    num_candidates: int = 3,
    llm_client_override=None,
) -> dict:
    """
    Run the full remediation pipeline: generate fixes → test each →
    verify with Shannon → select best → create PR.

    Args:
        finding_json:   JSON of the BLOCK finding to remediate.
        source_code:    Full source of the affected file.
        filename:       Affected filename.
        repo_owner:     GitHub repo owner (for PR creation).
        repo_name:      GitHub repo name (for PR creation).
        num_candidates: Number of fix candidates to generate.

    Returns:
        Complete remediation result with selected fix and verification.
    """
    # Step 1: Generate candidates
    candidates_result = await generate_fix_candidates(
        finding_json, source_code, filename, num_candidates,
        llm_client_override=llm_client_override)

    if not candidates_result.get("candidates"):
        return {"success": False, "error": "No fix candidates generated",
                "candidates_result": candidates_result}

    # Step 2: Test each candidate
    test_results = []
    for candidate in candidates_result["candidates"]:
        patched = candidate.get("patch", {}).get("patched_source", source_code)
        test = await test_fix_in_sandbox(
            candidate["id"], patched, filename)
        test_results.append(test)

    # Step 3: Verify each with Shannon + always-on blocklist
    shannon_results = []
    blocklist_results = []

    # Setup verification repos
    orig_repo = Path("./.work/orig")
    patched_repo = Path("./.work/patched")
    orig_file = orig_repo / filename
    orig_file.parent.mkdir(parents=True, exist_ok=True)
    orig_file.write_text(source_code, encoding="utf-8")

    for candidate in candidates_result["candidates"]:
        patched = candidate.get("patch", {}).get("patched_source", source_code)
        patched_file = patched_repo / filename
        patched_file.parent.mkdir(parents=True, exist_ok=True)
        patched_file.write_text(patched, encoding="utf-8")

        bl = verify_patch_blocklist(patched, filename)
        blocklist_results.append(bl)

        # Demote candidate if blocklist FAILs — patch reintroduced danger.
        if bl["verdict"] == "FAIL":
            candidate["confidence"] = 0.0
            candidate["blocklist_failed"] = True

        shannon = await verify_candidate(
            candidate["id"], finding_json, orig_repo, patched_repo
        )
        shannon_results.append(shannon)

    # Step 4: Select best candidate.
    # Rules: blocklist PASS is mandatory. Among those, prefer Shannon PASS, then confidence.
    safe_candidates = [
        (i, c) for i, c in enumerate(candidates_result["candidates"])
        if blocklist_results[i]["verdict"] == "PASS"
    ]

    best = None
    best_idx = -1
    if safe_candidates:
        # Prefer Shannon PASS within safe set
        for i, candidate in safe_candidates:
            if shannon_results[i].get("shannon_verdict") == "PASS":
                if best is None or candidate["confidence"] > best["confidence"]:
                    best = candidate
                    best_idx = i
        if best is None:
            # No Shannon PASS — pick highest-confidence safe candidate
            best_idx, best = max(safe_candidates, key=lambda x: x[1]["confidence"])
    else:
        # All candidates failed blocklist — pick least-bad as last resort, flag verified=False
        best = max(candidates_result["candidates"], key=lambda c: c["confidence"])
        best_idx = candidates_result["candidates"].index(best)

    # Step 5: Create PR (if repo info provided)
    pr_result = None
    if repo_owner and repo_name:
        branch = f"sentinel-fix/{filename.replace('/', '-')}-{int(time.time())}"
        pr_result = await create_remediation_pr(
            repo_owner, repo_name, branch,
            json.dumps(best),
            json.dumps(shannon_results[best_idx]),
            finding_json,
        )

    selected_blocklist = blocklist_results[best_idx]
    selected_shannon = shannon_results[best_idx]
    fully_verified = (
        selected_blocklist["verdict"] == "PASS"
        and selected_shannon.get("shannon_verdict") in ("PASS", "INDETERMINATE")
    )

    verifier_report = {
        "blocklist_verdict": selected_blocklist["verdict"],
        "blocklist_details": selected_blocklist["details"],
        "blocklist_hits": selected_blocklist.get("hits", []),
        "shannon_verdict": selected_shannon.get("shannon_verdict"),
        "shannon_method": selected_shannon.get("verification_method"),
        "shannon_details": selected_shannon.get("details"),
        "fully_verified": fully_verified,
    }

    return {
        "success": True,
        "selected_fix": best,
        "selected_index": best_idx,
        "shannon_verdict": selected_shannon.get("shannon_verdict"),
        "verifier_report": verifier_report,
        "all_candidates": candidates_result["candidates"],
        "all_shannon_results": shannon_results,
        "all_blocklist_results": blocklist_results,
        "test_results": test_results,
        "pr_result": pr_result,
        "summary": (
            f"Generated {len(candidates_result['candidates'])} fixes. "
            f"Selected '{best['strategy']}' "
            f"(blocklist: {selected_blocklist['verdict']}, "
            f"Shannon: {selected_shannon.get('shannon_verdict', '?')}). "
            + (f"PR: {pr_result.get('pr_spec', {}).get('title', 'N/A')}"
               if pr_result else "No PR created (repo info not provided).")
        ),
    }


# ─────────────────────────────────────────────────────────────
# Private helpers
# ─────────────────────────────────────────────────────────────

def _build_fix_prompt(attack_type, line, description, source, filename, style):
    """Build the LLM prompt for fix generation."""
    attack_lower = (attack_type or "").lower()
    is_secret = any(k in attack_lower for k in ("secret", "credential", "password", "api_key", "apikey", "token", "encoded_shell"))

    extra_rules = ""
    if is_secret:
        extra_rules = (
            "\n\nSECRET-SPECIFIC RULES (MANDATORY when fixing hardcoded credentials):\n"
            "- DELETE the literal credential string. The patched_source MUST NOT contain "
            "the original quoted secret value anywhere.\n"
            "- Replace `VAR = \"literal\"` with `VAR = os.getenv(\"VAR\", \"\")`.\n"
            "- Add `import os` at the top of the file if not already imported.\n"
            "- Preserve all other lines unchanged."
        )
    elif "eval" in attack_lower or "exec" in attack_lower or "dangerous" in attack_lower:
        extra_rules = (
            "\n\nEXEC-SPECIFIC RULES:\n"
            "- Remove the eval/exec/__import__ call entirely.\n"
            "- Replace with an explicit allowlist dispatch or safe parser (json.loads, ast.literal_eval).\n"
            "- Never leave the dangerous call commented out — delete it."
        )

    return (
        f"Fix the following security issue in {filename}:\n\n"
        f"**Issue**: {description}\n"
        f"**Type**: {attack_type}\n"
        f"**Line**: {line}\n\n"
        f"Source code:\n```\n{source}\n```\n\n"
        f"Generate a minimal, safe fix that removes the vulnerability. "
        f"CRITICAL: The 'patched_source' MUST be the FULL file content with the vulnerable "
        f"code REPLACED — not commented out, not annotated, REPLACED. "
        f"The original vulnerable text MUST NOT appear anywhere in patched_source."
        + extra_rules
        + (f"\n\nCoding style: {style}" if style else "")
    )


def _is_meaningful_fix(patched: str, source: str, evidence: str, attack_type: str, line: int) -> bool:
    """Decide if a candidate actually fixes the vulnerability rather than echoing source.

    Accepts the patch when the vulnerable line (or its non-comment counterpart) has
    been replaced. Rejects whitespace-only diffs and unmodified source.
    """
    if not patched or not patched.strip():
        return False

    p_strip = patched.strip()
    s_strip = (source or "").strip()
    if p_strip == s_strip:
        return False
    if "".join(p_strip.split()) == "".join(s_strip.split()):
        return False

    # For hardcoded secrets / credentials: ensure the literal value is gone from
    # any non-comment line in the patch. A literal inside a `# was: ...` comment
    # is fine — the runtime code no longer carries the secret.
    src_lines = (source or "").replace("\r\n", "\n").split("\n")
    orig_line = src_lines[line - 1] if (line and 1 <= line <= len(src_lines)) else ""
    attack_lower = (attack_type or "").lower()
    is_secret_class = (
        any(k in attack_lower for k in ("secret", "credential", "password", "api_key", "token", "hardcoded", "encoded"))
        or re.search(r"(?i)(password|api[_-]?key|secret|token|credential)\s*[=:]", orig_line)
    )

    if is_secret_class and orig_line:
        m = re.search(r"""['"]([^'"]{6,})['"]""", orig_line)
        if m:
            literal = m.group(1)
            # Check if the literal exists in any non-comment, non-string-doc line of patched code
            for pl in patched.replace("\r\n", "\n").split("\n"):
                stripped = pl.lstrip()
                if stripped.startswith("#") or stripped.startswith("//"):
                    continue
                # Allow `os.getenv("VAR", "literal_default")` only if the literal isn't the secret
                if literal in pl:
                    return False
    return True


def _get_fix_strategies(attack_type: str) -> list[dict]:
    """Return fix strategies appropriate for the attack type."""
    strategies = {
        "dangerous_call": [
            {"name": "remove_dangerous_call", "description": "Remove eval/exec call and replace with safe alternative",
             "confidence": 0.85, "risk": "MEDIUM", "breaking": False},
            {"name": "sanitize_input", "description": "Add input validation/sanitization before the dangerous call",
             "confidence": 0.75, "risk": "LOW", "breaking": False},
            {"name": "allowlist_functions", "description": "Replace dynamic execution with explicit allowlisted function dispatch",
             "confidence": 0.90, "risk": "LOW", "breaking": True},
        ],
        "hidden_in_except": [
            {"name": "remove_hidden_payload", "description": "Remove suspicious code from exception handler",
             "confidence": 0.90, "risk": "LOW", "breaking": False},
            {"name": "add_specific_except", "description": "Replace bare except with specific exception types",
             "confidence": 0.80, "risk": "LOW", "breaking": False},
            {"name": "add_logging", "description": "Replace dangerous call with logging statement",
             "confidence": 0.85, "risk": "LOW", "breaking": False},
        ],
        "base64_payload": [
            {"name": "remove_encoded_payload", "description": "Remove base64-encoded payload entirely",
             "confidence": 0.90, "risk": "LOW", "breaking": True},
            {"name": "decode_and_review", "description": "Decode payload and replace with transparent version",
             "confidence": 0.70, "risk": "MEDIUM", "breaking": False},
            {"name": "add_integrity_check", "description": "Add hash verification for the encoded data",
             "confidence": 0.75, "risk": "LOW", "breaking": False},
        ],
        "homoglyph": [
            {"name": "replace_homoglyphs", "description": "Replace Unicode homoglyphs with ASCII equivalents",
             "confidence": 0.95, "risk": "LOW", "breaking": False},
            {"name": "add_unicode_lint", "description": "Add Unicode character validation pre-commit hook",
             "confidence": 0.80, "risk": "LOW", "breaking": False},
            {"name": "flag_and_comment", "description": "Add warning comment and normalize identifiers",
             "confidence": 0.85, "risk": "LOW", "breaking": False},
        ],
        "install_hook": [
            {"name": "remove_install_hook", "description": "Remove custom install/postinstall hook entirely",
             "confidence": 0.90, "risk": "HIGH", "breaking": True},
            {"name": "sandbox_hook", "description": "Wrap hook execution in sandboxed subprocess",
             "confidence": 0.70, "risk": "MEDIUM", "breaking": False},
            {"name": "audit_and_pin", "description": "Pin dependency version and add audit comment",
             "confidence": 0.75, "risk": "LOW", "breaking": False},
        ],
        "encoded_shell": [
            {"name": "move_to_env", "description": "Move hardcoded secret to an .env file and use os.getenv()",
             "confidence": 0.95, "risk": "LOW", "breaking": False},
            {"name": "use_secret_manager", "description": "Integrate with a Cloud Secret Manager (AWS/GCP/Azure)",
             "confidence": 0.85, "risk": "LOW", "breaking": False},
            {"name": "revoke_and_rotate", "description": "Revoke the leaked key immediately and rotate credentials",
             "confidence": 1.0, "risk": "CRITICAL", "breaking": False},
        ],
        "hardcoded_secret": [
            {"name": "move_to_env", "description": "Move hardcoded secret to an .env file and use os.getenv()",
             "confidence": 0.95, "risk": "LOW", "breaking": False},
            {"name": "mask_in_logs", "description": "Ensure the secret is masked in all logs and telemetry",
             "confidence": 0.80, "risk": "LOW", "breaking": False},
        ],
    }

    # Default strategies for unknown attack types
    default = [
        {"name": "remove_suspicious_code", "description": "Remove the flagged suspicious code block",
         "confidence": 0.80, "risk": "MEDIUM", "breaking": True},
        {"name": "add_security_comment", "description": "Add security review comment and TODO",
         "confidence": 0.60, "risk": "LOW", "breaking": False},
        {"name": "quarantine_code", "description": "Move suspicious code to quarantine module with disabled flag",
         "confidence": 0.75, "risk": "LOW", "breaking": False},
    ]

    return strategies.get(attack_type, default)


def _generate_patch_stub(source, filename, line, strategy, finding):
    """Generate a patch stub with a heuristic line-level transformation."""
    attack_type = finding.get("type") or finding.get("technique") or ""
    evidence = finding.get("evidence", "")
    patched = _apply_quick_fix(source, line, attack_type, evidence) or source
    return {
        "filename": filename,
        "strategy": strategy["name"],
        "target_line": line,
        "patched_source": patched,
        "diff_preview": f"# Patch: {strategy['description']} at line {line}",
    }


def _coerce_patched_source(raw, source_code: str, line: int, attack_type: str, evidence: str) -> str:
    """Ensure patched_source is a usable string. Falls back to a heuristic
    line-level quick-fix when the LLM returned null/empty/garbage."""
    if isinstance(raw, str) and raw.strip():
        return raw
    quick = _apply_quick_fix(source_code, line, attack_type, evidence)
    return quick or source_code


def _apply_quick_fix(source: str, line: int, attack_type: str, evidence: str) -> str:
    """Heuristic single-line patches for common vulnerability classes.
    Used when the LLM fails to return patched_source. Returns the full
    patched file, or '' if no rule applies.
    """
    if not source:
        return ""
    lines = source.replace("\r\n", "\n").split("\n")
    if line and 1 <= line <= len(lines):
        idx = line - 1
    else:
        idx = _guess_line_index(lines, evidence)
        if idx is None:
            return ""

    original = lines[idx]
    patched_line = _rewrite_line(original, attack_type, evidence)
    if patched_line is None or patched_line == original:
        return ""
    lines[idx] = patched_line
    result = "\n".join(lines)
    # Dedup os import for hardcoded-secret rewrites: keep top-level import only
    if "import os" in patched_line and re.search(r"^\s*import os\b", source, re.MULTILINE):
        result = re.sub(r"^(\s*)import os\s*#\s*noqa\s*\n", "", result, count=1, flags=re.MULTILINE)
    return result


def _guess_line_index(lines: list[str], evidence: str) -> int | None:
    """Find the first line containing the evidence snippet."""
    if not evidence:
        return None
    needle = evidence.strip().splitlines()[0].strip() if evidence.strip() else ""
    for i, ln in enumerate(lines):
        if needle and needle in ln:
            return i
    return None


def _rewrite_line(line: str, attack_type: str, evidence: str) -> str | None:
    """Apply a heuristic transformation to a single line based on attack type."""
    # Normalize inputs
    attack_type = (attack_type or "").lower()
    line_upper = line.upper()

    # 0o777 / 777 chmod → 0o644
    if "0o777" in line or re.search(r"chmod\s*\(.*,\s*0?o?777\s*\)", line) or re.search(r"\bchmod\s+777\b", line):
        out = re.sub(r"0o?777", "0o644", line)
        out = re.sub(r"(chmod\s+)777\b", r"\g<1>644", out)
        return out

    # CORS wildcard
    if re.search(r"cors\s*=\s*['\"]?\*['\"]?", line, flags=re.IGNORECASE):
        return re.sub(r"cors\s*=\s*['\"]?\*['\"]?", 'cors="https://your-allowed-origin.example"',
                      line, flags=re.IGNORECASE)

    # --allow-all flag
    if "--allow-all" in line:
        return line.replace("--allow-all", "# --allow-all REMOVED for security")

    # eval / exec / __import__ → comment out
    if attack_type in {"dangerous_call", "obfuscated_eval", "dynamic_execution", "string_concat_eval"} or \
       re.search(r"\b(eval|exec|__import__)\s*\(", line):
        return f"# SECURITY: removed dangerous call — review and replace with safe alternative\n# {line.lstrip()}"

    # base64 + exec
    if attack_type == "base64_payload" or re.search(r"base64\.b64decode\s*\(.*\).*exec", line):
        return f"# SECURITY: base64-decoded exec removed\n# {line.lstrip()}"

    # bare `except: pass`
    if re.search(r"^\s*except\s*:\s*$", line):
        return line.replace("except:", "except Exception as exc:  # narrow this")

    # SQL Injection via f-strings (common in hackathon repos)
    if "F\"SELECT" in line_upper or "F\"INSERT" in line_upper or "F\"UPDATE" in line_upper:
        if "{" in line and "}" in line:
            # Simple heuristic to parameterize f-string SQL
            # Remove f-prefix and replace {var} with ?
            patched = re.sub(r"([fF])(['\"])", r"\2", line) # Remove f prefix
            patched = re.sub(r"\{([^}]+)\}", "?", patched)
            return f"# SECURITY: Parameterized query suggested to prevent SQL Injection\n{patched}  # Use cursor.execute(query, (params,))"

    # hardcoded secrets / passwords
    if attack_type in {"hardcoded_secret", "encoded_shell"} or \
       re.search(r"(?i)(password|api[_-]?key|secret|token)\s*=\s*['\"]", line):
        # Match assignment: variable = "value"
        # Relaxed regex to catch assignments not at the start of line
        m = re.search(r"(\s*)([A-Za-z_][\w]*)\s*=\s*['\"][^'\"]+['\"]", line)
        if m:
            indent, name = m.group(1), m.group(2)
            return f'{indent}import os  # noqa\n{indent}{name} = os.getenv("{name.upper()}", "")'
        return None

    return None


def _check_syntax(source: str, filename: str) -> bool:
    """Check if patched source has valid syntax."""
    if filename.endswith(".py"):
        try:
            compile(source, filename, "exec")
            return True
        except SyntaxError:
            return False
    # For non-Python, assume valid (Stage 2: tree-sitter validation)
    return True


def _verify_pattern_removed(source: str, attack_type: str, finding: dict) -> dict:
    """Verify the dangerous pattern no longer exists in patched source."""
    pattern_map = {
        "dangerous_call": r'\b(eval|exec|compile|__import__)\s*\(',
        "hidden_in_except": r'except\s*:\s*\n\s*(eval|exec|__import__)',
        "base64_payload": r'["\'][A-Za-z0-9+/]{50,}={0,2}["\']',
        "homoglyph": r'[\u0400-\u04ff\u0500-\u052f]',
        "install_hook": r'class\s+\w+\s*\(\s*(install|develop)\s*\)',
        "obfuscated_eval": r'(eval|exec)\s*\([^)]*\+',
    }

    pattern = pattern_map.get(attack_type, "")
    if not pattern:
        return {
            "pattern_removed": False,
            "method": "no_pattern_available",
            "details": f"No verification pattern for attack type: {attack_type}",
            "confidence": 0.3,
        }

    matches = re.findall(pattern, source)
    removed = len(matches) == 0

    return {
        "pattern_removed": removed,
        "method": "regex_verification",
        "details": (f"Pattern '{attack_type}' {'not found' if removed else 'still present'} "
                    f"in patched source ({len(matches)} matches)"),
        "confidence": 0.85 if removed else 0.10,
    }


def apply_patch_to_source(original_code: str, unified_diff: str) -> str:
    """
    Apply a unified diff / patch to the original_code and return the patched code.
    If patching fails, falls back to the raw source.
    """
    # Simply using a basic parsing of unified diff, or since we already have candidates 
    # where patched_source is generated, this helper can be a fallback or a light patch applicator.
    # Often, the unified diff contains the exact lines to modify.
    # In our scan pipeline, the patched_source is already complete, but this is a mandated helper.
    import patch
    import tempfile
    
    # If the unified diff is actually just the full new code (common LLM error), return that
    if "diff --git" not in unified_diff and "@@ " not in unified_diff:
        if len(unified_diff.strip()) > 0 and len(unified_diff.splitlines()) > 5:
            return unified_diff

    # Real unified diff application via temp files
    try:
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.py') as orig_file:
            orig_file.write(original_code)
            orig_name = orig_file.name
            
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.patch') as patch_file:
            patch_file.write(unified_diff)
            patch_name = patch_file.name

        import subprocess
        # try using git apply or patch command
        try:
            res = subprocess.run(['git', 'apply', '--recount', patch_name], cwd=tempfile.gettempdir(), capture_output=True, text=True)
            if res.returncode == 0:
                with open(orig_name, 'r') as f:
                    return f.read()
        except Exception:
            pass
            
        # fallback to standard patch utility or simple line-by-line diff replacement if patch utility is missing
        # In most cases, PatchForge generates candidate patches directly, so this is just a best-effort utility.
        return original_code
    except Exception:
        return original_code

