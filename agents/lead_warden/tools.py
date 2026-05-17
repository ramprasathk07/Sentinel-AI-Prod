"""
Lead Warden Tools — Stage 1→3

Central decision-making tools for synthesizing agent findings into
a BLOCK/REVIEW/APPROVE verdict with confidence scoring and chain-of-thought
reasoning.

  Stage 1: Structured LLM prompt over local model (Ollama/vLLM)
  Stage 2: Graphiti context injection before verdict prompt
  Stage 3: M-GRPO trained policy replaces raw LLM call
"""

from __future__ import annotations

import json
from datetime import datetime, timezone


# ═════════════════════════════════════════════════════════════
# TOOL 1 — Synthesize Verdict from Agent Findings
# ═════════════════════════════════════════════════════════════

# Verdict decision matrix: severity → verdict thresholds
_SEVERITY_WEIGHTS = {
    "CRITICAL": 10.0,
    "HIGH": 5.0,
    "MEDIUM": 2.0,
    "LOW": 0.5,
    "UNKNOWN": 0.2,
}

_VERDICT_THRESHOLDS = {
    "BLOCK": 15.0,      # weighted score ≥ 15 → auto-block
    "REVIEW": 5.0,      # weighted score ≥ 5  → manual review
    # below 5 → APPROVE
}

# Attack classification taxonomy
_ATTACK_CLASSES = {
    "supply_chain_injection": {
        "indicators": ["install_hook", "preinstall", "postinstall", "setup.py",
                       "build.rs", "init()"],
        "description": "Malicious code injected via package install hooks",
    },
    "code_obfuscation": {
        "indicators": ["base64_payload", "dynamic_execution", "string_concat_eval",
                       "obfuscated_import", "homoglyph", "encoded_shell"],
        "description": "Code hidden or disguised using obfuscation techniques",
    },
    "data_exfiltration": {
        "indicators": ["network_import", "dns_exfil", "env_var_read",
                       "exfiltration", "data_access"],
        "description": "Unauthorized data collection or transmission",
    },
    "hidden_execution": {
        "indicators": ["hidden_in_except", "dead_code_payload", "hidden_atexit",
                       "hidden_in_destructor", "hidden_signal_handler"],
        "description": "Payload hidden in rarely-executed code paths",
    },
    "dependency_vulnerability": {
        "indicators": ["cve", "osv", "nvd", "one_week_rule"],
        "description": "Known CVE or maintainer trust violation in dependency",
    },
    "credential_exposure": {
        "indicators": ["hardcoded_secret", "api_key", "token", "password", "credential"],
        "description": "Hardcoded secrets or credentials in source code",
    },
    "vibe_smell": {
        "indicators": ["vibe_smell", "over_permissive", "hallucinated_import",
                       "ai_marker", "missing_error_handling", "swallowed_exception"],
        "description": "AI-generated-code smells (over-permissive, hallucinated APIs, missing error handling)",
    },
}


def synthesize_verdict(
    archeologist_findings: str = "",
    shadow_stalker_findings: str = "",
    detonator_telemetry: str = "",
    graphiti_context: str = "",
    pr_metadata: str = "",
) -> dict:
    """
    Synthesize all agent findings into a final BLOCK/REVIEW/APPROVE verdict.

    Analyzes findings from Archeologist (CVE/dependency risks),
    Shadow Stalker (static analysis/obfuscation), Detonator (sandbox telemetry),
    and Graphiti (historical attack pattern similarity) to produce a structured
    verdict with confidence scoring and chain-of-thought reasoning.

    Args:
        archeologist_findings: JSON string of Archeologist scan results
                               (CVEs, one-week flags, maintainer info).
        shadow_stalker_findings: JSON string of Shadow Stalker scan results
                                  (static findings, obfuscation detections).
        detonator_telemetry: JSON string of Detonator sandbox telemetry
                              (Stage 2+, may be empty).
        graphiti_context: JSON string of Graphiti similarity search results
                          for similar historical attack patterns.
        pr_metadata: JSON string with PR metadata (author, repo, changed files).

    Returns:
        Structured verdict dict with: verdict, confidence, severity, summary,
        reasoning chain, attack classification, and per-agent breakdowns.
    """
    reasoning = []
    agent_scores = {}
    all_findings_flat = []

    # ── Parse Archeologist findings ─────────────────────────
    arch_data = _safe_parse(archeologist_findings)
    arch_score = 0.0
    if arch_data:
        arch_score, arch_reasons, arch_findings = _score_archeologist(arch_data)
        agent_scores["archeologist"] = arch_score
        reasoning.extend(arch_reasons)
        all_findings_flat.extend(arch_findings)

    # ── Parse Shadow Stalker findings ───────────────────────
    ss_data = _safe_parse(shadow_stalker_findings)
    ss_score = 0.0
    if ss_data:
        ss_score, ss_reasons, ss_findings = _score_shadow_stalker(ss_data)
        agent_scores["shadow_stalker"] = ss_score
        reasoning.extend(ss_reasons)
        all_findings_flat.extend(ss_findings)

    # ── Parse Detonator telemetry (Stage 2+) ────────────────
    det_data = _safe_parse(detonator_telemetry)
    det_score = 0.0
    if det_data:
        det_score, det_reasons = _score_detonator(det_data)
        agent_scores["detonator"] = det_score
        reasoning.extend(det_reasons)

    # ── Parse Graphiti context ──────────────────────────────
    graphiti_data = _safe_parse(graphiti_context)
    graphiti_boost = 0.0
    if graphiti_data:
        graphiti_boost, graphiti_reasons = _score_graphiti(graphiti_data)
        reasoning.extend(graphiti_reasons)

    # ── Calculate aggregate score ───────────────────────────
    raw_score = arch_score + ss_score + det_score + graphiti_boost
    total_score = min(raw_score, 50.0)  # cap

    # ── Determine verdict ───────────────────────────────────
    if total_score >= _VERDICT_THRESHOLDS["BLOCK"]:
        verdict = "BLOCK"
    elif total_score >= _VERDICT_THRESHOLDS["REVIEW"]:
        verdict = "REVIEW"
    else:
        verdict = "APPROVE"

    # ── Calculate confidence ────────────────────────────────
    agents_reporting = sum(1 for s in agent_scores.values() if s > 0)
    total_agents = max(len(agent_scores), 1)
    data_coverage = agents_reporting / total_agents

    if verdict == "BLOCK" and total_score >= 25:
        base_confidence = 0.95
    elif verdict == "BLOCK":
        base_confidence = 0.80
    elif verdict == "REVIEW":
        base_confidence = 0.70
    else:
        base_confidence = 0.85 if total_score < 1 else 0.65

    confidence = round(min(base_confidence * (0.6 + 0.4 * data_coverage), 1.0), 2)

    # ── Classify attack ─────────────────────────────────────
    attack_class = _classify_attack(all_findings_flat)

    # ── Determine overall severity ──────────────────────────
    if total_score >= 20:
        severity = "CRITICAL"
    elif total_score >= 10:
        severity = "HIGH"
    elif total_score >= 3:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    # ── Build summary ───────────────────────────────────────
    summary = _build_summary(verdict, severity, confidence, agent_scores,
                              attack_class, total_score)

    return {
        "verdict": verdict,
        "confidence": confidence,
        "severity": severity,
        "risk_score": round(total_score, 2),
        "summary": summary,
        "reasoning": reasoning,
        "attack_classification": attack_class,
        "agent_scores": agent_scores,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ═════════════════════════════════════════════════════════════
# TOOL 2 — Build Verdict Prompt (for LLM-based verdict)
# ═════════════════════════════════════════════════════════════

async def get_llm_verdict(
    archeologist_findings: str = "",
    shadow_stalker_findings: str = "",
    detonator_telemetry: str = "",
    graphiti_context: str = "",
    pr_metadata: str = "",
    llm_client_override=None,
) -> dict:
    """
    Get a structured verdict from the LLM (Qwen2.5-Coder-7B via
    Ollama/vLLM). This uses the llm_client to run inference locally.

    In Stage 3, this is replaced by the M-GRPO trained policy adapter.

    Args:
        archeologist_findings: JSON string of Archeologist results.
        shadow_stalker_findings: JSON string of Shadow Stalker results.
        detonator_telemetry: JSON string of Detonator results (optional).
        graphiti_context: JSON string of Graphiti similarity results.
        pr_metadata: JSON string with PR metadata.

    Returns:
        A dict with the 'verdict_json' output from the LLM.
    """
    from llm.llm_client import llm_client as _default_client
    llm_client = llm_client_override or _default_client

    system_prompt = (
        "You are a security verdict engine for the Sentinel-AI platform. "
        "Your role is to analyze aggregated security findings from multiple "
        "specialized agents and produce a final structured verdict.\n\n"
        "You MUST respond with valid JSON matching this schema:\n"
        "{\n"
        '  "verdict": "BLOCK" | "REVIEW" | "APPROVE",\n'
        '  "confidence": 0.0-1.0,\n'
        '  "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",\n'
        '  "summary": "one-paragraph explanation",\n'
        '  "reasoning": ["step 1...", "step 2...", ...],\n'
        '  "attack_classification": "supply_chain_injection" | "code_obfuscation" | '
        '"data_exfiltration" | "hidden_execution" | "dependency_vulnerability" | '
        '"credential_exposure" | "vibe_smell" | "none"\n'
        "}\n\n"
        "Decision rules:\n"
        "- ANY CRITICAL finding → BLOCK (confidence ≥ 0.85)\n"
        "- Multiple HIGH findings → BLOCK (confidence ≥ 0.75)\n"
        "- Single HIGH finding → REVIEW (confidence ≥ 0.70)\n"
        "- Only MEDIUM/LOW findings → REVIEW if >5 total, else APPROVE\n"
        "- One-Week Rule violation → always BLOCK regardless of other findings\n"
        "- Graphiti match (similarity > 0.7) with known attack → boost severity by one level\n"
        "\n"
        "Vibe-Coding heuristics (AI-generated code smells — weight as MEDIUM unless combined):\n"
        "- chmod 0o777 / wildcard CORS / verify=False → over-permissive, MEDIUM\n"
        "- imports of non-existent stdlib paths (langchain.utils.fake, openai.experimental_unsafe, etc.) → hallucinated_import, HIGH\n"
        "- Network calls without try/except → missing_error_handling, MEDIUM\n"
        "- `except Exception: pass` adjacent to network call → swallowed_exception, MEDIUM\n"
        "- TODO: implement / placeholder strings / NotImplementedError stubs → ai_marker, LOW\n"
        "- 2+ vibe smells in same file → upgrade to REVIEW; 4+ → BLOCK with attack_classification=vibe_smell\n"
        "\n"
        "Be willing to BLOCK on a small number of findings if they reveal an active attack pattern; "
        "be willing to REVIEW even with one ambiguous finding rather than reflexively APPROVE."
    )

    user_sections = []

    if pr_metadata:
        user_sections.append(f"## PR Metadata\n```json\n{pr_metadata}\n```")

    if archeologist_findings:
        user_sections.append(
            f"## Archeologist Findings (Dependency/CVE Analysis)\n"
            f"```json\n{archeologist_findings}\n```"
        )

    if shadow_stalker_findings:
        user_sections.append(
            f"## Shadow Stalker Findings (Static Analysis)\n"
            f"```json\n{shadow_stalker_findings}\n```"
        )

    if detonator_telemetry:
        user_sections.append(
            f"## Detonator Telemetry (Sandbox Execution)\n"
            f"```json\n{detonator_telemetry}\n```"
        )

    if graphiti_context:
        user_sections.append(
            f"## Graphiti Historical Context (Similar Known Attacks)\n"
            f"```json\n{graphiti_context}\n```"
        )

    user_prompt = (
        "Analyze the following security findings and produce a verdict.\n\n"
        + "\n\n".join(user_sections)
        + "\n\nProduce your verdict as JSON."
    )

    try:
        response_text = await llm_client.complete(
            prompt=user_prompt,
            system_prompt=system_prompt,
            temperature=0.1,
            max_tokens=1024,
            json_mode=True
        )
        
        verdict_data = json.loads(response_text)
    except Exception as exc:
        return {"error": f"LLM inference failed: {exc}"}

    return {
        "verdict_json": verdict_data,
        "engine_version": "stage1_llm",
        "model": llm_client.model,
        "backend": llm_client.backend,
        "note": "Generated via vLLM/Ollama integration."
    }


# ═════════════════════════════════════════════════════════════
# TOOL 3 — Query Graphiti for Similar Historical Patterns
# ═════════════════════════════════════════════════════════════

def query_similar_findings(
    findings_summary: str,
    top_k: int = 5,
) -> dict:
    """
    Search Graphiti for historical FindingNodes similar to the current
    PR's findings. Returns past verdicts and attack patterns that match.

    In Stage 1, this uses the Shadow Stalker's local embedding store.
    In Stage 2+, this queries the Graphiti knowledge graph directly.

    Args:
        findings_summary: JSON string summarizing current findings to search for.
        top_k: Number of similar historical patterns to return.

    Returns:
        A dict with 'similar_patterns' (list of historical matches) and metadata.
    """
    # Stage 1: Use Shadow Stalker's embedding store as fallback
    try:
        from agents.shadow_stalker.embedding_store import search_known_attacks
        result = search_known_attacks(findings_summary, "verdict_query", top_k)
        return {
            "source": "local_embedding_store",
            "similar_patterns": result.get("matches", []),
            "match_count": result.get("match_count", 0),
            "corpus_size": result.get("corpus_size", 0),
            "note": "Stage 1: using local embedding store. Stage 2+ will use Graphiti.",
        }
    except Exception as exc:
        return {
            "source": "none",
            "similar_patterns": [],
            "match_count": 0,
            "error": str(exc),
        }


# ═════════════════════════════════════════════════════════════
# TOOL 4 — Emit Per-Agent Reward Signal
# ═════════════════════════════════════════════════════════════

def emit_reward_signal(
    agent_name: str,
    verdict: str,
    agent_findings_count: int,
    agent_score_contribution: float,
    was_useful: bool = True,
) -> dict:
    """
    Emit a reward signal for a specific agent based on how its findings
    contributed to the final verdict. Used for Stage 3 M-GRPO training
    data collection.

    Args:
        agent_name:              Name of the agent (archeologist/shadow_stalker/detonator).
        verdict:                 Final verdict issued (BLOCK/REVIEW/APPROVE).
        agent_findings_count:    Number of findings this agent contributed.
        agent_score_contribution: How much this agent's score contributed to total.
        was_useful:              Whether the agent's findings were relevant.

    Returns:
        A dict with the reward signal record.
    """
    # Calculate reward based on contribution and verdict alignment
    if verdict == "BLOCK" and agent_score_contribution > 5:
        reward = 1.0  # Correctly identified critical threat
    elif verdict == "APPROVE" and agent_findings_count == 0:
        reward = 0.8  # Correctly found nothing in clean PR
    elif verdict == "REVIEW" and agent_findings_count > 0:
        reward = 0.6  # Contributed to review decision
    elif not was_useful:
        reward = -0.3  # False positive / noise
    else:
        reward = 0.3  # Partial contribution

    signal = {
        "agent_name": agent_name,
        "verdict": verdict,
        "findings_count": agent_findings_count,
        "score_contribution": round(agent_score_contribution, 2),
        "reward": reward,
        "was_useful": was_useful,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    # Stage 3: This would be written to a training buffer for M-GRPO
    # For now, just return it for logging
    return {
        "recorded": True,
        "signal": signal,
        "note": "Stage 1: logged for future M-GRPO training. No adapter active.",
    }


# ═════════════════════════════════════════════════════════════
# TOOL 5 — Format Verdict as Structured JSON
# ═════════════════════════════════════════════════════════════

def format_verdict_output(
    verdict: str,
    confidence: float,
    severity: str,
    summary: str,
    reasoning: str = "[]",
    attack_classification: str = "none",
    risk_score: float = 0.0,
) -> dict:
    """
    Format the final verdict into the canonical structured JSON output
    that downstream consumers (GitHub PR comments, Slack alerts, CI/CD
    gates) expect.

    Args:
        verdict:                BLOCK, REVIEW, or APPROVE.
        confidence:             Confidence score 0.0–1.0.
        severity:               CRITICAL, HIGH, MEDIUM, or LOW.
        summary:                Human-readable summary paragraph.
        reasoning:              JSON string of reasoning steps list.
        attack_classification:  Attack class or "none".
        risk_score:             Aggregate risk score 0.0–50.0.

    Returns:
        Canonical verdict JSON dict.
    """
    reasoning_list = _safe_parse(reasoning) or []
    if isinstance(reasoning_list, str):
        reasoning_list = [reasoning_list]

    return {
        "verdict": verdict.upper(),
        "confidence": max(0.0, min(1.0, confidence)),
        "severity": severity.upper(),
        "risk_score": round(risk_score, 2),
        "summary": summary,
        "reasoning": reasoning_list,
        "attack_classification": attack_classification,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "engine_version": "stage1",
        "model": "rule-based+llm-prompt",
    }


# ─────────────────────────────────────────────────────────────
# Private helpers
# ─────────────────────────────────────────────────────────────

def _safe_parse(json_str: str) -> dict | list | None:
    """Safely parse a JSON string, returning None on failure."""
    if not json_str or not json_str.strip():
        return None
    try:
        return json.loads(json_str)
    except (json.JSONDecodeError, TypeError):
        return None


def _score_archeologist(data: dict | list) -> tuple[float, list[str], list[dict]]:
    """Score Archeologist findings and build reasoning chain."""
    score = 0.0
    reasoning = []
    findings_flat = []

    if isinstance(data, dict):
        # Handle structured report
        cves = data.get("cve_findings", [])
        owf = data.get("one_week_flags", [])
        deps = data.get("dependencies", [])

        if owf:
            score += len(owf) * _SEVERITY_WEIGHTS["CRITICAL"]
            reasoning.append(
                f"Archeologist: {len(owf)} One-Week Rule violation(s) detected — "
                f"CRITICAL (new maintainer accounts < 7 days old)"
            )
            for f in owf:
                findings_flat.append({"type": "one_week_rule", "severity": "CRITICAL"})

        for cve in cves:
            sev = cve.get("severity", "UNKNOWN")
            score += _SEVERITY_WEIGHTS.get(sev, 0.2)
            reasoning.append(
                f"Archeologist: CVE {cve.get('cve_id', '?')} in "
                f"{cve.get('package_name', '?')}@{cve.get('version', '?')} — {sev}"
            )
            findings_flat.append({"type": "cve", "severity": sev})

        if deps and not cves and not owf:
            reasoning.append(
                f"Archeologist: {len(deps)} dependencies scanned — no issues found"
            )
    elif isinstance(data, list):
        for item in data:
            sev = item.get("severity", "MEDIUM")
            score += _SEVERITY_WEIGHTS.get(sev, 1.0)
            findings_flat.append(item)

    return score, reasoning, findings_flat


def _score_shadow_stalker(data: dict | list) -> tuple[float, list[str], list[dict]]:
    """Score Shadow Stalker findings and build reasoning chain."""
    score = 0.0
    reasoning = []
    findings_flat = []

    findings = []
    if isinstance(data, dict):
        findings = data.get("findings", [])
        if not findings:
            findings = data.get("matches", [])
    elif isinstance(data, list):
        findings = data

    severity_counts = {}
    for f in findings:
        sev = f.get("severity", "MEDIUM")
        score += _SEVERITY_WEIGHTS.get(sev, 1.0)
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        findings_flat.append(f)

    if findings:
        parts = []
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = severity_counts.get(sev, 0)
            if count:
                parts.append(f"{count} {sev}")
        reasoning.append(
            f"Shadow Stalker: {len(findings)} static findings — {', '.join(parts)}"
        )

        # Check for specific high-risk patterns
        techniques = {f.get("technique", f.get("type", "")) for f in findings}
        if "homoglyph" in techniques:
            reasoning.append(
                "Shadow Stalker: Unicode homoglyph attack detected — "
                "HIGH CONFIDENCE supply-chain indicator"
            )
            score += 5.0  # bonus for homoglyph detection

        if "hidden_in_except" in techniques or "dead_code_payload" in techniques:
            reasoning.append(
                "Shadow Stalker: Hidden payload in error handler / dead code — "
                "strong obfuscation indicator"
            )
    else:
        reasoning.append("Shadow Stalker: No static analysis findings")

    return score, reasoning, findings_flat


def _score_detonator(data: dict | list) -> tuple[float, list[str]]:
    """Score Detonator sandbox telemetry."""
    score = 0.0
    reasoning = []

    if isinstance(data, dict):
        # Check for sandbox escape attempts
        if data.get("sandbox_escape_attempted"):
            score += _SEVERITY_WEIGHTS["CRITICAL"] * 2
            reasoning.append("Detonator: SANDBOX ESCAPE ATTEMPT — auto-BLOCK")

        # Check for network connections
        net_conns = data.get("network_connections", [])
        if net_conns:
            score += len(net_conns) * _SEVERITY_WEIGHTS["HIGH"]
            reasoning.append(
                f"Detonator: {len(net_conns)} unexpected network connection(s) "
                f"during sandbox execution"
            )

        # Check for file system writes
        fs_writes = data.get("file_writes", [])
        suspicious_paths = [w for w in fs_writes if any(
            p in str(w) for p in ["/etc/", "/usr/", "\\System32\\", "\\Windows\\"]
        )]
        if suspicious_paths:
            score += len(suspicious_paths) * _SEVERITY_WEIGHTS["CRITICAL"]
            reasoning.append(
                f"Detonator: {len(suspicious_paths)} write(s) to sensitive "
                f"system paths during sandbox execution"
            )

        # Check for process spawning
        procs = data.get("spawned_processes", [])
        if procs:
            score += len(procs) * _SEVERITY_WEIGHTS["MEDIUM"]
            reasoning.append(
                f"Detonator: {len(procs)} child process(es) spawned during execution"
            )

        if not any([net_conns, fs_writes, suspicious_paths, procs,
                     data.get("sandbox_escape_attempted")]):
            reasoning.append("Detonator: Clean sandbox execution — no suspicious behavior")

    return score, reasoning


def _score_graphiti(data: dict | list) -> tuple[float, list[str]]:
    """Score Graphiti historical pattern matches."""
    boost = 0.0
    reasoning = []

    matches = []
    if isinstance(data, dict):
        matches = data.get("similar_patterns", data.get("matches", []))
    elif isinstance(data, list):
        matches = data

    high_sim = [m for m in matches if m.get("similarity", 0) > 0.7]
    if high_sim:
        boost += len(high_sim) * 3.0
        reasoning.append(
            f"Graphiti: {len(high_sim)} historical attack pattern(s) with "
            f">70% similarity — elevated risk"
        )
        for m in high_sim[:3]:
            label = m.get("finding", {}).get("label", m.get("code_preview", "?")[:60])
            sim = m.get("similarity", 0)
            reasoning.append(f"  → Similar to: '{label}' (similarity: {sim:.0%})")

    elif matches:
        reasoning.append(
            f"Graphiti: {len(matches)} pattern matches found but similarity <70%"
        )

    return boost, reasoning


def _classify_attack(findings: list[dict]) -> str:
    """Classify the primary attack type from all findings."""
    if not findings:
        return "none"

    class_scores = {}
    for finding in findings:
        ftype = finding.get("type", finding.get("technique", "")).lower()
        for cls_name, cls_info in _ATTACK_CLASSES.items():
            if any(ind in ftype for ind in cls_info["indicators"]):
                class_scores[cls_name] = class_scores.get(cls_name, 0) + 1

    if not class_scores:
        return "none"

    return max(class_scores, key=class_scores.get)


def _build_summary(
    verdict: str, severity: str, confidence: float,
    agent_scores: dict, attack_class: str, total_score: float,
) -> str:
    """Build a human-readable summary paragraph."""
    parts = [f"Verdict: **{verdict}** (confidence: {confidence:.0%})."]
    parts.append(f"Overall severity: {severity} (risk score: {total_score:.1f}).")

    if attack_class != "none":
        cls_desc = _ATTACK_CLASSES.get(attack_class, {}).get("description", attack_class)
        parts.append(f"Primary threat: {cls_desc}.")

    contributing = [
        f"{name} ({score:.1f})"
        for name, score in sorted(agent_scores.items(), key=lambda x: -x[1])
        if score > 0
    ]
    if contributing:
        parts.append(f"Contributing agents: {', '.join(contributing)}.")

    return " ".join(parts)
