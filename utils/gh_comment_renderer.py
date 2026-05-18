"""
GitGuardian-style PR Comment Renderer

Renders rich structured security findings comments for GitHub PRs.
Supports upsert (find existing comment by hidden marker and update it).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional


# ── Category remediation guidelines ─────────────────────────

_GUIDELINES = {
    "secret": (
        "**Secrets / Credentials**\n"
        "- Immediately rotate and revoke the exposed secret.\n"
        "- Move it to environment variables or a secrets manager (AWS Secrets Manager, Vault, GCP Secret Manager).\n"
        "- Rewrite git history with `git filter-repo` to remove the secret from all commits.\n"
        "- Audit access logs for unauthorized use since the exposure date."
    ),
    "injection": (
        "**Injection (SQL / Command / LDAP)**\n"
        "- Use parameterized queries / prepared statements — never concatenate user input into queries.\n"
        "- Apply input allowlisting. Reject unexpected characters at the boundary.\n"
        "- Run with least-privilege DB accounts. Disable dangerous functions (`xp_cmdshell`, etc.)."
    ),
    "xss": (
        "**Cross-Site Scripting (XSS)**\n"
        "- Escape all output in HTML context (`htmlspecialchars`, `DOMPurify`, template auto-escape).\n"
        "- Apply a strict Content-Security-Policy header.\n"
        "- Never trust `innerHTML` with user data."
    ),
    "dynamic_execution": (
        "**Dynamic Execution (eval / exec)**\n"
        "- Remove `eval`/`exec`/`__import__` calls entirely.\n"
        "- Replace with an explicit allowlist dispatch or safe parser (`ast.literal_eval`, `json.loads`).\n"
        "- Never execute user-supplied strings as code."
    ),
    "obfuscation": (
        "**Code Obfuscation**\n"
        "- Remove encoded or obfuscated payloads immediately.\n"
        "- Audit the full commit history for similar patterns.\n"
        "- Consider adding Unicode/homoglyph linting to your CI pipeline."
    ),
    "dependency": (
        "**Vulnerable / Suspicious Dependency**\n"
        "- Update the dependency to a patched version immediately.\n"
        "- Pin dependency versions and use lock files.\n"
        "- Integrate a SCA tool (Dependabot, Snyk, OWASP Dependency-Check) in CI."
    ),
    "default": (
        "**General Remediation**\n"
        "- Review the flagged code with a security-aware developer.\n"
        "- Apply principle of least privilege.\n"
        "- Add relevant security tests to prevent regression."
    ),
}


def _guideline_for(technique: str) -> str:
    t = (technique or "").lower()
    if any(k in t for k in ("secret", "credential", "password", "api_key", "token", "hardcoded", "encoded_shell")):
        return _GUIDELINES["secret"]
    if any(k in t for k in ("injection", "sql", "command", "ldap", "taint")):
        return _GUIDELINES["injection"]
    if "xss" in t:
        return _GUIDELINES["xss"]
    if any(k in t for k in ("eval", "exec", "dynamic_execution", "string_concat")):
        return _GUIDELINES["dynamic_execution"]
    if any(k in t for k in ("obfuscat", "homoglyph", "base64", "hidden_in_except")):
        return _GUIDELINES["obfuscation"]
    if any(k in t for k in ("cve", "dependency", "package", "one_week")):
        return _GUIDELINES["dependency"]
    return _GUIDELINES["default"]


# ── Severity badge ────────────────────────────────────────────

_SEV_BADGE = {
    "CRITICAL": "🔴 CRITICAL",
    "HIGH": "🟠 HIGH",
    "MEDIUM": "🟡 MEDIUM",
    "LOW": "🟢 LOW",
    "UNKNOWN": "⚪ UNKNOWN",
}


# ── Main renderer ─────────────────────────────────────────────

def render_pr_comment(
    verdict: str,
    severity: str,
    findings: List[dict],
    scan_id: Optional[str] = None,
    repo: str = "",
    pr_number: Optional[int] = None,
    commit_sha: str = "",
    dashboard_url: str = "",
) -> str:
    """
    Render a GitGuardian-style PR comment body.

    Args:
        findings: List of finding dicts with keys: file, line, technique, severity, description, evidence
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    verdict_upper = (verdict or "UNKNOWN").upper()
    severity_upper = (severity or "UNKNOWN").upper()

    # Count secrets vs vulns
    secret_count = sum(
        1 for f in findings
        if any(k in (f.get("technique") or "").lower()
               for k in ("secret", "credential", "password", "api_key", "token", "encoded"))
    )
    vuln_count = len(findings) - secret_count

    verdict_icon = {"BLOCK": "🚫", "REVIEW": "⚠️", "APPROVE": "✅"}.get(verdict_upper, "❓")

    # ── Header ──
    lines = [
        "## 🛡️ Sentinel-AI Security Checks",
        "",
        f"{verdict_icon} **Verdict: {verdict_upper}** — {_SEV_BADGE.get(severity_upper, severity_upper)}",
        "",
        f"**{secret_count}** secret(s) / **{vuln_count}** vulnerability(ies) uncovered"
        + (f" · commit `{commit_sha[:7]}`" if commit_sha else ""),
        "",
    ]

    # ── Findings table ──
    if findings:
        lines += [
            "### Findings",
            "",
            "| # | Status | Type | Severity | File | Line |",
            "|---|--------|------|----------|------|------|",
        ]
        for i, f in enumerate(findings, 1):
            fid = f.get("id") or f"F-{i:03d}"
            technique = f.get("technique") or f.get("type") or "unknown"
            sev = (f.get("severity") or "UNKNOWN").upper()
            fname = f.get("file") or f.get("filename") or "—"
            fline = f.get("line") or "—"
            view = ""
            if repo and pr_number and fname != "—" and fline != "—":
                view = f"[view](https://github.com/{repo}/pull/{pr_number}/files#diff-{fname})"

            lines.append(
                f"| `{fid}` | 🔍 Detected | `{technique}` | {_SEV_BADGE.get(sev, sev)} "
                f"| `{fname}` | {fline} {view} |"
            )
        lines.append("")

    # ── Guidelines ──
    seen_guidelines = set()
    guideline_blocks = []
    for f in findings:
        g = _guideline_for(f.get("technique") or "")
        if g not in seen_guidelines:
            seen_guidelines.add(g)
            guideline_blocks.append(g)

    if guideline_blocks:
        lines += ["### Remediation Guidelines", ""]
        for g in guideline_blocks:
            lines.append(g)
            lines.append("")

    # ── Footer ──
    lines += [
        "---",
        f"*Scanned at {now}. React 👍 to confirm this finding or 👎 to mark as false positive.*",
    ]
    if dashboard_url:
        lines.append(f"[View full report]({dashboard_url})")

    # ── Hidden marker for upsert ──
    marker = f"\n<!-- sentinel-ai:scan-id={scan_id or 'unknown'} -->"
    return "\n".join(lines) + marker


def extract_scan_id_from_comment(body: str) -> Optional[str]:
    """Extract the scan_id from a hidden marker in a comment body."""
    import re
    m = re.search(r"<!-- sentinel-ai:scan-id=([^\s>]+) -->", body)
    return m.group(1) if m else None
