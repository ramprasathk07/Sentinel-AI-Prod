"""
Check-Run Markdown Renderer

Renders the full text for GitHub Check Run output.text field.
Hard cap: 60k chars (GitHub limit is 65535, leaving 5k headroom).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional, List

MAX_CHARS = 60_000
_TRUNC_SUFFIX = "\n\n> [Report truncated — view full findings in the Sentinel dashboard]"


def _severity_sections(findings: List[dict]) -> str:
    """Group findings into sections by severity."""
    groups: dict[str, list] = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": [], "UNKNOWN": []}
    for f in findings:
        sev = (f.get("severity") or "UNKNOWN").upper()
        groups.setdefault(sev, []).append(f)

    icons = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "UNKNOWN": "⚪"}
    lines = []
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
        grp = groups.get(sev, [])
        if not grp:
            continue
        lines.append(f"\n#### {icons[sev]} {sev} ({len(grp)})\n")
        for f in grp:
            fname = f.get("file") or f.get("filename") or "—"
            line = f.get("line") or "—"
            technique = f.get("technique") or f.get("type") or "—"
            desc = (f.get("description") or "")[:200]
            lines.append(f"- **`{fname}:{line}`** — `{technique}` — {desc}")
    return "\n".join(lines)


def render_check_run_md(
    verdict: str,
    severity: str,
    findings: List[dict],
    pentest_report=None,
    scan_id: Optional[str] = None,
    pentest_session_id: Optional[str] = None,
    dashboard_url: str = "",
    truncation_meta: Optional[dict] = None,
) -> str:
    """
    Render full Check Run output.text markdown.

    Sections:
    1. Verdict summary
    2. Findings table by severity
    3. Exploited (from pentest, if provided)
    4. Confirmed-no-exploit (from pentest, if provided)
    5. Guidelines
    6. Footer with sentinel IDs
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    verdict_upper = (verdict or "UNKNOWN").upper()
    verdict_icon = {"BLOCK": "🚫", "REVIEW": "⚠️", "APPROVE": "✅"}.get(verdict_upper, "❓")

    lines: List[str] = []

    # ── 1. Verdict ──
    lines += [
        f"## {verdict_icon} Sentinel-AI Security Report",
        "",
        f"**Verdict**: {verdict_upper} | **Severity**: {severity or 'UNKNOWN'} | **Scanned at**: {now}",
        "",
    ]

    # ── 2. Findings ──
    if findings:
        trunc_note = ""
        if truncation_meta and truncation_meta.get("dropped_by_cap", 0) > 0:
            dropped = truncation_meta["dropped_by_cap"]
            trunc_note = f" *(+{dropped} lower-priority findings not shown)*"
        lines += [f"### Findings ({len(findings)} shown{trunc_note})", ""]
        lines.append(_severity_sections(findings))
        lines.append("")
    else:
        lines += ["### ✅ No findings detected", ""]

    # ── 3. Pentest: Exploited ──
    if pentest_report:
        proven = [f for f in (getattr(pentest_report, "findings", None) or []) if getattr(f, "proven", False)]
        if proven:
            lines += ["### 💥 Exploited (Pentest confirmed)", ""]
            for pf in proven:
                lines.append(f"- **[{getattr(pf, 'severity', '?')}]** {getattr(pf, 'title', '')} — `{getattr(pf, 'vulnerable_location', '')}`")
            lines.append("")

        # ── 4. Confirmed-no-exploit ──
        not_proven = [f for f in (getattr(pentest_report, "findings", None) or []) if not getattr(f, "proven", False)]
        if not_proven:
            lines += ["### ✓ Investigated — No Exploit Confirmed", ""]
            for pf in not_proven:
                lines.append(f"- {getattr(pf, 'title', '')} — `{getattr(pf, 'vulnerable_location', '')}`")
            lines.append("")

    # ── 5. Guidelines link ──
    if dashboard_url:
        lines += [f"### 📋 Full Report", "", f"[View detailed findings and remediation →]({dashboard_url})", ""]

    # ── 6. Footer markers (for round-trip) ──
    footer_parts = []
    if scan_id:
        footer_parts.append(f"scan_id={scan_id}")
    if pentest_session_id:
        footer_parts.append(f"pentest_id={pentest_session_id}")
    if footer_parts:
        lines.append(f"<!-- sentinel-ai:{' '.join(footer_parts)} -->")

    text = "\n".join(lines)

    # Hard cap
    if len(text) > MAX_CHARS:
        text = text[:MAX_CHARS] + _TRUNC_SUFFIX

    return text


def render_check_run_summary(verdict: str, severity: str, findings: List[dict]) -> str:
    """Short summary string for output.summary (shown collapsed in Checks UI)."""
    verdict_upper = (verdict or "UNKNOWN").upper()
    n = len(findings)
    crit = sum(1 for f in findings if (f.get("severity") or "").upper() == "CRITICAL")
    high = sum(1 for f in findings if (f.get("severity") or "").upper() == "HIGH")

    if verdict_upper == "BLOCK":
        return (
            f"🚫 **BLOCK** — {n} finding(s) detected "
            f"({crit} CRITICAL, {high} HIGH). Merge not recommended."
        )
    elif verdict_upper == "REVIEW":
        return f"⚠️ **REVIEW** — {n} finding(s) need attention before merging."
    else:
        return "✅ **APPROVE** — No significant security issues detected."
