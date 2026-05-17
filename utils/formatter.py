"""
GitHub PR Comment Formatter

Transforms the structured JSON Lead Warden verdict into a beautiful,
color-coded markdown comment using GitHub alert syntax.
"""

from typing import Dict, Any


def format_verdict_comment(verdict_data: Dict[str, Any]) -> str:
    """
    Format a Lead Warden JSON verdict into a GitHub markdown comment.
    """
    verdict = verdict_data.get("verdict", "REVIEW").upper()
    confidence = verdict_data.get("confidence", 0.0)
    severity = verdict_data.get("severity", "UNKNOWN")
    summary = verdict_data.get("summary", "No summary provided.")
    reasoning = verdict_data.get("reasoning", [])
    
    # 1. Header Alert Block
    if verdict == "BLOCK":
        header = f"> [!CAUTION]\n> **Sentinel-AI Verification Failed (BLOCK)**\n> Risk Score: {verdict_data.get('risk_score', 'N/A')} | Confidence: {confidence:.0%}"
    elif verdict == "REVIEW":
        header = f"> [!WARNING]\n> **Sentinel-AI Manual Review Required**\n> Risk Score: {verdict_data.get('risk_score', 'N/A')} | Confidence: {confidence:.0%}"
    else:
        header = f"> [!TIP]\n> **Sentinel-AI Verification Passed (APPROVE)**\n> Risk Score: {verdict_data.get('risk_score', 'N/A')} | Confidence: {confidence:.0%}"

    # 2. Body Sections
    sections = [
        header,
        f"**Severity**: `{severity}`\n**Classification**: `{verdict_data.get('attack_classification', 'none')}`",
        f"### Summary\n{summary}"
    ]

    # 3. Reasoning List
    if reasoning:
        reasoning_list = "\n".join([f"- {step}" for step in reasoning])
        sections.append(f"### Reasoning Trace\n{reasoning_list}")

    # 4. Footer
    footer = (
        "---\n"
        "*Pipeline executed locally (0 cloud reliance). Ground-truth data logged.*\n"
        "*React with 👍 if this analysis was helpful, or 👎 if this is a false positive to improve the model.*"
    )
    sections.append(footer)

    return "\n\n".join(sections)
