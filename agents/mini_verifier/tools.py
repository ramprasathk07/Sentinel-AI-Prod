"""
Mini-Verifier Tools
Contains the actual verification logic for different supply-chain attack classes.
"""

import json
import ast
import re
from pathlib import Path
from llm.llm_client import llm_client


# ═════════════════════════════════════════════════════════════
# TOOL 0 — Patch Blocklist (always-on closed-loop check)
# ═════════════════════════════════════════════════════════════

# Known-malicious / regression patterns that must NEVER appear in a generated patch.
PATCH_BLOCKLIST_PATTERNS = [
    (r"\beval\s*\(", "eval() reintroduced"),
    (r"\bexec\s*\(", "exec() reintroduced"),
    (r"\b__import__\s*\(", "dynamic __import__ reintroduced"),
    (r"subprocess\.[A-Za-z_]+\([^)]*shell\s*=\s*True", "subprocess shell=True"),
    (r"os\.system\s*\(", "os.system() call"),
    (r"\bcurl\s+[^|;]*\|\s*(?:ba)?sh\b", "curl | sh pattern"),
    (r"\bwget\s+[^|;]*\|\s*(?:ba)?sh\b", "wget | sh pattern"),
    (r"base64\.b64decode\s*\([^)]*\)\s*[\.,]\s*(?:exec|eval|decode)", "decoded base64 payload"),
    (r"socket\.socket\s*\(", "raw socket creation"),
    (r"chmod\s*\(\s*[^,]+,\s*0?o?777\s*\)", "chmod 0o777 introduced"),
    (r"pickle\.loads\s*\(", "pickle.loads() (RCE primitive)"),
    (r"yaml\.load\s*\([^,)]*\)", "yaml.load without SafeLoader"),
]


def verify_patch_blocklist(patched_source: str, filename: str = "unknown") -> dict:
    """Always-on regex audit of a generated patch.

    Returns dict (not VerifierResult) to keep this callable from anywhere
    without importing the agent module. PatchForge wraps it as needed.
    """
    hits = []
    for pattern, label in PATCH_BLOCKLIST_PATTERNS:
        for m in re.finditer(pattern, patched_source):
            hits.append({"pattern": label, "match": m.group(0)[:120], "pos": m.start()})

    if hits:
        return {
            "verdict": "FAIL",
            "method": "mini_verifier:patch_blocklist",
            "details": f"{len(hits)} blocklist hit(s): " + ", ".join(h["pattern"] for h in hits[:3]),
            "confidence": 0.95,
            "hits": hits,
            "filename": filename,
        }
    return {
        "verdict": "PASS",
        "method": "mini_verifier:patch_blocklist",
        "details": "No malicious-pattern regressions in patch.",
        "confidence": 0.9,
        "hits": [],
        "filename": filename,
    }

from agents.shadow_stalker.tools import detect_homoglyphs, detect_base64_payloads
from agents.archeologist.tools import query_osv, parse_lockfile

# ═════════════════════════════════════════════════════════════
# TOOL 1 — Homoglyph Verifier
# ═════════════════════════════════════════════════════════════
async def verify_homoglyph(finding: dict, original_repo: Path, patched_repo: Path):
    from agents.mini_verifier.agent import VerifierResult
    filename = finding.get("filename", "")
    if not filename:
        return VerifierResult(verdict="INDETERMINATE", method="mini_verifier:homoglyph_regex", details="No filename provided.", confidence=0.0)
    
    patched_file = patched_repo / filename
    if not patched_file.exists():
        return VerifierResult(verdict="INDETERMINATE", method="mini_verifier:homoglyph_regex", details=f"File {filename} not found in patched repo.", confidence=0.0)
        
    patched_text = patched_file.read_text(encoding="utf-8", errors="replace")
    result = detect_homoglyphs(patched_text, filename)
    matches = result.get("homoglyphs", [])
    
    if matches:
        return VerifierResult(verdict="FAIL",
                             method="mini_verifier:homoglyph_regex",
                             details=f"{len(matches)} homoglyphs remaining. Examples: {[m.get('char') for m in matches[:3]]}",
                             confidence=0.95)
    return VerifierResult(verdict="PASS",
                         method="mini_verifier:homoglyph_regex",
                         details="No Cyrillic/look-alike codepoints detected.",
                         confidence=0.95)

# ═════════════════════════════════════════════════════════════
# TOOL 2 — Base64 Verifier
# ═════════════════════════════════════════════════════════════
async def verify_base64_payload(finding: dict, original_repo: Path, patched_repo: Path):
    from agents.mini_verifier.agent import VerifierResult
    filename = finding.get("filename", "")
    if not filename:
        return VerifierResult(verdict="INDETERMINATE", method="mini_verifier:base64_decode", details="No filename provided.", confidence=0.0)
    
    patched_file = patched_repo / filename
    if not patched_file.exists():
        return VerifierResult(verdict="INDETERMINATE", method="mini_verifier:base64_decode", details=f"File {filename} not found in patched repo.", confidence=0.0)
        
    patched_text = patched_file.read_text(encoding="utf-8", errors="replace")
    result = detect_base64_payloads(patched_text, filename, min_length=50)
    
    suspicious = [m for m in result.get("payloads", []) if m.get("is_suspicious")]
    if suspicious:
        return VerifierResult(verdict="FAIL",
                              method="mini_verifier:base64_decode",
                              details=f"{len(suspicious)} suspicious base64 payloads remaining.",
                              confidence=0.95)
    return VerifierResult(verdict="PASS",
                          method="mini_verifier:base64_decode",
                          details="No suspicious base64 payloads detected.",
                          confidence=0.95)

# ═════════════════════════════════════════════════════════════
# TOOL 3 — PoC Generator
# ═════════════════════════════════════════════════════════════

SYSTEM_PROMPT = """You are a security researcher writing a minimal,
self-contained Python proof-of-concept that triggers a SPECIFIC code path
in a target file. Your output is a single JSON object with the keys:

  poc_code:   the full Python script (string)
  canary:     a unique 16-hex-char string the script prints on success
  expected:   short English description of what success looks like

The script MUST:
  - import nothing from the network
  - open no sockets
  - touch no files outside its own working directory
  - print "SENTINEL_CANARY=<canary>" exactly once on success
  - exit 0 only if the canary was printed

The script MUST NOT:
  - call os.system, subprocess.*, or eval anything beyond what is strictly
    needed to trigger the finding under test
  - sleep more than 1 second total
"""

USER_PROMPT_TEMPLATE = """Target finding:
  - file: {filename}
  - line: {line}
  - technique: {technique}
  - description: {description}
  - evidence: {evidence}

Snippets around the finding:
```
{snippet}
```

Generate a minimal PoC that triggers this code path and emits the canary."""

def _get_snippet(filepath: Path, line_num: int, context: int = 5) -> str:
    if not filepath.exists():
        return ""
    lines = filepath.read_text(encoding="utf-8", errors="replace").splitlines()
    start = max(0, line_num - context - 1)
    end = min(len(lines), line_num + context)
    return "\n".join(lines[start:end])

def _is_safe_poc(poc_code: str) -> bool:
    try:
        tree = ast.parse(poc_code)
    except SyntaxError:
        return False
        
    forbidden_modules = {"socket", "urllib", "requests", "httpx", "pty", "ctypes", "subprocess", "pickle"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] in forbidden_modules:
                    return False
        if isinstance(node, ast.ImportFrom):
            mod = (node.module or "").split(".")[0]
            if mod in forbidden_modules:
                return False
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr in ("system", "popen"):
                return False
    return True

async def generate_poc(finding: dict, original_repo: Path) -> dict:
    filename = finding.get("filename", "")
    line = finding.get("line", 0)
    
    filepath = original_repo / filename
    snippet = _get_snippet(filepath, line)
    
    prompt = USER_PROMPT_TEMPLATE.format(
        filename=filename,
        line=line,
        technique=finding.get("technique", ""),
        description=finding.get("description", ""),
        evidence=finding.get("evidence", ""),
        snippet=snippet
    )
    
    try:
        response = await llm_client.complete(
            prompt=prompt,
            system_prompt=SYSTEM_PROMPT,
            temperature=0.1,
            json_mode=True
        )
        poc_data = json.loads(response)
    except Exception:
        return {}
        
    poc_code = poc_data.get("poc_code", "")
    canary = poc_data.get("canary", "")
    
    if len(poc_code.splitlines()) > 200:
        return {} # Reject scripts > 200 LoC
        
    if not canary or canary not in poc_code:
        return {} # Canary uniqueness / presence
        
    if not _is_safe_poc(poc_code):
        return {}
        
    return poc_data

# ═════════════════════════════════════════════════════════════
# Sandbox Execution Helper
# ═════════════════════════════════════════════════════════════
async def _sandbox_run(poc_code: str, repo_path: Path, runtime: str) -> dict:
    # Stage 2: Detonator sandbox integration pending.
    return {"telemetry": {"stdout_preview": ""}}

# ═════════════════════════════════════════════════════════════
# TOOL 4 — Dynamic Execution Verifier
# ═════════════════════════════════════════════════════════════
async def verify_dynamic_exec(finding: dict, original_repo: Path, patched_repo: Path):
    from agents.mini_verifier.agent import VerifierResult
    poc_data = await generate_poc(finding, original_repo)
    if not poc_data:
        return VerifierResult(verdict="INDETERMINATE", method="mini_verifier:dynamic_exec", details="Failed to generate safe PoC", confidence=0.0)
        
    poc_code = poc_data.get("poc_code", "")
    canary = poc_data.get("canary", "")
    
    orig_result = await _sandbox_run(poc_code, original_repo, "python")
    orig_stdout = orig_result.get("telemetry", {}).get("stdout_preview", "")
    
    if canary not in orig_stdout:
        return VerifierResult(verdict="INDETERMINATE", method="mini_verifier:dynamic_exec", details="PoC failed to reproduce on original code.", confidence=0.0)
        
    patch_result = await _sandbox_run(poc_code, patched_repo, "python")
    patch_stdout = patch_result.get("telemetry", {}).get("stdout_preview", "")
    
    if canary in patch_stdout:
        return VerifierResult(verdict="FAIL", method="mini_verifier:dynamic_exec", details="Exploit still works on patched code.", confidence=0.95)
        
    return VerifierResult(verdict="PASS", method="mini_verifier:dynamic_exec", details="Exploit mitigated in patched code.", confidence=0.95)

# ═════════════════════════════════════════════════════════════
# TOOL 5 — Hidden Execution Verifier
# ═════════════════════════════════════════════════════════════
async def verify_hidden_exec(finding: dict, original_repo: Path, patched_repo: Path):
    from agents.mini_verifier.agent import VerifierResult
    poc_data = await generate_poc(finding, original_repo)
    if not poc_data:
        return VerifierResult(verdict="INDETERMINATE", method="mini_verifier:hidden_exec", details="Failed to generate safe PoC", confidence=0.0)
        
    poc_code = poc_data.get("poc_code", "")
    canary = poc_data.get("canary", "")
    
    orig_result = await _sandbox_run(poc_code, original_repo, "python")
    orig_stdout = orig_result.get("telemetry", {}).get("stdout_preview", "")
    
    if canary not in orig_stdout:
        return VerifierResult(verdict="INDETERMINATE", method="mini_verifier:hidden_exec", details="PoC failed to reproduce on original code.", confidence=0.0)
        
    patch_result = await _sandbox_run(poc_code, patched_repo, "python")
    patch_stdout = patch_result.get("telemetry", {}).get("stdout_preview", "")
    
    if canary in patch_stdout:
        return VerifierResult(verdict="FAIL", method="mini_verifier:hidden_exec", details="Exploit still works on patched code.", confidence=0.95)
        
    return VerifierResult(verdict="PASS", method="mini_verifier:hidden_exec", details="Exploit mitigated in patched code.", confidence=0.95)

# ═════════════════════════════════════════════════════════════
# TOOL 6 — Install Hook Verifier
# ═════════════════════════════════════════════════════════════
def _detect_runtime(filename: str) -> str:
    if filename.endswith(".py") or filename == "setup.py":
        return "python"
    elif filename.endswith(".js") or filename == "package.json":
        return "node"
    return "python"

async def verify_install_hook(finding: dict, original_repo: Path, patched_repo: Path):
    from agents.mini_verifier.agent import VerifierResult
    # Stage 2: dynamic sandbox egress monitoring pending (Detonator integration).
    return VerifierResult(
        verdict="INDETERMINATE",
        method="mini_verifier:install_egress",
        details="Dynamic sandbox verification not yet available (Stage 2).",
        confidence=0.0,
    )

# ═════════════════════════════════════════════════════════════
# TOOL 7 — CVE Verifier
# ═════════════════════════════════════════════════════════════
async def verify_cve(finding: dict, original_repo: Path, patched_repo: Path):
    from agents.mini_verifier.agent import VerifierResult
    filename = finding.get("filename", "")
    cve_id = finding.get("cve_id", "")
    package_name = finding.get("package_name", "")
    ecosystem = finding.get("ecosystem", "PyPI")
    
    if not filename or not cve_id or not package_name:
        return VerifierResult(verdict="INDETERMINATE", method="mini_verifier:osv_recheck", details="Missing filename, cve_id, or package_name in finding.", confidence=0.0)
        
    patched_file = patched_repo / filename
    if not patched_file.exists():
        return VerifierResult(verdict="INDETERMINATE", method="mini_verifier:osv_recheck", details=f"File {filename} not found in patched repo.", confidence=0.0)
        
    content = patched_file.read_text(encoding="utf-8", errors="replace")
    lockfile_type = filename.split("/")[-1]
    res = parse_lockfile(content, lockfile_type)
    
    patched_version = ""
    for dep in res.get("dependencies", []):
        if dep.get("name") == package_name:
            patched_version = dep.get("version", "")
            break
            
    if not patched_version:
        return VerifierResult(verdict="INDETERMINATE", method="mini_verifier:osv_recheck", details=f"Package {package_name} not found in patched lockfile.", confidence=0.0)
        
    osv = query_osv(package_name, patched_version, ecosystem)
    cve_present = any(v.get("cve_id") == cve_id for v in osv.get("vulnerabilities", []))
    
    if cve_present:
        return VerifierResult(verdict="FAIL",
                              method="mini_verifier:osv_recheck",
                              details=f"OSV says {package_name}@{patched_version} is still affected by {cve_id}",
                              confidence=0.9)
    return VerifierResult(verdict="PASS",
                          method="mini_verifier:osv_recheck",
                          details=f"OSV says {package_name}@{patched_version} is unaffected by {cve_id}",
                          confidence=0.95)
