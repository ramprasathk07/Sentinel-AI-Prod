"""
Shadow Stalker Tools — Stage 1

Deep static analysis tools for PR diffs:
  • Python AST analysis for dangerous patterns
  • Unicode homoglyph detection
  • Base64 payload detection
  • Dynamic code execution pattern matching
  • Obfuscation classification
"""

from __future__ import annotations

import ast
import base64
import re
import unicodedata


# ═════════════════════════════════════════════════════════════
# TOOL 1 — Python AST Analysis for Dangerous Patterns
# ═════════════════════════════════════════════════════════════

def analyze_python_ast(source_code: str, filename: str = "unknown.py") -> dict:
    """
    Parse Python source code into an AST and detect dangerous patterns:
    eval/exec calls, __import__ usage, dynamic attribute access, subprocess
    calls, and code hidden inside exception handlers.

    Args:
        source_code: Raw Python source code to analyze.
        filename:    Name of the file being analyzed (for reporting).

    Returns:
        A dict with 'findings' (list of detected patterns) and 'count'.
    """
    findings = []

    try:
        tree = ast.parse(source_code, filename=filename)
    except SyntaxError as exc:
        return {
            "error": f"SyntaxError: {exc}",
            "filename": filename,
            "findings": [],
            "count": 0,
        }

    # Dangerous function names
    DANGEROUS_CALLS = {
        "eval", "exec", "compile", "__import__", "getattr",
        "setattr", "delattr", "globals", "locals", "vars",
    }

    DANGEROUS_MODULES = {
        "subprocess", "os", "shutil", "ctypes", "importlib",
        "pickle", "shelve", "marshal", "tempfile",
    }

    NETWORK_MODULES = {
        "socket", "http", "urllib", "requests", "httpx",
        "aiohttp", "ftplib", "smtplib",
    }

    def _get_context(line_num):
        lines = source_code.splitlines()
        idx = line_num - 1
        start = max(0, idx - 1)
        end = min(len(lines), idx + 2)
        return "\n".join(lines[start:end])

    for node in ast.walk(tree):
        # Detect eval/exec/compile/__import__ calls
        if isinstance(node, ast.Call):
            func_name = _get_call_name(node)
            if func_name in DANGEROUS_CALLS:
                findings.append({
                    "type": "dangerous_call",
                    "pattern": func_name,
                    "line": node.lineno,
                    "col": node.col_offset,
                    "severity": "HIGH" if func_name in ("eval", "exec") else "MEDIUM",
                    "description": f"Dynamic code execution via {func_name}()",
                    "filename": filename,
                    "before": _get_context(node.lineno)
                })

        # Detect dangerous imports
        if isinstance(node, ast.Import):
            for alias in node.names:
                mod = alias.name.split(".")[0]
                if mod in DANGEROUS_MODULES:
                    findings.append({
                        "type": "dangerous_import",
                        "pattern": alias.name,
                        "line": node.lineno,
                        "severity": "MEDIUM",
                        "description": f"Import of security-sensitive module: {alias.name}",
                        "filename": filename,
                        "before": _get_context(node.lineno)
                    })
                if mod in NETWORK_MODULES:
                    findings.append({
                        "type": "network_import",
                        "pattern": alias.name,
                        "line": node.lineno,
                        "severity": "MEDIUM",
                        "description": f"Network-capable module imported: {alias.name}",
                        "filename": filename,
                        "before": _get_context(node.lineno)
                    })

        if isinstance(node, ast.ImportFrom):
            mod = (node.module or "").split(".")[0]
            if mod in DANGEROUS_MODULES:
                findings.append({
                    "type": "dangerous_import",
                    "pattern": node.module,
                    "line": node.lineno,
                    "severity": "MEDIUM",
                    "description": f"Import from security-sensitive module: {node.module}",
                    "filename": filename,
                    "before": _get_context(node.lineno)
                })
            if mod in NETWORK_MODULES:
                findings.append({
                    "type": "network_import",
                    "pattern": node.module,
                    "line": node.lineno,
                    "severity": "MEDIUM",
                    "description": f"Network-capable module imported: {node.module}",
                    "filename": filename,
                    "before": _get_context(node.lineno)
                })

        # Detect code hidden in exception handlers (catch-all)
        if isinstance(node, ast.ExceptHandler):
            if node.type is None:  # bare except:
                body_calls = [
                    n for n in ast.walk(node)
                    if isinstance(n, ast.Call) and _get_call_name(n) in DANGEROUS_CALLS
                ]
                if body_calls:
                    for c in body_calls:
                        findings.append({
                            "type": "hidden_in_except",
                            "pattern": _get_call_name(c),
                            "line": c.lineno,
                            "severity": "CRITICAL",
                            "description": (
                                f"Dangerous call {_get_call_name(c)}() hidden inside "
                                f"bare except handler — likely obfuscation"
                            ),
                            "filename": filename,
                            "before": _get_context(c.lineno)
                        })

        # Detect string concatenation used to build eval/exec args
        if isinstance(node, ast.Call):
            func_name = _get_call_name(node)
            if func_name in ("eval", "exec") and node.args:
                arg = node.args[0]
                if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
                    findings.append({
                        "type": "obfuscated_eval",
                        "pattern": f"{func_name}_with_concatenation",
                        "line": node.lineno,
                        "severity": "CRITICAL",
                        "description": (
                            f"{func_name}() called with string concatenation — "
                            f"possible payload obfuscation"
                        ),
                        "filename": filename,
                    })

    return {
        "filename": filename,
        "findings": findings,
        "count": len(findings),
        "lines_analyzed": len(source_code.splitlines()),
    }


# ═════════════════════════════════════════════════════════════
# TOOL 2 — Unicode Homoglyph Detection
# ═════════════════════════════════════════════════════════════

def detect_homoglyphs(source_code: str, filename: str = "unknown") -> dict:
    """
    Scan source code for Unicode homoglyph attacks — characters that look
    identical to ASCII but are from different Unicode blocks (e.g., Cyrillic
    'о' U+043E substituting Latin 'o' U+006F in identifiers).

    Args:
        source_code: Raw source code text to scan.
        filename:    Name of the file being scanned.

    Returns:
        A dict with 'homoglyphs' (list of suspicious characters found) and 'count'.
    """
    # Common confusable mappings: non-ASCII char → ASCII lookalike
    CONFUSABLES = {
        "\u0410": "A",  # Cyrillic А
        "\u0412": "B",  # Cyrillic В
        "\u0421": "C",  # Cyrillic С
        "\u0415": "E",  # Cyrillic Е
        "\u041d": "H",  # Cyrillic Н
        "\u041a": "K",  # Cyrillic К
        "\u041c": "M",  # Cyrillic М
        "\u041e": "O",  # Cyrillic О
        "\u0420": "P",  # Cyrillic Р
        "\u0422": "T",  # Cyrillic Т
        "\u0425": "X",  # Cyrillic Х
        "\u0430": "a",  # Cyrillic а
        "\u0435": "e",  # Cyrillic е
        "\u043e": "o",  # Cyrillic о
        "\u0440": "p",  # Cyrillic р
        "\u0441": "c",  # Cyrillic с
        "\u0443": "y",  # Cyrillic у
        "\u0445": "x",  # Cyrillic х
        "\u0456": "i",  # Cyrillic і
        "\u0458": "j",  # Cyrillic ј
        "\u0455": "s",  # Cyrillic ѕ
        "\u04bb": "h",  # Cyrillic һ
        "\u0501": "d",  # Cyrillic ԁ
        "\u051b": "q",  # Cyrillic ԛ
        "\u051d": "w",  # Cyrillic ԝ
        "\u0261": "g",  # Latin ɡ
        "\u01c3": "!",  # Latin ǃ
        "\uff01": "!",  # Fullwidth !
        "\u2024": ".",  # One Dot Leader
        "\uff0e": ".",  # Fullwidth .
    }

    homoglyphs = []

    for line_num, line in enumerate(source_code.splitlines(), start=1):
        for col, char in enumerate(line):
            if char in CONFUSABLES:
                ascii_equiv = CONFUSABLES[char]
                homoglyphs.append({
                    "line": line_num,
                    "column": col,
                    "char": char,
                    "unicode_name": unicodedata.name(char, "UNKNOWN"),
                    "codepoint": f"U+{ord(char):04X}",
                    "ascii_lookalike": ascii_equiv,
                    "context": line.strip()[:100],
                    "severity": "CRITICAL",
                })
            elif ord(char) > 127:
                # Flag any non-ASCII character in code (not in strings/comments)
                cat = unicodedata.category(char)
                if cat.startswith("L"):  # Letter category
                    homoglyphs.append({
                        "line": line_num,
                        "column": col,
                        "char": char,
                        "unicode_name": unicodedata.name(char, "UNKNOWN"),
                        "codepoint": f"U+{ord(char):04X}",
                        "ascii_lookalike": "?",
                        "context": line.strip()[:100],
                        "severity": "HIGH",
                    })

    return {
        "filename": filename,
        "homoglyphs": homoglyphs,
        "count": len(homoglyphs),
    }


# ═════════════════════════════════════════════════════════════
# TOOL 3 — Base64 Payload Detection
# ═════════════════════════════════════════════════════════════

def detect_base64_payloads(source_code: str, filename: str = "unknown", min_length: int = 50) -> dict:
    """
    Scan source code for base64-encoded strings longer than a threshold.
    Attempts to decode each match and flags those containing executable
    patterns (import, eval, exec, http, etc.).

    Args:
        source_code: Raw source code text to scan.
        filename:    Name of the file being scanned.
        min_length:  Minimum length of base64 string to flag (default: 50).

    Returns:
        A dict with 'payloads' (list of detected base64 strings) and 'count'.
    """
    # Match base64 strings (inside quotes or standalone)
    b64_pattern = re.compile(
        r'["\']([A-Za-z0-9+/]{' + str(min_length) + r',}={0,2})["\']'
    )

    payloads = []

    for line_num, line in enumerate(source_code.splitlines(), start=1):
        for match in b64_pattern.finditer(line):
            b64_str = match.group(1)
            decoded = None
            is_suspicious = False

            try:
                decoded_bytes = base64.b64decode(b64_str)
                decoded = decoded_bytes.decode("utf-8", errors="replace")

                # Check for suspicious decoded content
                suspicious_patterns = [
                    "import", "eval", "exec", "subprocess", "os.system",
                    "http://", "https://", "socket", "__import__",
                    "powershell", "cmd.exe", "/bin/sh", "/bin/bash",
                    "curl ", "wget ", "chmod ", "base64",
                ]
                for pat in suspicious_patterns:
                    if pat.lower() in decoded.lower():
                        is_suspicious = True
                        break
            except Exception:
                pass

            payloads.append({
                "line": line_num,
                "encoded_preview": b64_str[:80] + ("..." if len(b64_str) > 80 else ""),
                "encoded_length": len(b64_str),
                "decoded_preview": (decoded[:200] if decoded else None),
                "is_suspicious": is_suspicious,
                "severity": "CRITICAL" if is_suspicious else "MEDIUM",
                "filename": filename,
            })

    return {
        "filename": filename,
        "payloads": payloads,
        "count": len(payloads),
    }


# ═════════════════════════════════════════════════════════════
# TOOL 4 — Regex Pattern Scanner (multi-language)
# ═════════════════════════════════════════════════════════════

def scan_with_patterns(source_code: str, filename: str = "unknown", language: str = "python") -> dict:
    """
    Scan source code against a curated regex pattern library for supply-chain
    attack indicators across Python, JavaScript, Go, and Rust.

    Args:
        source_code: Raw source code to scan.
        filename:    Name of the file being scanned.
        language:    Programming language — one of 'python', 'javascript', 'go', 'rust'.

    Returns:
        A dict with 'matches' (list of pattern hits) and 'count'.
    """
    patterns = _get_patterns_for_language(language)
    matches = []

    for line_num, line in enumerate(source_code.splitlines(), start=1):
        for pattern_info in patterns:
            regex = pattern_info["regex"]
            if re.search(regex, line):
                matches.append({
                    "line": line_num,
                    "pattern_name": pattern_info["name"],
                    "category": pattern_info["category"],
                    "severity": pattern_info["severity"],
                    "description": pattern_info["description"],
                    "matched_line": line.strip()[:200],
                    "filename": filename,
                })

    return {
        "filename": filename,
        "language": language,
        "matches": matches,
        "count": len(matches),
    }


# ═════════════════════════════════════════════════════════════
# TOOL 5 — PR Diff Parser (extract added lines)
# ═════════════════════════════════════════════════════════════

def parse_pr_diff(diff_content: str) -> dict:
    """
    Parse a unified diff (git diff format) and extract only added lines
    with their file paths and line numbers — these are what the PR introduces.

    Args:
        diff_content: Raw unified diff text (git diff output).

    Returns:
        A dict with 'files' — a list of {filename, added_lines} objects.
    """
    files = {}
    current_file = None
    current_line_num = 0

    for line in diff_content.splitlines():
        # Detect file headers
        if line.startswith("+++ b/"):
            current_file = line[6:]
            if current_file not in files:
                files[current_file] = []

        # Detect hunk headers: @@ -old,count +new,count @@
        elif line.startswith("@@"):
            hunk_match = re.search(r"\+(\d+)", line)
            if hunk_match:
                current_line_num = int(hunk_match.group(1)) - 1

        # Added lines (start with + but not +++)
        elif line.startswith("+") and not line.startswith("+++"):
            current_line_num += 1
            if current_file:
                files[current_file].append({
                    "line_number": current_line_num,
                    "content": line[1:],  # strip leading +
                })

        # Context/unchanged lines increment line counter
        elif not line.startswith("-"):
            current_line_num += 1

    result = [
        {
            "filename": fname,
            "added_lines": lines,
            "added_count": len(lines),
        }
        for fname, lines in files.items()
    ]

    return {
        "files": result,
        "total_files": len(result),
        "total_added_lines": sum(f["added_count"] for f in result),
    }


# ─────────────────────────────────────────────────────────────
# Private helpers
# ─────────────────────────────────────────────────────────────

def _get_call_name(node: ast.Call) -> str:
    """Extract function name from an ast.Call node."""
    if isinstance(node.func, ast.Name):
        return node.func.id
    elif isinstance(node.func, ast.Attribute):
        return node.func.attr
    return ""


def _get_patterns_for_language(language: str) -> list[dict]:
    """Return curated regex patterns for a given language."""
    common = [
        {
            "name": "hardcoded_ip",
            "regex": r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
            "category": "network",
            "severity": "MEDIUM",
            "description": "Hardcoded IP address detected",
        },
        {
            "name": "hardcoded_secret",
            "regex": r"""(?i)(api[_-]?key|secret|password|token|credential)\s*[=:]\s*["'][^"']{8,}["']""",
            "category": "secrets",
            "severity": "HIGH",
            "description": "Potential hardcoded secret or API key",
        },
        {
            "name": "data_exfil_url",
            "regex": r"""https?://[^\s"']+\.(ru|cn|tk|ml|ga|cf|top|xyz)/""",
            "category": "exfiltration",
            "severity": "HIGH",
            "description": "URL with suspicious TLD — potential data exfiltration endpoint",
        },
    ]

    python_patterns = [
        {
            "name": "eval_exec",
            "regex": r"\b(eval|exec)\s*\(",
            "category": "code_execution",
            "severity": "HIGH",
            "description": "Dynamic code execution via eval()/exec()",
        },
        {
            "name": "dunder_import",
            "regex": r"__import__\s*\(",
            "category": "code_execution",
            "severity": "HIGH",
            "description": "Dynamic import via __import__()",
        },
        {
            "name": "os_system",
            "regex": r"os\.(system|popen|exec[lv]?[pe]?)\s*\(",
            "category": "code_execution",
            "severity": "HIGH",
            "description": "OS command execution detected",
        },
        {
            "name": "subprocess_call",
            "regex": r"subprocess\.(call|run|Popen|check_output)\s*\(",
            "category": "code_execution",
            "severity": "HIGH",
            "description": "Subprocess execution detected",
        },
        {
            "name": "pickle_load",
            "regex": r"pickle\.(loads?|Unpickler)\s*\(",
            "category": "deserialization",
            "severity": "HIGH",
            "description": "Pickle deserialization — potential RCE vector",
        },
        {
            "name": "setup_py_install",
            "regex": r"class\s+\w+\s*\(\s*(install|develop)\s*\)",
            "category": "install_hook",
            "severity": "CRITICAL",
            "description": "Custom setup.py install hook — runs code during pip install",
        },
        {
            "name": "env_var_read",
            "regex": r"os\.environ\[|os\.getenv\(",
            "category": "data_access",
            "severity": "LOW",
            "description": "Environment variable access detected",
        },
    ]

    javascript_patterns = [
        {
            "name": "eval",
            "regex": r"\beval\s*\(",
            "category": "code_execution",
            "severity": "HIGH",
            "description": "Dynamic code execution via eval()",
        },
        {
            "name": "function_constructor",
            "regex": r"new\s+Function\s*\(",
            "category": "code_execution",
            "severity": "HIGH",
            "description": "Dynamic code via Function constructor",
        },
        {
            "name": "child_process",
            "regex": r"require\s*\(\s*['\"]child_process['\"]\s*\)",
            "category": "code_execution",
            "severity": "HIGH",
            "description": "child_process module — shell command execution",
        },
        {
            "name": "preinstall_script",
            "regex": r'"(preinstall|postinstall|preuninstall)"\s*:',
            "category": "install_hook",
            "severity": "CRITICAL",
            "description": "npm lifecycle script — runs during install",
        },
        {
            "name": "dns_exfil",
            "regex": r"require\s*\(\s*['\"]dns['\"]\s*\)",
            "category": "exfiltration",
            "severity": "HIGH",
            "description": "DNS module — potential data exfiltration via DNS",
        },
        {
            "name": "process_env",
            "regex": r"process\.env\b",
            "category": "data_access",
            "severity": "LOW",
            "description": "Environment variable access via process.env",
        },
    ]

    go_patterns = [
        {
            "name": "exec_command",
            "regex": r"exec\.Command\s*\(",
            "category": "code_execution",
            "severity": "HIGH",
            "description": "OS command execution via exec.Command()",
        },
        {
            "name": "os_exec",
            "regex": r"syscall\.Exec\s*\(",
            "category": "code_execution",
            "severity": "HIGH",
            "description": "Direct syscall execution",
        },
        {
            "name": "net_http",
            "regex": r"http\.(Get|Post|Do)\s*\(",
            "category": "network",
            "severity": "MEDIUM",
            "description": "HTTP network request detected",
        },
    ]

    rust_patterns = [
        {
            "name": "command_exec",
            "regex": r"Command::new\s*\(",
            "category": "code_execution",
            "severity": "HIGH",
            "description": "OS command execution via Command::new()",
        },
        {
            "name": "unsafe_block",
            "regex": r"\bunsafe\s*\{",
            "category": "unsafe",
            "severity": "MEDIUM",
            "description": "Unsafe Rust block — bypasses memory safety",
        },
        {
            "name": "build_script",
            "regex": r"fn\s+main\s*\(\s*\).*build\.rs",
            "category": "install_hook",
            "severity": "HIGH",
            "description": "Cargo build script — runs during compilation",
        },
    ]

    lang_map = {
        "python": common + python_patterns,
        "javascript": common + javascript_patterns,
        "go": common + go_patterns,
        "rust": common + rust_patterns,
    }

    return lang_map.get(language, common)


# ═════════════════════════════════════════════════════════════
# TOOL 6 — Full 3-Stage Orchestrator
# ═════════════════════════════════════════════════════════════

# File extension → language mapping
_EXT_LANG = {
    ".py": "python", ".pyw": "python",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "javascript", ".jsx": "javascript", ".tsx": "javascript",
    ".go": "go",
    ".rs": "rust",
}


def run_full_scan(diff_content: str, file_contents_map: dict[str, str]) -> dict:
    """
    Run the complete 3-stage deep static analysis pipeline on a PR diff.

    Stage 1: Parse diff → run AST analysis + homoglyph + base64 + regex
    Stage 2: For files with Stage 1 hits, run CPG analysis + hidden payloads
    Stage 3: Search critical findings against known attack pattern corpus

    Args:
        diff_content:      Raw unified diff text (git diff output).
        file_contents_map: Dict mapping filename → full source code for each
                           changed file. Keys should match diff filenames.

    Returns:
        A dict with consolidated 'findings', per-file breakdowns, and
        aggregate risk score.
    """
    from agents.shadow_stalker.cpg_analyzer import analyze_cpg, detect_hidden_payloads
    from agents.shadow_stalker.embedding_store import search_known_attacks, store_flagged_pattern

    all_findings = []
    file_reports = {}

    # ── Stage 0: Parse the diff ─────────────────────────────
    diff_result = parse_pr_diff(diff_content)

    # ── Stage 1: AST + Regex + Homoglyphs + Base64 ──────────
    for file_info in diff_result["files"]:
        fname = file_info["filename"]
        ext = "." + fname.rsplit(".", 1)[-1] if "." in fname else ""
        lang = _EXT_LANG.get(ext, "")
        file_findings = []

        # Get full source if available, otherwise reconstruct from added lines
        source = file_contents_map.get(fname, "")
        if not source:
            source = "\n".join(l["content"] for l in file_info["added_lines"])

        def _add_context(finding):
            if "before" in finding: return finding
            line_num = finding.get("line")
            if not line_num: return finding
            lines = source.splitlines()
            idx = line_num - 1
            start = max(0, idx - 1)
            end = min(len(lines), idx + 2)
            finding["before"] = "\n".join(lines[start:end])
            return finding

        # 1a. Python AST analysis
        if lang == "python":
            ast_result = analyze_python_ast(source, fname)
            for f in ast_result.get("findings", []):
                file_findings.append(_add_context({
                    **f, "stage": "stage1",
                    "technique": _classify_technique(f.get("type", "")),
                }))

        # 1b. Homoglyph detection (all languages)
        homo_result = detect_homoglyphs(source, fname)
        for h in homo_result.get("homoglyphs", []):
            file_findings.append(_add_context({
                "type": "homoglyph",
                "pattern": f"{h['char']} ({h['codepoint']})",
                "line": h["line"],
                "severity": h["severity"],
                "description": (
                    f"Unicode homoglyph: {h['unicode_name']} ({h['codepoint']}) "
                    f"looks like ASCII '{h['ascii_lookalike']}'"
                ),
                "evidence": h["context"],
                "filename": fname,
                "stage": "stage1",
                "technique": "homoglyph",
            }))

        # 1c. Base64 payload detection
        b64_result = detect_base64_payloads(source, fname)
        for p in b64_result.get("payloads", []):
            file_findings.append(_add_context({
                "type": "base64_payload",
                "pattern": "base64_encoded_string",
                "line": p["line"],
                "severity": p["severity"],
                "description": f"Base64 string ({p['encoded_length']} chars)" + (
                    f" — decoded contains suspicious content" if p["is_suspicious"] else ""
                ),
                "evidence": p["encoded_preview"],
                "filename": fname,
                "stage": "stage1",
                "technique": "base64_payload",
            }))

        # 1c2. Vibe-coding smells (AI-generated patterns)
        from agents.shadow_stalker.vibe_detector import detect_vibe_smells
        vibe_result = detect_vibe_smells(source, fname)
        for vf in vibe_result.get("findings", []):
            file_findings.append(_add_context(vf))

        # 1d. Regex pattern scan
        if lang:
            regex_result = scan_with_patterns(source, fname, lang)
            for m in regex_result.get("matches", []):
                file_findings.append(_add_context({
                    "type": m["category"],
                    "pattern": m["pattern_name"],
                    "line": m["line"],
                    "severity": m["severity"],
                    "description": m["description"],
                    "evidence": m["matched_line"],
                    "filename": fname,
                    "stage": "stage1",
                    "technique": _classify_technique(m["category"]),
                }))

        # ── Stage 2: CPG analysis for files with hits ───────
        if file_findings and lang:
            cpg_result = analyze_cpg(source, lang, fname)
            for f in cpg_result.get("findings", []):
                file_findings.append({
                    **f,
                    "technique": _classify_technique(f.get("type", "")),
                })

            hidden_result = detect_hidden_payloads(source, lang, fname)
            for f in hidden_result.get("findings", []):
                file_findings.append({
                    **f,
                    "technique": _classify_technique(f.get("type", "")),
                })

        # ── Stage 3: Similarity search for critical findings ─
        critical_findings = [f for f in file_findings if f.get("severity") == "CRITICAL"]
        for cf in critical_findings[:5]:  # limit to top 5 to avoid overload
            evidence = cf.get("evidence", "")
            if evidence:
                sim_result = search_known_attacks(evidence, fname, top_k=3)
                if sim_result["matches"]:
                    cf["similar_known_attacks"] = sim_result["matches"]

                # Store the pattern for future matching
                store_flagged_pattern(
                    evidence,
                    cf.get("type", "unknown"),
                    cf.get("severity", "HIGH"),
                    fname,
                )

        for f in file_findings:
            line_idx = f.get("line", 1) - 1
            source_lines = source.splitlines()
            if 0 <= line_idx < len(source_lines):
                f["before"] = source_lines[line_idx]
            f["filename"] = fname

        file_reports[fname] = {
            "findings": file_findings,
            "count": len(file_findings),
            "language": lang,
            "source": source,  # full reconstructed file content for PatchForge
        }
        all_findings.extend(file_findings)

    # ── Aggregate risk score ────────────────────────────────
    risk_score = _calculate_risk_score(all_findings)

    return {
        "findings": all_findings,
        "total_findings": len(all_findings),
        "files_analyzed": len(file_reports),
        "lines_analyzed": diff_result["total_added_lines"],
        "file_reports": file_reports,
        "risk_score": risk_score,
        "summary": _generate_summary(all_findings, risk_score),
    }


def _classify_technique(finding_type: str) -> str:
    """Map internal finding types to ObfuscationTechnique enum values."""
    mapping = {
        "dangerous_call": "dynamic_execution",
        "dangerous_import": "obfuscated_import",
        "network_import": "obfuscated_import",
        "hidden_in_except": "hidden_in_except",
        "obfuscated_eval": "string_concat_eval",
        "dead_code_payload": "dead_code_payload",
        "taint_propagation": "taint_propagation",
        "obfuscation_chain": "dynamic_execution",
        "hidden_in_handler": "hidden_in_except",
        "hidden_atexit": "hidden_in_except",
        "hidden_in_destructor": "hidden_in_except",
        "hidden_signal_handler": "hidden_in_except",
        "hidden_exit_handler": "hidden_in_except",
        "hidden_timer_eval": "dynamic_execution",
        "hidden_in_error_handler": "hidden_in_except",
        "homoglyph": "homoglyph",
        "base64_payload": "base64_payload",
        "code_execution": "dynamic_execution",
        "install_hook": "install_hook",
        "secrets": "encoded_shell",
        "exfiltration": "encoded_shell",
        "deserialization": "dynamic_execution",
        "unsafe": "dynamic_execution",
    }
    return mapping.get(finding_type, "dynamic_execution")


def _calculate_risk_score(findings: list[dict]) -> float:
    """Calculate aggregate risk score 0.0–10.0 from findings."""
    if not findings:
        return 0.0

    severity_weights = {"CRITICAL": 4.0, "HIGH": 2.5, "MEDIUM": 1.0, "LOW": 0.3}
    total = sum(severity_weights.get(f.get("severity", "LOW"), 0.3) for f in findings)

    # Normalize to 0–10 scale (cap at 10)
    score = min(10.0, total * 0.5)
    return round(score, 1)


def _generate_summary(findings: list[dict], risk_score: float) -> str:
    """Generate a human-readable summary of scan results."""
    if not findings:
        return "No suspicious patterns detected. Risk: LOW."

    severity_counts = {}
    for f in findings:
        sev = f.get("severity", "UNKNOWN")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    parts = [f"Found {len(findings)} suspicious patterns."]
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = severity_counts.get(sev, 0)
        if count:
            parts.append(f"{sev}: {count}")

    risk_label = (
        "CRITICAL" if risk_score >= 8 else
        "HIGH" if risk_score >= 5 else
        "MEDIUM" if risk_score >= 2 else "LOW"
    )
    parts.append(f"Overall risk: {risk_label} ({risk_score}/10)")

    return " | ".join(parts)
