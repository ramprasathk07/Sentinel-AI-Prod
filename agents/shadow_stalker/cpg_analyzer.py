"""
Shadow Stalker — Stage 2: Code Property Graph Analyzer

Combines CFG + data flow + AST to detect obfuscation that regex misses:
  • Taint propagation: source → sink tracking
  • Dead-code payload detection in unreachable branches
  • Multi-step obfuscation chains (b64decode → exec)
  • Hidden payloads in error handlers and atexit hooks
"""

from __future__ import annotations


from agents.shadow_stalker.cfg_builder import (
    build_cfg, find_unreachable_blocks, extract_call_graph,
    CallGraphEntry, _TREE_SITTER_AVAILABLE,
)

# Dangerous sinks — functions where tainted data is exploitable
_SINKS = {
    "eval", "exec", "compile", "__import__", "system", "popen",
    "call", "run", "Popen", "check_output",  # subprocess
    "loads", "Unpickler",  # pickle
    "execl", "execlp", "execle", "execv", "execvp", "execvpe",
}

# Taint sources — functions/objects that introduce external data
_SOURCES = {
    "input", "getenv", "environ", "argv",
    "request", "args", "form", "json", "data",  # web frameworks
    "recv", "read", "readline", "readlines",
    "urlopen", "get", "post",  # network
}

# Obfuscation intermediaries — functions used to transform payloads
_TRANSFORMS = {
    "b64decode", "b64encode", "decode", "encode",
    "decompress", "loads", "fromhex", "unhexlify",
    "codecs.decode", "rot13", "zlib.decompress",
    "join", "replace", "format", "chr", "ord",
}


def analyze_cpg(
    source_code: str,
    language: str = "python",
    filename: str = "unknown",
) -> dict:
    """
    Build a Code Property Graph from source code and detect advanced
    obfuscation patterns that simple regex cannot catch.

    Performs:
      1. CFG construction via tree-sitter
      2. Taint propagation: tracks external data to dangerous sinks
      3. Dead-code analysis: payloads hidden in unreachable branches
      4. Multi-step obfuscation chain detection (e.g. b64decode → exec)

    Args:
        source_code: Raw source code to analyze.
        language:    Programming language (python/javascript/go/rust).
        filename:    Name of the file being analyzed.

    Returns:
        A dict with 'findings' (list of detected issues), 'cfg_summary',
        and metadata.
    """
    findings = []
    cfgs = build_cfg(source_code, language)

    # ── 1. Dead-code payload detection ──────────────────────
    unreachable = find_unreachable_blocks(cfgs)
    for block in unreachable:
        dangerous_calls = [c for c in block.calls if c in _SINKS]
        if dangerous_calls:
            findings.append({
                "type": "dead_code_payload",
                "line": block.start_line,
                "end_line": block.end_line,
                "severity": "CRITICAL",
                "description": (
                    f"Dangerous call(s) [{', '.join(dangerous_calls)}] found in "
                    f"{'error handler' if block.is_error_handler else 'dead code'} "
                    f"block ({block.node_type})"
                ),
                "evidence": block.text_preview,
                "confidence": 0.85 if block.is_error_handler else 0.90,
                "filename": filename,
                "stage": "stage2",
            })

    # ── 2. Taint propagation ────────────────────────────────
    call_graph = extract_call_graph(cfgs)
    taint_chains = _find_taint_chains(call_graph)
    for chain in taint_chains:
        findings.append({
            "type": "taint_propagation",
            "line": chain["source_line"],
            "severity": "CRITICAL",
            "description": (
                f"Tainted data flows from {chain['source']} to dangerous "
                f"sink {chain['sink']} via: {' → '.join(chain['path'])}"
            ),
            "evidence": f"Source: {chain['source']}, Sink: {chain['sink']}",
            "confidence": chain.get("confidence", 0.75),
            "filename": filename,
            "stage": "stage2",
        })

    # ── 3. Multi-step obfuscation chains ────────────────────
    obfusc_chains = _find_obfuscation_chains(call_graph)
    for chain in obfusc_chains:
        findings.append({
            "type": "obfuscation_chain",
            "line": chain["line"],
            "severity": "HIGH",
            "description": (
                f"Multi-step obfuscation detected: {' → '.join(chain['steps'])} "
                f"ending in dangerous sink"
            ),
            "evidence": f"Chain: {' → '.join(chain['steps'])}",
            "confidence": 0.80,
            "filename": filename,
            "stage": "stage2",
        })

    # ── 4. Calls in error handlers ──────────────────────────
    for cfg in cfgs:
        for block in cfg.get_error_handler_blocks():
            suspicious = [c for c in block.calls if c in _SINKS | _TRANSFORMS]
            if suspicious:
                findings.append({
                    "type": "hidden_in_handler",
                    "line": block.start_line,
                    "end_line": block.end_line,
                    "severity": "HIGH",
                    "description": (
                        f"Suspicious call(s) [{', '.join(suspicious)}] inside "
                        f"error handler ({block.node_type}) in {cfg.function_name}()"
                    ),
                    "evidence": block.text_preview,
                    "confidence": 0.80,
                    "filename": filename,
                    "stage": "stage2",
                })

    # ── CFG summary for report ──────────────────────────────
    cfg_summary = {
        "functions_analyzed": len(cfgs),
        "total_blocks": sum(c.block_count for c in cfgs),
        "error_handler_blocks": sum(len(c.get_error_handler_blocks()) for c in cfgs),
        "dead_code_blocks": sum(len(c.get_dead_code_blocks()) for c in cfgs),
        "call_graph_edges": len(call_graph),
        "tree_sitter_available": _TREE_SITTER_AVAILABLE,
    }

    return {
        "filename": filename,
        "language": language,
        "findings": findings,
        "count": len(findings),
        "cfg_summary": cfg_summary,
    }


def detect_hidden_payloads(
    source_code: str,
    language: str = "python",
    filename: str = "unknown",
) -> dict:
    """
    Specifically target payloads hidden in rarely-executed code paths:
      • except/catch/finally blocks
      • if __name__ == '__main__' guards
      • atexit handlers
      • signal handlers
      • __del__ destructors

    Args:
        source_code: Raw source code to analyze.
        language:    Programming language.
        filename:    Name of the file being analyzed.

    Returns:
        A dict with 'findings' (list of hidden payloads detected).
    """
    import re
    findings = []
    lines = source_code.splitlines()

    # ── Python-specific hidden execution points ─────────────
    if language.lower() in ("python", "py"):
        # atexit handlers
        atexit_pat = re.compile(r'atexit\.(register|unregister)\s*\(')
        for i, line in enumerate(lines, 1):
            if atexit_pat.search(line):
                findings.append({
                    "type": "hidden_atexit",
                    "line": i,
                    "severity": "HIGH",
                    "description": "Code registered via atexit — runs at interpreter exit",
                    "evidence": line.strip()[:200],
                    "confidence": 0.70,
                    "filename": filename,
                    "stage": "stage2",
                })

        # __del__ destructors with dangerous calls
        del_pat = re.compile(r'def\s+__del__\s*\(')
        for i, line in enumerate(lines, 1):
            if del_pat.search(line):
                # Check the body for dangerous calls
                body_end = min(i + 20, len(lines))
                body = "\n".join(lines[i:body_end])
                for sink in _SINKS:
                    if re.search(rf'\b{re.escape(sink)}\s*\(', body):
                        findings.append({
                            "type": "hidden_in_destructor",
                            "line": i,
                            "severity": "CRITICAL",
                            "description": (
                                f"Dangerous call {sink}() inside __del__ destructor — "
                                f"executes during garbage collection"
                            ),
                            "evidence": body[:200],
                            "confidence": 0.85,
                            "filename": filename,
                            "stage": "stage2",
                        })
                        break

        # signal handlers with dangerous calls
        signal_pat = re.compile(r'signal\.signal\s*\(')
        for i, line in enumerate(lines, 1):
            if signal_pat.search(line):
                findings.append({
                    "type": "hidden_signal_handler",
                    "line": i,
                    "severity": "MEDIUM",
                    "description": "Signal handler registered — runs on OS signal",
                    "evidence": line.strip()[:200],
                    "confidence": 0.60,
                    "filename": filename,
                    "stage": "stage2",
                })

    # ── JavaScript-specific hidden execution ────────────────
    if language.lower() in ("javascript", "js"):
        # process.on('exit') handlers
        exit_pat = re.compile(r"process\.on\s*\(\s*['\"]exit['\"]")
        for i, line in enumerate(lines, 1):
            if exit_pat.search(line):
                findings.append({
                    "type": "hidden_exit_handler",
                    "line": i,
                    "severity": "HIGH",
                    "description": "Code in process exit handler — runs at process termination",
                    "evidence": line.strip()[:200],
                    "confidence": 0.75,
                    "filename": filename,
                    "stage": "stage2",
                })

        # setTimeout/setInterval with suspicious strings
        timer_pat = re.compile(r'(setTimeout|setInterval)\s*\(\s*["\']')
        for i, line in enumerate(lines, 1):
            if timer_pat.search(line):
                findings.append({
                    "type": "hidden_timer_eval",
                    "line": i,
                    "severity": "HIGH",
                    "description": "String passed to timer function — implicit eval()",
                    "evidence": line.strip()[:200],
                    "confidence": 0.80,
                    "filename": filename,
                    "stage": "stage2",
                })

    # ── Use CFG for structural analysis ─────────────────────
    cfgs = build_cfg(source_code, language)
    for cfg in cfgs:
        for block in cfg.get_error_handler_blocks():
            has_sink = any(c in _SINKS for c in block.calls)
            has_transform = any(c in _TRANSFORMS for c in block.calls)
            if has_sink or has_transform:
                findings.append({
                    "type": "hidden_in_error_handler",
                    "line": block.start_line,
                    "end_line": block.end_line,
                    "severity": "CRITICAL" if has_sink else "HIGH",
                    "description": (
                        f"{'Dangerous sink' if has_sink else 'Transform function'} "
                        f"[{', '.join(block.calls)}] inside error handler "
                        f"in {cfg.function_name}()"
                    ),
                    "evidence": block.text_preview,
                    "confidence": 0.85,
                    "filename": filename,
                    "stage": "stage2",
                })

    return {
        "filename": filename,
        "findings": findings,
        "count": len(findings),
    }


# ═══════════════════════════════════════════════════════════
# Internal analysis helpers
# ═══════════════════════════════════════════════════════════

def _find_taint_chains(call_graph: list[CallGraphEntry]) -> list[dict]:
    """Find paths from taint sources to dangerous sinks in the call graph."""
    chains = []
    source_edges = [e for e in call_graph if e.callee in _SOURCES]
    sink_edges = [e for e in call_graph if e.callee in _SINKS]

    # Build adjacency from caller→callee
    adj: dict[str, list[CallGraphEntry]] = {}
    for edge in call_graph:
        adj.setdefault(edge.caller, []).append(edge)

    for src in source_edges:
        for snk in sink_edges:
            if src.caller == snk.caller:
                # Same function: direct source→sink
                chains.append({
                    "source": src.callee,
                    "sink": snk.callee,
                    "source_line": src.line,
                    "path": [src.callee, snk.callee],
                    "confidence": 0.75,
                })
            else:
                # Check one-hop: source_func calls sink_func
                for edge in adj.get(src.caller, []):
                    if edge.callee == snk.caller:
                        chains.append({
                            "source": src.callee,
                            "sink": snk.callee,
                            "source_line": src.line,
                            "path": [src.callee, edge.callee, snk.callee],
                            "confidence": 0.60,
                        })
    return chains


def _find_obfuscation_chains(call_graph: list[CallGraphEntry]) -> list[dict]:
    """Detect transform → sink chains (e.g. b64decode → exec)."""
    chains = []
    for edge in call_graph:
        if edge.callee in _TRANSFORMS:
            # Look for a sink in the same function
            for other in call_graph:
                if other.caller == edge.caller and other.callee in _SINKS:
                    chains.append({
                        "line": edge.line,
                        "steps": [edge.callee, other.callee],
                        "function": edge.caller,
                    })
    return chains
