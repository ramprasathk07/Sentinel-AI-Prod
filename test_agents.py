"""
Sentinel-AI Agent Integration Tests

Tests all vLLM-backed agents with a realistic malicious diff.
Captures every LLM call (prompt, response, latency) to llm_call_log.json.

Agents tested:
  - Archeologist     (bypass — lockfile CVE scan, no LLM)
  - Shadow Stalker   (bypass — static analysis, no LLM)
  - Lead Warden      (vLLM verdict)
  - PatchForge       (vLLM fix generation)

ADK agents (Ghost Detector, SBOM, Detonator, Sentinel Watcher) require
Gemini API key — skipped here.
"""

from __future__ import annotations

import asyncio
import json
import time
from datetime import datetime, timezone
from typing import Any

# ── LLM call interceptor ───────────────────────────────────────
_llm_call_log: list[dict] = []


def _patch_llm_client():
    """Wrap LLMClient.complete — log every call with exact start/end timestamps."""
    import llm.llm_client as llm_mod

    original_complete = llm_mod.LLMClient.complete

    async def _instrumented_complete(self, prompt, system_prompt="",
                                     temperature=0.1, max_tokens=2048,
                                     json_mode=False):
        call_id = len(_llm_call_log) + 1
        start_dt = datetime.now(timezone.utc)
        t0 = time.perf_counter()

        print(f"  [LLM #{call_id}] START {start_dt.strftime('%H:%M:%S.%f')[:-3]} "
              f"model={self.model.split('/')[-1]} prompt_chars={len(prompt)} json={json_mode}")

        try:
            response = await original_complete(
                self, prompt, system_prompt, temperature, max_tokens, json_mode)
            status = "ok"
            error = None
        except Exception as exc:
            response = f"ERROR: {exc}"
            status = "error"
            error = str(exc)

        end_dt = datetime.now(timezone.utc)
        elapsed_ms = round((time.perf_counter() - t0) * 1000)

        print(f"  [LLM #{call_id}] END   {end_dt.strftime('%H:%M:%S.%f')[:-3]} "
              f"elapsed={elapsed_ms}ms status={status} resp_chars={len(response) if response else 0}")

        entry = {
            "call_id": call_id,
            "start_time": start_dt.isoformat(),
            "end_time": end_dt.isoformat(),
            "elapsed_ms": elapsed_ms,
            "status": status,
            "error": error,
            "backend": self.backend,
            "model": self.model,
            "base_url": self.base_url,
            "params": {
                "temperature": temperature,
                "max_tokens": max_tokens,
                "json_mode": json_mode,
            },
            "system_prompt": system_prompt,
            "prompt": prompt,
            "response": response,
            "prompt_chars": len(prompt),
            "response_chars": len(response) if response else 0,
        }
        _llm_call_log.append(entry)
        return response

    llm_mod.LLMClient.complete = _instrumented_complete
    print("[test] LLM client instrumented — full prompt/response + exact timestamps logged")


# ── Shared test fixtures ───────────────────────────────────────

MALICIOUS_DIFF = """\
diff --git a/db_service.py b/db_service.py
new file mode 100644
--- /dev/null
+++ b/db_service.py
@@ -0,0 +1,40 @@
+import sqlite3
+import logging
+import os
+
+# Hardcoded credentials (VULN: hardcoded secrets)
+DB_HOST = "prod-db.internal"
+DB_USER = "admin"
+DB_PASSWORD = "SuperSecret123!"
+DB_NAME = "users"
+
+# Hardcoded AWS keys (VULN: credential exposure)
+AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
+AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
+
+# Hardcoded JWT secret (VULN: credential exposure)
+JWT_SECRET = "my-super-secret-jwt-key-do-not-share"
+
+logger = logging.getLogger(__name__)
+
+def get_user_by_id(user_id):
+    conn = sqlite3.connect(DB_NAME)
+    # VULN: SQL injection via string concatenation
+    query = "SELECT * FROM users WHERE id=" + user_id
+    return conn.execute(query).fetchone()
+
+def get_user_by_name(username):
+    conn = sqlite3.connect(DB_NAME)
+    # VULN: SQL injection via f-string
+    return conn.execute(f"SELECT * FROM users WHERE name='{username}'").fetchone()
+
+def authenticate_user(username, password):
+    conn = sqlite3.connect(DB_NAME)
+    # VULN: SQL injection auth bypass + plaintext password logging
+    logger.info(f"Auth attempt: user={username} password={password}")
+    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
+    return conn.execute(query).fetchone()
+
+def run_raw_query(query):
+    # VULN: arbitrary SQL execution
+    conn = sqlite3.connect(DB_NAME)
+    return conn.execute(query).fetchall()
"""

MALICIOUS_LOCKFILE = """\
{
  "name": "test-app",
  "version": "1.0.0",
  "dependencies": {
    "lodash": "4.17.15",
    "event-stream": "3.3.6",
    "flatmap-stream": "0.1.1"
  }
}
"""

PR_METADATA = {
    "author": "unknown_contributor",
    "repo": "ramprasathk07/Test_repo",
    "pr": 1,
}


# ── Test results collector ─────────────────────────────────────

_test_results: list[dict] = []


def _record(name: str, status: str, duration: float, output: Any, error: str = ""):
    entry = {
        "test": name,
        "status": status,
        "duration_seconds": round(duration, 3),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "output_summary": {},
        "error": error,
    }

    if isinstance(output, dict):
        entry["output_summary"] = {
            k: v for k, v in output.items()
            if k not in ("findings", "file_reports")
        }
        if "findings" in output:
            entry["output_summary"]["findings_count"] = len(output["findings"])
    elif isinstance(output, str):
        try:
            parsed = json.loads(output)
            entry["output_summary"] = parsed if isinstance(parsed, dict) else {"raw": output[:500]}
        except Exception:
            entry["output_summary"] = {"raw": output[:500]}

    _test_results.append(entry)
    status_icon = "PASS" if status == "pass" else ("SKIP" if status == "skip" else "FAIL")
    print(f"\n{status_icon} [{name}] {status} in {round(duration, 3)}s")
    return entry


# ── Individual agent tests ─────────────────────────────────────

async def test_archeologist():
    from agents.archeologist.a2a_wrapper import ArcheologistA2AWrapper
    from core.schemas import AgentRequest

    print("\n=== Archeologist ===")
    t0 = time.perf_counter()
    try:
        agent = ArcheologistA2AWrapper()
        req = AgentRequest(
            agent_id="archeologist",
            task="Scan PR for supply-chain risks",
            context={
                "diff": MALICIOUS_DIFF,
                "lockfiles": {"package-lock.json": MALICIOUS_LOCKFILE},
                "pr_metadata": PR_METADATA,
            },
        )
        res = await agent.handle_request(req)
        elapsed = time.perf_counter() - t0
        output = json.loads(res.output) if res.output else {}
        findings = output.get("findings", [])
        print(f"  status={res.status} findings={len(findings)}")
        for f in findings[:3]:
            print(f"  - {f.get('type')} {f.get('details', {})}")
        _record("archeologist", "pass", elapsed, output)
    except Exception as exc:
        elapsed = time.perf_counter() - t0
        print(f"  ERROR: {exc}")
        _record("archeologist", "fail", elapsed, {}, str(exc))


async def test_shadow_stalker():
    from agents.shadow_stalker.a2a_wrapper import ShadowStalkerA2AWrapper
    from core.schemas import AgentRequest

    print("\n=== Shadow Stalker ===")
    t0 = time.perf_counter()
    try:
        agent = ShadowStalkerA2AWrapper()
        req = AgentRequest(
            agent_id="shadow_stalker",
            task="Static analysis of PR diff",
            context={"diff": MALICIOUS_DIFF},
        )
        res = await agent.handle_request(req)
        elapsed = time.perf_counter() - t0
        output = json.loads(res.output) if res.output else {}
        findings = output.get("findings", [])
        print(f"  status={res.status} findings={len(findings)} "
              f"files={output.get('files_analyzed', 0)} "
              f"risk={output.get('risk_score', 0)}")
        for f in findings[:5]:
            print(f"  - [{f.get('severity')}] {f.get('type')} | {str(f.get('description', ''))[:70]}")
        _record("shadow_stalker", "pass", elapsed, output)
        return res.output
    except Exception as exc:
        elapsed = time.perf_counter() - t0
        print(f"  ERROR: {exc}")
        _record("shadow_stalker", "fail", elapsed, {}, str(exc))
        return ""


async def test_lead_warden(arch_output: str, ss_output: str):
    from agents.lead_warden.tools import get_llm_verdict

    print("\n=== Lead Warden (vLLM) ===")
    t0 = time.perf_counter()
    try:
        result = await get_llm_verdict(
            archeologist_findings=arch_output,
            shadow_stalker_findings=ss_output,
            pr_metadata=json.dumps(PR_METADATA),
        )
        elapsed = time.perf_counter() - t0

        if "error" in result:
            print(f"  ERROR from LLM: {result['error']}")
            _record("lead_warden_llm", "fail", elapsed, result, result["error"])
            return result

        vj = result.get("verdict_json", {})
        print(f"  verdict={vj.get('verdict')} confidence={vj.get('confidence')} "
              f"severity={vj.get('severity')} engine={result.get('engine_version')}")
        for r in (vj.get("reasoning") or [])[:3]:
            print(f"  reasoning: {str(r)[:80]}")
        _record("lead_warden_llm", "pass", elapsed, vj)
        return result
    except Exception as exc:
        elapsed = time.perf_counter() - t0
        print(f"  ERROR: {exc}")
        _record("lead_warden_llm", "fail", elapsed, {}, str(exc))
        return {}


async def test_lead_warden_rule_based(arch_output: str, ss_output: str):
    from agents.lead_warden.tools import synthesize_verdict

    print("\n=== Lead Warden (Rule-Based Fallback) ===")
    t0 = time.perf_counter()
    try:
        result = synthesize_verdict(
            archeologist_findings=arch_output,
            shadow_stalker_findings=ss_output,
            pr_metadata=json.dumps(PR_METADATA),
        )
        elapsed = time.perf_counter() - t0
        print(f"  verdict={result['verdict']} score={result['risk_score']} "
              f"severity={result['severity']} confidence={result['confidence']}")
        for r in result.get("reasoning", [])[:3]:
            print(f"  reasoning: {str(r)[:80]}")
        _record("lead_warden_rule_based", "pass", elapsed, result)
        return result
    except Exception as exc:
        elapsed = time.perf_counter() - t0
        print(f"  ERROR: {exc}")
        _record("lead_warden_rule_based", "fail", elapsed, {}, str(exc))
        return {}


async def test_patchforge(ss_output: str):
    from agents.patchforge.vllm_wrapper import PatchForgeVLLMWrapper
    from core.schemas import AgentRequest

    print("\n=== PatchForge (vLLM) ===")
    t0 = time.perf_counter()
    try:
        ss_data = json.loads(ss_output) if ss_output else {}
        findings = ss_data.get("findings", [])
        if not findings:
            print("  SKIP — no findings from Shadow Stalker")
            _record("patchforge", "skip", 0, {}, "no findings")
            return

        top = findings[0]
        fname = top.get("filename", "db_service.py")
        print(f"  remediating: [{top.get('severity')}] {top.get('type')} in {fname}")

        agent = PatchForgeVLLMWrapper()
        req = AgentRequest(
            agent_id="patchforge",
            task=f"Generate fix for: {top.get('description', '')}",
            context={
                "finding_json": json.dumps(top),
                "source_code": "\n".join(
                    l["content"] for f in ss_data.get("file_reports", {}).values()
                    if isinstance(f, dict)
                    for l in f.get("added_lines", [])
                ),
                "filename": fname,
                "repo_owner": "ramprasathk07",
                "repo_name": "Test_repo",
            },
        )
        res = await agent.handle_request(req)
        elapsed = time.perf_counter() - t0
        output = json.loads(res.output) if res.output else {}
        print(f"  status={res.status} success={output.get('success')} "
              f"candidates={len(output.get('candidates_result', {}).get('candidates', []))}")
        best = output.get("best_candidate") or {}
        if best:
            print(f"  best_fix strategy={best.get('strategy')} "
                  f"confidence={best.get('confidence')}")
        _record("patchforge", "pass" if res.status != "error" else "fail", elapsed, output)
    except Exception as exc:
        elapsed = time.perf_counter() - t0
        print(f"  ERROR: {exc}")
        _record("patchforge", "fail", elapsed, {}, str(exc))


async def test_full_pipeline():
    """End-to-end: all agents in sequence, mimicking real scan_pr flow."""
    from agents.archeologist.a2a_wrapper import ArcheologistA2AWrapper
    from agents.shadow_stalker.a2a_wrapper import ShadowStalkerA2AWrapper
    from agents.lead_warden.tools import synthesize_verdict, get_llm_verdict
    from core.schemas import AgentRequest

    print("\n=== Full Pipeline (end-to-end) ===")
    t0 = time.perf_counter()
    try:
        arch = ArcheologistA2AWrapper()
        ss = ShadowStalkerA2AWrapper()

        arch_req = AgentRequest(
            agent_id="archeologist",
            task="Scan PR",
            context={"diff": MALICIOUS_DIFF,
                     "lockfiles": {"package-lock.json": MALICIOUS_LOCKFILE},
                     "pr_metadata": PR_METADATA},
        )
        ss_req = AgentRequest(
            agent_id="shadow_stalker",
            task="Static analysis",
            context={"diff": MALICIOUS_DIFF},
        )

        print("  running Archeologist + Shadow Stalker in parallel...")
        arch_res, ss_res = await asyncio.gather(
            arch.handle_request(arch_req),
            ss.handle_request(ss_req),
        )

        pr_meta_json = json.dumps(PR_METADATA)

        print("  calling Lead Warden (vLLM)...")
        llm_result = await get_llm_verdict(
            archeologist_findings=arch_res.output,
            shadow_stalker_findings=ss_res.output,
            pr_metadata=pr_meta_json,
        )

        if "error" in llm_result:
            print(f"  LLM failed ({llm_result['error']}) — using rule-based fallback")
            verdict_data = synthesize_verdict(
                archeologist_findings=arch_res.output,
                shadow_stalker_findings=ss_res.output,
                pr_metadata=pr_meta_json,
            )
            verdict_data["verdict_engine"] = "rule-based"
        else:
            vj = llm_result["verdict_json"]
            rule = synthesize_verdict(
                archeologist_findings=arch_res.output,
                shadow_stalker_findings=ss_res.output,
                pr_metadata=pr_meta_json,
            )
            vj.setdefault("risk_score", rule["risk_score"])
            vj.setdefault("agent_scores", rule["agent_scores"])
            vj["verdict_engine"] = "vllm"
            verdict_data = vj

        elapsed = time.perf_counter() - t0
        print(f"  PIPELINE DONE in {round(elapsed, 2)}s")
        print(f"  verdict={verdict_data.get('verdict')} "
              f"severity={verdict_data.get('severity')} "
              f"score={verdict_data.get('risk_score')} "
              f"engine={verdict_data.get('verdict_engine')}")

        _record("full_pipeline", "pass", elapsed, verdict_data)
    except Exception as exc:
        elapsed = time.perf_counter() - t0
        print(f"  ERROR: {exc}")
        _record("full_pipeline", "fail", elapsed, {}, str(exc))


# ── Main ───────────────────────────────────────────────────────

async def main():
    print("=" * 60)
    print("Sentinel-AI Agent Integration Tests")
    print(f"Started: {datetime.now(timezone.utc).isoformat()}")
    print("=" * 60)

    # Patch LLM client before any imports that create agents
    _patch_llm_client()

    # Run individual agent tests
    await test_archeologist()
    ss_output = await test_shadow_stalker() or ""

    # Run LLM-backed agents (need ss_output for context)
    arch_output = json.dumps({"findings": []})  # minimal arch output for LLM test
    await test_lead_warden(arch_output, ss_output)
    await test_lead_warden_rule_based(arch_output, ss_output)
    await test_patchforge(ss_output)

    # Full end-to-end pipeline
    await test_full_pipeline()

    # ── Save results ───────────────────────────────────────────
    output_file = "test_results.json"
    report = {
        "run_timestamp": datetime.now(timezone.utc).isoformat(),
        "total_tests": len(_test_results),
        "passed": sum(1 for t in _test_results if t["status"] == "pass"),
        "failed": sum(1 for t in _test_results if t["status"] == "fail"),
        "skipped": sum(1 for t in _test_results if t["status"] == "skip"),
        "total_llm_calls": len(_llm_call_log),
        "total_llm_latency_ms": sum(c["elapsed_ms"] for c in _llm_call_log),
        "total_llm_latency_seconds": round(
            sum(c["elapsed_ms"] for c in _llm_call_log) / 1000, 3),
        "test_results": _test_results,
        "llm_calls": _llm_call_log,
    }

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str)

    print("\n" + "=" * 60)
    print(f"RESULTS: {report['passed']} passed / {report['failed']} failed / "
          f"{report['skipped']} skipped")
    print(f"LLM calls: {report['total_llm_calls']} "
          f"total latency: {report['total_llm_latency_seconds']}s")
    print(f"Saved to: {output_file}")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
