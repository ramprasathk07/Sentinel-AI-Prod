"""
RL Store

Handles SQLite persistence and JSON mirroring for RL training pairs.
"""

import json
import sqlite3
import os
import asyncio
from datetime import datetime, timezone
from pathlib import Path

from core.config import settings
from utils.logger import logger
from storage.db import get_db, init_db
from agents.rl_trace.generator import generate_reasoning_trace


_RL_DIR = Path(settings.RL_DATA_DIR)
_RL_INDEX_FILE = _RL_DIR / "index.jsonl"


init_db()


def _calculate_reward(human_label: int, shannon: str, mini: dict) -> dict:
    w = [float(x) for x in settings.RL_REWARD_WEIGHTS.split(",")]
    # w[0] = human, w[1] = shannon, w[2] = mini
    s_val = 1 if shannon == "PASS" else 0
    m_val = 1 if mini.get("passed") else 0
    
    comp = (w[0] * human_label) + (w[1] * s_val) + (w[2] * m_val)
    return {
        "human_label": human_label,
        "auto_signals": {"shannon": s_val, "mini_verifier": m_val, "tests_pass": None},
        "composite": comp
    }


def stage_pending_pair(
    scan_id: str,
    repo: str,
    file_path: str,
    original: str,
    patched: str,
    unified_diff: str,
    finding: dict,
    prompt_ctx: dict,
    patch_meta: dict,
) -> str:
    """Stage a new RL pair directly into the DB with 'pending' status."""
    import hashlib
    ts = datetime.now(timezone.utc).isoformat()
    raw = f"{scan_id}{file_path}{finding.get('line',0)}{ts}"
    rl_id = "rl_" + hashlib.sha256(raw.encode()).hexdigest()[:8]
    
    record = {
        "schema_version": "1.0",
        "id": rl_id,
        "created_at": ts,
        "label": "pending",
        "reviewer": {"email": "", "session_id": ""},
        "source": {
            "type": "scan",
            "scan_id": scan_id,
            "repo": repo,
            "pr_number": 0,
            "commit_sha": "",
            "file_path": file_path
        },
        "finding": finding,
        "prompt_context": prompt_ctx,
        "code": {
            "original_full": original,
            "patched_full": patched,
            "unified_diff": unified_diff,
            "language": "python",
            "size_bytes_original": len(original),
            "size_bytes_patched": len(patched)
        },
        "patch_metadata": patch_meta,
        "reward_signal": {},
        "reasoning_trace": None,
        "hashes": {
            "original_sha256": hashlib.sha256(original.encode()).hexdigest(),
            "patched_sha256": hashlib.sha256(patched.encode()).hexdigest(),
            "record_sha256": ""
        }
    }
    
    record_json = json.dumps(record)
    
    with get_db() as conn:
        conn.execute("""
            INSERT INTO rl_pairs (id, scan_id, repo, file_path, label, record_json)
            VALUES (?, ?, ?, ?, 'pending', ?)
        """, (rl_id, scan_id, repo, file_path, record_json))
        conn.commit()
        
    return rl_id


async def commit_label(rl_id: str, label: str, reviewer_email: str, generate_trace: bool = True) -> dict:
    """Commit human label. Accept triggers trace gen."""
    with get_db() as conn:
        cur = conn.execute("SELECT record_json FROM rl_pairs WHERE id = ?", (rl_id,))
        row = cur.fetchone()
        if not row:
            raise ValueError(f"RL pair {rl_id} not found")
        
        record = json.loads(row["record_json"])
        
    # Update record
    record["label"] = label
    record["reviewer"]["email"] = reviewer_email
    
    human_val = 1 if label == "accept" else (0 if label == "reject" else 0.5)
    patch_meta = record.get("patch_metadata", {})
    shannon = patch_meta.get("shannon_verdict", "FAIL")
    mini = patch_meta.get("mini_verifier", {})
    
    reward = _calculate_reward(human_val, shannon, mini)
    record["reward_signal"] = reward
    
    # Save to disk
    _RL_DIR.mkdir(parents=True, exist_ok=True)
    file_path = _RL_DIR / f"{rl_id}.json"
    file_path.write_text(json.dumps(record, indent=2), encoding="utf-8")
    
    # Append index
    index_entry = json.dumps({
        "id": rl_id,
        "ts": record["created_at"],
        "repo": record["source"]["repo"],
        "verdict": label,
        "reward": reward["composite"]
    })
    with open(_RL_INDEX_FILE, "a") as f:
        f.write(index_entry + "\n")
        
    # Update DB
    with get_db() as conn:
        conn.execute("""
            UPDATE rl_pairs
            SET label = ?, reviewer_email = ?, composite_reward = ?, record_json = ?, record_path = ?, trace_status = ?
            WHERE id = ?
        """, (label, reviewer_email, reward["composite"], json.dumps(record), str(file_path), 'pending' if (label == 'accept' and generate_trace) else 'none', rl_id))
        conn.commit()
        
    if label == "accept" and generate_trace:
        # Fire async trace generation (fire and forget)
        asyncio.create_task(_run_trace_gen(rl_id, record))
        
    return record


async def _run_trace_gen(rl_id: str, record: dict):
    try:
        finding = record["finding"]
        original = record["code"]["original_full"]
        patched = record["code"]["patched_full"]
        diff = record["code"]["unified_diff"]
        
        trace_block = await generate_reasoning_trace(finding, original, patched, diff)
        
        record["reasoning_trace"] = json.loads(trace_block.model_dump_json())
        
        file_path = _RL_DIR / f"{rl_id}.json"
        if file_path.exists():
            file_path.write_text(json.dumps(record, indent=2), encoding="utf-8")
            
        with get_db() as conn:
            conn.execute("""
                UPDATE rl_pairs
                SET trace_status = 'ready', trace_json = ?, record_json = ?
                WHERE id = ?
            """, (json.dumps(record["reasoning_trace"]), json.dumps(record), rl_id))
            conn.commit()
    except Exception as exc:
        logger.error(f"[rl_store] Trace gen failed for {rl_id}: {exc}")
        with get_db() as conn:
            conn.execute("UPDATE rl_pairs SET trace_status = 'failed' WHERE id = ?", (rl_id,))
            conn.commit()


def get_pair(rl_id: str) -> dict:
    with get_db() as conn:
        cur = conn.execute("SELECT record_json FROM rl_pairs WHERE id = ?", (rl_id,))
        row = cur.fetchone()
        if not row:
            return None
        return json.loads(row["record_json"])


def list_pairs(label: str = None, limit: int = 50, offset: int = 0) -> list:
    with get_db() as conn:
        if label:
            cur = conn.execute("SELECT record_json FROM rl_pairs WHERE label = ? ORDER BY created_at DESC LIMIT ? OFFSET ?", (label, limit, offset))
        else:
            cur = conn.execute("SELECT record_json FROM rl_pairs ORDER BY created_at DESC LIMIT ? OFFSET ?", (limit, offset))
        return [json.loads(row["record_json"]) for row in cur.fetchall()]


def update_trace(rl_id: str, edits: dict) -> dict:
    record = get_pair(rl_id)
    if not record:
        raise ValueError("Not found")
    
    if "reasoning_trace" in record and record["reasoning_trace"]:
        record["reasoning_trace"]["human_edits"] = edits
    else:
        # Initialize if missing
        record["reasoning_trace"] = {
            "human_edits": edits
        }
        
    with get_db() as conn:
        conn.execute("UPDATE rl_pairs SET record_json = ?, trace_json = ? WHERE id = ?", 
                     (json.dumps(record), json.dumps(record["reasoning_trace"]), rl_id))
        conn.commit()
        
    file_path = _RL_DIR / f"{rl_id}.json"
    if file_path.exists():
        file_path.write_text(json.dumps(record, indent=2), encoding="utf-8")
        
    return record
