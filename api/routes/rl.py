"""
RL Data Collection Routes

Endpoints for fetching pending pairs, committing human labels,
and retrieving the dataset history.
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import List, Optional

from storage.rl_store import get_pair, list_pairs, commit_label, update_trace, _run_trace_gen

router = APIRouter()


class LabelRequest(BaseModel):
    label: Optional[str] = None
    decision: Optional[str] = None
    reviewer_email: Optional[str] = None
    user_email: Optional[str] = None
    notes: Optional[str] = None


class GeneralLabelRequest(BaseModel):
    pair_id: str
    label: Optional[str] = None
    decision: Optional[str] = None
    reviewer_email: Optional[str] = None
    user_email: Optional[str] = None
    notes: Optional[str] = None


class TraceRegenRequest(BaseModel):
    force_backend: Optional[str] = None


class TraceEditRequest(BaseModel):
    root_cause: str
    exploit_path: List[str]
    why_patch_fixes: str
    residual_risks: List[str]
    lesson: str
    tags: List[str]


def map_record_to_frontend(record: dict) -> dict:
    """Map a nested database RL record to the flat structure expected by the React frontend."""
    if not record:
        return {}
    
    code = record.get("code") or {}
    source = record.get("source") or {}
    finding = record.get("finding") or {}
    reward = record.get("reward_signal") or {}
    auto_signals = reward.get("auto_signals") or {}
    
    # Get rewards: human label is 1, 0, or 0.5
    human_label = reward.get("human_label", 0)
    # Map label string to rewards if it hasn't been set as float
    if "human_reward" not in record:
        human_reward = 1.0 if record.get("label") == "accept" else (0.0 if record.get("label") == "reject" else 0.5)
    else:
        human_reward = human_label
        
    shannon_reward = float(auto_signals.get("shannon") or 0.0)
    verifier_reward = float(auto_signals.get("mini_verifier") or 0.0)
    
    # Extract reasoning trace text or format from trace_json
    trace = record.get("reasoning_trace")
    trace_text = ""
    if trace:
        if isinstance(trace, dict):
            # Extract nested trace block if present in the Pydantic dictionary
            actual_trace = trace.get("trace") if "trace" in trace else trace
            if isinstance(actual_trace, dict):
                # Format nicely
                parts = []
                if actual_trace.get("root_cause"):
                    parts.append(f"### Root Cause Analysis\n{actual_trace.get('root_cause')}")
                if actual_trace.get("exploit_path"):
                    paths = "\n".join(f"- {p}" for p in actual_trace.get("exploit_path", []))
                    parts.append(f"### Potential Exploit Vectors\n{paths}")
                if actual_trace.get("why_patch_fixes"):
                    parts.append(f"### Patch Correctness Reasoning\n{actual_trace.get('why_patch_fixes')}")
                if actual_trace.get("residual_risks"):
                    risks = "\n".join(f"- {r}" for r in actual_trace.get("residual_risks", []))
                    parts.append(f"### Residual Risks\n{risks}")
                if actual_trace.get("lesson"):
                    parts.append(f"### LLM Alignment Lesson Learned\n{actual_trace.get('lesson')}")
                trace_text = "\n\n".join(parts)
        else:
            trace_text = str(trace)

    return {
        "pair_id": record.get("id") or "",
        "scan_id": source.get("scan_id") or record.get("scan_id") or "",
        "repo": source.get("repo") or record.get("repo") or "",
        "file_path": source.get("file_path") or record.get("file_path") or "",
        "finding_type": finding.get("technique") or finding.get("type") or "Vulnerability",
        "finding": finding,
        "original": code.get("original_full") or "",
        "patched": code.get("patched_full") or "",
        "human_reward": human_reward,
        "shannon_reward": shannon_reward,
        "verifier_reward": verifier_reward,
        "reasoning_trace": trace_text or "(no trace generated)",
        "raw_record": record  # keep full raw just in case
    }


@router.get("/rl/pending")
async def get_pending_pairs(scan_id: Optional[str] = None):
    # For now, list_pairs gets all. We filter by label="pending".
    # Since RL pairs are a backend state, scan_id can filter further.
    all_pending = list_pairs(label="pending", limit=100)
    mapped = [map_record_to_frontend(p) for p in all_pending]
    if scan_id:
        return [p for p in mapped if p["scan_id"] == scan_id]
    return mapped


@router.get("/rl/pairs")
@router.get("/rl/history")
async def get_history(label: Optional[str] = None, page: int = 1, limit: int = 10):
    offset = (page - 1) * limit
    from storage.db import get_db
    import json
    with get_db() as conn:
        if label == "labeled" or label is None:
            # history shows all non-pending pairs (either accepted or rejected)
            cur_count = conn.execute("SELECT COUNT(*) FROM rl_pairs WHERE label != 'pending'")
            total = cur_count.fetchone()[0]
            cur_items = conn.execute("SELECT record_json FROM rl_pairs WHERE label != 'pending' ORDER BY created_at DESC LIMIT ? OFFSET ?", (limit, offset))
        else:
            cur_count = conn.execute("SELECT COUNT(*) FROM rl_pairs WHERE label = ?", (label,))
            total = cur_count.fetchone()[0]
            cur_items = conn.execute("SELECT record_json FROM rl_pairs WHERE label = ? ORDER BY created_at DESC LIMIT ? OFFSET ?", (label, limit, offset))
            
        items = [map_record_to_frontend(json.loads(row["record_json"])) for row in cur_items.fetchall()]
        
    return {"items": items, "total": total}


@router.get("/rl/{rl_id}")
async def get_single_pair(rl_id: str):
    record = get_pair(rl_id)
    if not record:
        raise HTTPException(status_code=404, detail="RL pair not found")
    return map_record_to_frontend(record)


@router.post("/rl/label")
async def post_general_label(req: GeneralLabelRequest):
    try:
        lbl = (req.label or req.decision or "").lower()
        email = req.reviewer_email or req.user_email or "anonymous@sentinel.ai"
        if not lbl:
            raise HTTPException(status_code=422, detail="Missing decision or label in request.")
        updated = await commit_label(req.pair_id, lbl, email)
        return {"status": "success", "record": map_record_to_frontend(updated)}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/rl/{rl_id}/label")
async def post_label(rl_id: str, req: LabelRequest):
    try:
        lbl = (req.label or req.decision or "").lower()
        email = req.reviewer_email or req.user_email or "anonymous@sentinel.ai"
        if not lbl:
            raise HTTPException(status_code=422, detail="Missing decision or label in request.")
        updated = await commit_label(rl_id, lbl, email)
        return {"status": "success", "record": map_record_to_frontend(updated)}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/rl/{rl_id}/trace/regenerate")
async def regenerate_trace(rl_id: str, req: TraceRegenRequest, background_tasks: BackgroundTasks):
    record = get_pair(rl_id)
    if not record:
        raise HTTPException(status_code=404, detail="RL pair not found")
        
    # Schedule the async generation
    background_tasks.add_task(_run_trace_gen, rl_id, record)
    return {"status": "queued"}


@router.patch("/rl/{rl_id}/trace")
async def edit_trace(rl_id: str, req: TraceEditRequest):
    try:
        updated = update_trace(rl_id, req.model_dump())
        return {"status": "success", "record": map_record_to_frontend(updated)}
    except ValueError:
        raise HTTPException(status_code=404, detail="RL pair not found")


class TraceEditPostRequest(BaseModel):
    pair_id: str
    reasoning_trace: str


@router.post("/rl/trace/edit")
async def edit_trace_post(req: TraceEditPostRequest):
    """Save an edited reasoning trace for a labeled RL pair."""
    try:
        from storage.rl_store import get_pair, _RL_DIR
        from storage.db import get_db
        import json
        
        record = get_pair(req.pair_id)
        if not record:
            raise HTTPException(status_code=404, detail="RL pair not found")
            
        record["reasoning_trace"] = req.reasoning_trace
        
        # Save to DB
        with get_db() as conn:
            conn.execute(
                "UPDATE rl_pairs SET record_json = ?, trace_json = ? WHERE id = ?",
                (json.dumps(record), json.dumps(req.reasoning_trace), req.pair_id)
            )
            conn.commit()
            
        # Save to disk
        file_path = _RL_DIR / f"{req.pair_id}.json"
        if file_path.exists():
            file_path.write_text(json.dumps(record, indent=2), encoding="utf-8")
            
        return {"status": "success", "record": map_record_to_frontend(record)}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/rl/export")
async def export_jsonl():
    from fastapi.responses import FileResponse
    from storage.rl_store import _RL_INDEX_FILE
    if _RL_INDEX_FILE.exists():
        return FileResponse(str(_RL_INDEX_FILE), media_type="application/x-ndjson", filename="rl_index.jsonl")
    raise HTTPException(status_code=404, detail="No exported data yet")
