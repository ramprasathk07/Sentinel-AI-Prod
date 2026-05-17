"""
Ground Truth Logger

Logs every piece of data entering or leaving the webhook integration layer
locally to storage/ground_truth/. Ensures 100% data retention without
relying on cloud storage.
"""

import json
import os
from datetime import datetime, timezone

from core.config import settings
from utils.logger import logger


def save_ground_truth(
    repo_name: str,
    pr_number: int,
    payload: dict,
    diff_content: str,
    agent_outputs: dict,
    final_verdict: dict,
):
    """
    Save the ground truth data for a PR event.
    Creates a timestamped directory and saves individual JSON/txt files.
    """
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    safe_repo = repo_name.replace("/", "_")
    base_dir = os.path.join(
        settings.BASE_DIR, 
        "storage", 
        "ground_truth", 
        safe_repo, 
        str(pr_number), 
        timestamp
    )
    
    os.makedirs(base_dir, exist_ok=True)

    try:
        # Save webhook payload
        with open(os.path.join(base_dir, "webhook_payload.json"), "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)

        # Save raw diff
        with open(os.path.join(base_dir, "pr_diff.diff"), "w", encoding="utf-8") as f:
            f.write(diff_content)

        # Save individual agent outputs
        for agent_id, output in agent_outputs.items():
            out_file = os.path.join(base_dir, f"agent_{agent_id}.json")
            with open(out_file, "w", encoding="utf-8") as f:
                json.dump(output, f, indent=2)

        # Save final Lead Warden verdict
        with open(os.path.join(base_dir, "final_verdict.json"), "w", encoding="utf-8") as f:
            json.dump(final_verdict, f, indent=2)

        logger.info(f"Ground truth saved locally: {base_dir}")
        return base_dir
    except Exception as e:
        logger.error(f"Failed to save ground truth data: {e}")
        return None
