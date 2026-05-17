"""
Shadow Stalker — Stage 3: Embedding Store

Local vector store for code chunk embeddings. Stores flagged patterns
and performs cosine similarity search against known attack patterns.

Initial implementation: JSON file + numpy cosine similarity.
Future: swap for Graphiti client.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Optional

# ── numpy import with fallback ──────────────────────────────
_NUMPY_AVAILABLE = False
try:
    import numpy as np
    _NUMPY_AVAILABLE = True
except ImportError:
    pass

from agents.shadow_stalker.known_patterns import KNOWN_PATTERNS

# Default storage path
_DEFAULT_STORE_PATH = Path(__file__).parent / "data" / "embedding_store.json"


class EmbeddingStore:
    """
    Local vector store for code chunk embeddings.

    Stores embeddings as JSON with numpy-based cosine similarity search.
    Falls back to keyword matching when numpy is unavailable.
    """

    def __init__(self, store_path: Optional[str] = None):
        self.store_path = Path(store_path) if store_path else _DEFAULT_STORE_PATH
        self.store_path.parent.mkdir(parents=True, exist_ok=True)
        self._data: dict = self._load()

    def _load(self) -> dict:
        if self.store_path.exists():
            try:
                with open(self.store_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError):
                pass
        return {"patterns": [], "version": 1}

    def _save(self):
        with open(self.store_path, "w", encoding="utf-8") as f:
            json.dump(self._data, f, indent=2, default=str)

    def store_finding(
        self,
        code_chunk: str,
        finding: dict,
        embedding: Optional[list[float]] = None,
    ) -> str:
        """Persist a flagged code pattern with its vector embedding."""
        chunk_id = hashlib.sha256(code_chunk.encode()).hexdigest()[:16]

        entry = {
            "id": chunk_id,
            "code": code_chunk[:2000],
            "finding": finding,
            "embedding": embedding,
        }

        # Deduplicate by ID
        self._data["patterns"] = [
            p for p in self._data["patterns"] if p["id"] != chunk_id
        ]
        self._data["patterns"].append(entry)
        self._save()
        return chunk_id

    def search_similar(
        self,
        code_chunk: str,
        embedding: Optional[list[float]] = None,
        top_k: int = 5,
    ) -> list[dict]:
        """
        Find stored patterns similar to the given code chunk.

        If embeddings are available, uses cosine similarity.
        Falls back to keyword overlap scoring.
        """
        if embedding and _NUMPY_AVAILABLE:
            return self._vector_search(embedding, top_k)
        return self._keyword_search(code_chunk, top_k)

    def bootstrap_known_patterns(self):
        """Seed the store with the canonical malicious pattern corpus."""
        for pattern in KNOWN_PATTERNS:
            chunk_id = pattern["id"]
            entry = {
                "id": chunk_id,
                "code": pattern["code"],
                "finding": {
                    "label": pattern["label"],
                    "category": pattern["category"],
                    "language": pattern["language"],
                    "severity": pattern["severity"],
                },
                "embedding": None,  # Will be populated when embedding model available
            }
            # Skip if already present
            existing_ids = {p["id"] for p in self._data["patterns"]}
            if chunk_id not in existing_ids:
                self._data["patterns"].append(entry)

        self._save()

    @property
    def pattern_count(self) -> int:
        return len(self._data["patterns"])

    def _vector_search(self, query_embedding: list[float], top_k: int) -> list[dict]:
        """Cosine similarity search using numpy."""
        query = np.array(query_embedding)
        results = []

        for entry in self._data["patterns"]:
            if entry.get("embedding"):
                stored = np.array(entry["embedding"])
                similarity = float(
                    np.dot(query, stored) /
                    (np.linalg.norm(query) * np.linalg.norm(stored) + 1e-10)
                )
                results.append({
                    "id": entry["id"],
                    "code_preview": entry["code"][:200],
                    "finding": entry["finding"],
                    "similarity": round(similarity, 4),
                })

        results.sort(key=lambda x: x["similarity"], reverse=True)
        return results[:top_k]

    def _keyword_search(self, code_chunk: str, top_k: int) -> list[dict]:
        """Keyword overlap similarity when embeddings are unavailable."""
        query_tokens = set(re.findall(r'[a-zA-Z_]\w+', code_chunk.lower()))
        results = []

        for entry in self._data["patterns"]:
            stored_tokens = set(re.findall(r'[a-zA-Z_]\w+', entry["code"].lower()))
            if not stored_tokens:
                continue
            overlap = len(query_tokens & stored_tokens)
            union = len(query_tokens | stored_tokens)
            jaccard = overlap / union if union > 0 else 0.0

            if jaccard > 0.05:  # minimum threshold
                results.append({
                    "id": entry["id"],
                    "code_preview": entry["code"][:200],
                    "finding": entry["finding"],
                    "similarity": round(jaccard, 4),
                })

        results.sort(key=lambda x: x["similarity"], reverse=True)
        return results[:top_k]


# ═══════════════════════════════════════════════════════════
# ADK-compatible tool functions
# ═══════════════════════════════════════════════════════════

# Module-level singleton store
_store: Optional[EmbeddingStore] = None


def _get_store() -> EmbeddingStore:
    global _store
    if _store is None:
        _store = EmbeddingStore()
        if _store.pattern_count == 0:
            _store.bootstrap_known_patterns()
    return _store


def store_flagged_pattern(
    code_chunk: str,
    finding_type: str,
    severity: str,
    filename: str = "unknown",
) -> dict:
    """
    Store a flagged code pattern in the embedding store for future
    similarity matching. Called when a Stage 1 or Stage 2 finding
    is confirmed as suspicious.

    Args:
        code_chunk:   The suspicious code snippet.
        finding_type: Type of finding (e.g., 'dynamic_execution').
        severity:     Severity level (CRITICAL/HIGH/MEDIUM/LOW).
        filename:     Source file name.

    Returns:
        A dict confirming storage with the assigned chunk ID.
    """
    store = _get_store()
    finding = {
        "type": finding_type,
        "severity": severity,
        "filename": filename,
    }
    chunk_id = store.store_finding(code_chunk, finding)
    return {
        "stored": True,
        "chunk_id": chunk_id,
        "pattern_count": store.pattern_count,
    }


def search_known_attacks(
    code_chunk: str,
    filename: str = "unknown",
    top_k: int = 5,
) -> dict:
    """
    Search for known attack patterns similar to the given code chunk.
    Uses keyword overlap scoring (cosine similarity when embeddings
    are available).

    Args:
        code_chunk: The code snippet to search against.
        filename:   Source file name (for context).
        top_k:      Number of similar patterns to return.

    Returns:
        A dict with 'matches' (list of similar known patterns) and metadata.
    """
    store = _get_store()
    matches = store.search_similar(code_chunk, top_k=top_k)

    return {
        "filename": filename,
        "query_preview": code_chunk[:200],
        "matches": matches,
        "match_count": len(matches),
        "corpus_size": store.pattern_count,
    }
