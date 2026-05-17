"""
SQLite Database Tracker

Logs every PR analysis and ground truth reaction label locally.
Keeps track of:
- All analysis runs (verdict, confidence, findings, PR ID)
- Developer feedback (thumbs up/down) for Stage 3 M-GRPO RL training.
- Watched repositories (persistent across server restarts).
"""

import json
import sqlite3
import os
from contextlib import contextmanager
from datetime import datetime

from core.config import settings
from utils.logger import logger
from typing import Optional

def get_db_path() -> str:
    """Extract path from sqlite:///... URL."""
    if settings.DATABASE_URL.startswith("sqlite:///"):
        path = settings.DATABASE_URL.replace("sqlite:///", "")
        # Resolve relative to base dir if needed
        if not os.path.isabs(path):
            path = os.path.normpath(os.path.join(settings.BASE_DIR, path))
        return path
    return "sentinel.db"


@contextmanager
def get_db():
    conn = sqlite3.connect(get_db_path())
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def init_db():
    """Initialize the SQLite tables if they don't exist."""
    db_path = get_db_path()
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    
    with get_db() as conn:
        cursor = conn.cursor()
        
        # Table for storing PR analysis results
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS analysis_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                repo_name TEXT NOT NULL,
                pr_number INTEGER NOT NULL,
                verdict TEXT NOT NULL,
                confidence REAL NOT NULL,
                severity TEXT,
                findings_json TEXT,
                summary TEXT,
                reasoning_json TEXT,
                attack_classification TEXT,
                risk_score REAL,
                findings_count_json TEXT,
                user_email TEXT,
                pr_title TEXT,
                author TEXT,
                pr_url TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        # Additive migration — add new columns if upgrading older DB
        for col, ddl in [
            ("summary", "ALTER TABLE analysis_logs ADD COLUMN summary TEXT"),
            ("reasoning_json", "ALTER TABLE analysis_logs ADD COLUMN reasoning_json TEXT"),
            ("attack_classification", "ALTER TABLE analysis_logs ADD COLUMN attack_classification TEXT"),
            ("risk_score", "ALTER TABLE analysis_logs ADD COLUMN risk_score REAL"),
            ("findings_count_json", "ALTER TABLE analysis_logs ADD COLUMN findings_count_json TEXT"),
            ("user_email", "ALTER TABLE analysis_logs ADD COLUMN user_email TEXT"),
            ("pr_title", "ALTER TABLE analysis_logs ADD COLUMN pr_title TEXT"),
            ("author", "ALTER TABLE analysis_logs ADD COLUMN author TEXT"),
            ("pr_url", "ALTER TABLE analysis_logs ADD COLUMN pr_url TEXT"),
        ]:
            try:
                cursor.execute(ddl)
            except sqlite3.OperationalError:
                pass  # column already exists

        # Table for watched repositories (persists across restarts)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS watches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                repo_name TEXT NOT NULL UNIQUE,
                hook_id INTEGER,
                webhook_url TEXT,
                user_email TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Table for storing developer feedback on our verdicts (ground truth)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ground_truth_labels (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                repo_name TEXT NOT NULL,
                pr_number INTEGER NOT NULL,
                analysis_id INTEGER,
                user_login TEXT NOT NULL,
                reaction TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(analysis_id) REFERENCES analysis_logs(id)
            )
        """)
        
        # Table for storing encrypted GitHub tokens per user
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_tokens (
                user_email TEXT PRIMARY KEY,
                github_token_enc TEXT NOT NULL,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        conn.commit()
        logger.info(f"SQLite DB initialized at {db_path}")
        
        # Anti-tampering: If we are in production but the environment looks wrong, wipe tokens
        _check_integrity(cursor)

def _check_integrity(cursor):
    """Wipe tokens if running in unauthorized environment (hackathon anti-tamper)."""
    env = os.getenv("NODE_ENV", os.getenv("VERCEL_ENV", "local"))
    # If we are on Vercel/Render but SENTINEL_ENCRYPTION_KEY is default, it's unsafe -> WIPE
    if env in ["production", "preview"] and os.getenv("SENTINEL_ENCRYPTION_KEY") is None:
        logger.warning("UNSAFE ENVIRONMENT DETECTED! Wiping all secure tokens.")
        cursor.execute("DELETE FROM user_tokens")


def log_analysis(
    repo_name: str,
    pr_number: int,
    verdict: str,
    confidence: float,
    severity: str,
    findings: dict,
    summary: str = "",
    reasoning: list | None = None,
    attack_classification: str = "",
    risk_score: float = 0.0,
    findings_count: dict | None = None,
    user_email: str = "",
    pr_title: str = "",
    author: str = "",
    pr_url: str = "",
) -> int:
    """Log an analysis run and return the inserted row ID."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO analysis_logs
                (repo_name, pr_number, verdict, confidence, severity, findings_json,
                 summary, reasoning_json, attack_classification, risk_score,
                 findings_count_json, user_email, pr_title, author, pr_url)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            repo_name, pr_number, verdict, confidence, severity, json.dumps(findings),
            summary, json.dumps(reasoning or []),
            attack_classification, float(risk_score or 0.0),
            json.dumps(findings_count or {}),
            user_email or "", pr_title or "", author or "",
            pr_url or f"https://github.com/{repo_name}/pull/{pr_number}",
        ))
        conn.commit()
        return cursor.lastrowid


def log_ground_truth_reaction(repo_name: str, pr_number: int, user_login: str, reaction: str) -> int:
    """
    Log a thumbs up/down reaction to an analysis comment.
    Finds the latest analysis_id for this PR and links the reaction.
    """
    with get_db() as conn:
        cursor = conn.cursor()
        
        # Get the latest analysis ID for this PR
        cursor.execute("""
            SELECT id FROM analysis_logs 
            WHERE repo_name = ? AND pr_number = ? 
            ORDER BY timestamp DESC LIMIT 1
        """, (repo_name, pr_number))
        
        row = cursor.fetchone()
        analysis_id = row['id'] if row else None
        
        cursor.execute("""
            INSERT INTO ground_truth_labels (repo_name, pr_number, analysis_id, user_login, reaction)
            VALUES (?, ?, ?, ?, ?)
        """, (repo_name, pr_number, analysis_id, user_login, reaction))
        
        conn.commit()
        return cursor.lastrowid

def get_cached_scan(repo_name: str, pr_number: int) -> Optional[dict]:
    """Retrieve the most recent scan result for a specific repo and PR."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT verdict, confidence, severity, summary, reasoning_json, 
                   attack_classification, risk_score, findings_count_json, findings_json
            FROM analysis_logs 
            WHERE repo_name = ? AND pr_number = ? 
            ORDER BY timestamp DESC LIMIT 1
        """, (repo_name, pr_number))
        row = cursor.fetchone()
        if not row:
            return None
        
        d = dict(row)
        # Parse JSON fields
        import json
        d["reasoning"] = json.loads(d.pop("reasoning_json", "[]") or "[]")
        d["findings_count"] = json.loads(d.pop("findings_count_json", "{}") or "{}")
        d["findings"] = json.loads(d.pop("findings_json", "{}") or "{}")
        return d


# ── Watch persistence ──────────────────────────────────────────

def save_watch(repo_name: str, hook_id: int, webhook_url: str, user_email: str = "") -> int:
    """Persist a watched repo to the DB."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO watches (repo_name, hook_id, webhook_url, user_email)
            VALUES (?, ?, ?, ?)
        """, (repo_name, hook_id, webhook_url, user_email or ""))
        conn.commit()
        return cursor.lastrowid


def delete_watch(repo_name: str):
    """Remove a watched repo from the DB."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM watches WHERE repo_name = ?", (repo_name,))
        conn.commit()


def get_watches(user_email: str = "") -> list[dict]:
    """Get all watched repos (optionally filtered by user)."""
    with get_db() as conn:
        cursor = conn.cursor()
        if user_email:
            cursor.execute(
                "SELECT repo_name, hook_id, webhook_url, user_email, created_at "
                "FROM watches WHERE user_email = ? ORDER BY created_at DESC",
                (user_email,),
            )
        else:
            cursor.execute(
                "SELECT repo_name, hook_id, webhook_url, user_email, created_at "
                "FROM watches ORDER BY created_at DESC"
            )
        return [dict(r) for r in cursor.fetchall()]


def get_recent_scans(limit: int = 5, user_email: str = "") -> list[dict]:
    """Return the N most recent scans, deduped by (repo_name, pr_number) keeping newest."""
    with get_db() as conn:
        cursor = conn.cursor()
        # Use a subquery to get the latest scan per repo+PR, then take the top N
        if user_email:
            cursor.execute("""
                SELECT a.id, a.repo_name, a.pr_number, a.verdict, a.confidence,
                       a.severity, a.summary, a.reasoning_json, a.attack_classification,
                       a.risk_score, a.findings_count_json, a.pr_title, a.author,
                       a.pr_url, a.timestamp
                FROM analysis_logs a
                INNER JOIN (
                    SELECT MAX(id) as max_id
                    FROM analysis_logs
                    WHERE user_email = ?
                    GROUP BY repo_name, pr_number
                ) latest ON a.id = latest.max_id
                ORDER BY a.timestamp DESC
                LIMIT ?
            """, (user_email, limit))
        else:
            cursor.execute("""
                SELECT a.id, a.repo_name, a.pr_number, a.verdict, a.confidence,
                       a.severity, a.summary, a.reasoning_json, a.attack_classification,
                       a.risk_score, a.findings_count_json, a.pr_title, a.author,
                       a.pr_url, a.timestamp
                FROM analysis_logs a
                INNER JOIN (
                    SELECT MAX(id) as max_id
                    FROM analysis_logs
                    GROUP BY repo_name, pr_number
                ) latest ON a.id = latest.max_id
                ORDER BY a.timestamp DESC
                LIMIT ?
            """, (limit,))
        rows = cursor.fetchall()

    results = []
    for r in rows:
        d = dict(r)
        d["reasoning"] = json.loads(d.pop("reasoning_json", "[]") or "[]")
        d["findings_count"] = json.loads(d.pop("findings_count_json", "{}") or "{}")
        if not d.get("pr_url"):
            d["pr_url"] = f"https://github.com/{d['repo_name']}/pull/{d['pr_number']}"
        results.append(d)
    return results

# ── Token persistence ──────────────────────────────────────────

def save_token(user_email: str, encrypted_token: str):
    """Persist an encrypted token to the DB."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO user_tokens (user_email, github_token_enc)
            VALUES (?, ?)
        """, (user_email, encrypted_token))
        conn.commit()

def get_token(user_email: str) -> str | None:
    """Retrieve an encrypted token from the DB."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT github_token_enc FROM user_tokens WHERE user_email = ?", (user_email,))
        row = cursor.fetchone()
        return row["github_token_enc"] if row else None

def wipe_tokens():
    """Immediately delete all stored tokens (Panic Mode)."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM user_tokens")
        conn.commit()
        logger.warning("PANIC: All user tokens have been wiped from the database.")


# ── Pentest session persistence ──────────────────────────────

def init_pentest_table():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS pentest_sessions (
                session_id TEXT PRIMARY KEY,
                target_url TEXT NOT NULL,
                repo_url TEXT NOT NULL,
                phase TEXT NOT NULL,
                started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                completed_at DATETIME,
                duration_seconds REAL,
                findings_json TEXT,
                markdown TEXT,
                phase_data_json TEXT,
                error TEXT
            )
        """)
        # Migration: add phase_data_json if missing from older table
        try:
            conn.execute("ALTER TABLE pentest_sessions ADD COLUMN phase_data_json TEXT")
        except sqlite3.OperationalError:
            pass
        conn.commit()


def save_pentest_session(session_id: str, target_url: str, repo_url: str, phase: str) -> None:
    init_pentest_table()
    with get_db() as conn:
        conn.execute("""
            INSERT OR REPLACE INTO pentest_sessions
                (session_id, target_url, repo_url, phase, started_at)
            VALUES (?, ?, ?, ?, ?)
        """, (session_id, target_url, repo_url, phase, datetime.utcnow().isoformat()))
        conn.commit()


def update_pentest_session(session_id: str, report) -> None:
    """Persist a completed PentestReport into the pentest_sessions table."""
    init_pentest_table()
    try:
        findings = [f.model_dump() for f in (report.findings or [])]
    except Exception:
        findings = []
    findings_json = json.dumps(findings, default=str)
    phase_data_json = json.dumps(report.phase_data or {}, default=str)
    phase_val = report.phase.value if hasattr(report.phase, "value") else str(report.phase)
    completed_at = report.completed_at.isoformat() if report.completed_at else None
    with get_db() as conn:
        conn.execute("""
            UPDATE pentest_sessions
            SET phase=?, completed_at=?, duration_seconds=?,
                findings_json=?, markdown=?, phase_data_json=?, error=?
            WHERE session_id=?
        """, (
            phase_val,
            completed_at,
            report.duration_seconds,
            findings_json,
            report.markdown,
            phase_data_json,
            report.error,
            session_id,
        ))
        conn.commit()


def get_pentest_session(session_id: str) -> Optional[dict]:
    init_pentest_table()
    with get_db() as conn:
        cur = conn.execute(
            "SELECT * FROM pentest_sessions WHERE session_id = ?",
            (session_id,),
        )
        row = cur.fetchone()
        if not row:
            return None
        d = dict(row)
        if d.get("findings_json"):
            try:
                d["findings"] = json.loads(d["findings_json"])
            except Exception:
                d["findings"] = []
        if d.get("phase_data_json"):
            try:
                d["phase_data"] = json.loads(d["phase_data_json"])
            except Exception:
                d["phase_data"] = {}
        return d


def list_pentest_sessions(limit: int = 20) -> list[dict]:
    init_pentest_table()
    with get_db() as conn:
        cur = conn.execute(
            "SELECT session_id, target_url, repo_url, phase, started_at, "
            "completed_at, duration_seconds, error FROM pentest_sessions "
            "ORDER BY started_at DESC LIMIT ?",
            (limit,),
        )
        return [dict(r) for r in cur.fetchall()]


# Auto-initialize on import
init_db()
init_pentest_table()
