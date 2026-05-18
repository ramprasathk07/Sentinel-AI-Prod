"""Wipe scan/pentest/RL cache from sentinel.db while preserving credentials.

Default behavior — clears volatile scan output, keeps credentials and RL training pairs:
    analysis_logs        — cached PR scan results
    ground_truth_labels  — thumbs up/down feedback (FK to analysis_logs)
    pentest_sessions     — pentest run history

Preserved by default (credentials + curated training data):
    user_tokens          — encrypted GitHub tokens (legacy)
    github_user_tokens   — encrypted GitHub OAuth tokens (v2)
    watches              — webhook registrations
    rl_pairs             — RL training pairs (human-reviewed, expensive to recreate)

CLI flags:
    --wipe-rl            — also clear rl_pairs + delete data/rl/ + .prompts/ disk mirrors
    --wipe-watches       — also clear watches table
    --wipe-tokens        — also clear user_tokens + github_user_tokens (DESTRUCTIVE)
    --all                — wipe everything except encrypted token tables
    [path]               — optional path to sentinel.db (default: ./sentinel.db)

Examples:
    python clear_db_cache.py
    python clear_db_cache.py --wipe-rl
    python clear_db_cache.py --all ./sentinel.db
"""

import argparse
import shutil
import sqlite3
import sys
from pathlib import Path

DEFAULT_CACHE = ["ground_truth_labels", "analysis_logs", "pentest_sessions"]
RL_TABLES = ["rl_pairs"]
WATCH_TABLES = ["watches"]
TOKEN_TABLES = ["user_tokens", "github_user_tokens"]

RL_DISK_DIRS = ["data/rl", ".prompts"]


def _table_count(cur: sqlite3.Cursor, tbl: str) -> int:
    cur.execute(f"SELECT COUNT(*) FROM {tbl}")
    return cur.fetchone()[0]


def _wipe_tables(cur: sqlite3.Cursor, tables: list, existing: set) -> list:
    """Wipe given tables. Returns list of names actually wiped."""
    wiped = []
    for tbl in tables:
        if tbl not in existing:
            print(f"[skip] {tbl}: table not present")
            continue
        before = _table_count(cur, tbl)
        cur.execute(f"DELETE FROM {tbl}")
        print(f"[wipe] {tbl}: removed {before} row(s)")
        wiped.append(tbl)
    return wiped


def _clean_rl_disk(project_root: Path) -> None:
    """Remove RL JSON mirrors + cached prompt files from disk."""
    for rel in RL_DISK_DIRS:
        path = project_root / rel
        if not path.exists():
            print(f"[skip] {rel}: directory not present")
            continue
        try:
            file_count = sum(1 for _ in path.rglob("*") if _.is_file())
            shutil.rmtree(path)
            path.mkdir(parents=True, exist_ok=True)
            print(f"[wipe] {rel}: removed {file_count} file(s)")
        except OSError as exc:
            print(f"[fail] {rel}: {exc}")


def clear_cache(
    db_path: Path,
    wipe_rl: bool = False,
    wipe_watches: bool = False,
    wipe_tokens: bool = False,
) -> None:
    if not db_path.exists():
        print(f"[skip] {db_path} does not exist — nothing to clear")
        return

    cache_tables = list(DEFAULT_CACHE)
    if wipe_rl:
        cache_tables += RL_TABLES
    if wipe_watches:
        cache_tables += WATCH_TABLES
    if wipe_tokens:
        cache_tables += TOKEN_TABLES

    preserved_tables = []
    if not wipe_rl:
        preserved_tables += RL_TABLES
    if not wipe_watches:
        preserved_tables += WATCH_TABLES
    if not wipe_tokens:
        preserved_tables += TOKEN_TABLES

    with sqlite3.connect(db_path) as conn:
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        existing = {r[0] for r in cur.fetchall()}

        wiped = _wipe_tables(cur, cache_tables, existing)

        if wiped:
            placeholders = ",".join("?" * len(wiped))
            cur.execute(
                f"DELETE FROM sqlite_sequence WHERE name IN ({placeholders})",
                wiped,
            )

        conn.commit()
        cur.execute("VACUUM")

        print("\n[preserved]")
        for tbl in preserved_tables:
            if tbl not in existing:
                print(f"  {tbl}: not present")
                continue
            print(f"  {tbl}: {_table_count(cur, tbl)} row(s) kept")

    if wipe_rl:
        print("\n[rl-disk]")
        _clean_rl_disk(db_path.parent)


def _parse_args(argv: list) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Wipe scan/pentest/RL cache from sentinel.db",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=None,
        help="Path to sentinel.db (default: ./sentinel.db)",
    )
    parser.add_argument(
        "--wipe-rl",
        action="store_true",
        help="Also clear rl_pairs + delete data/rl/ and .prompts/ disk mirrors",
    )
    parser.add_argument(
        "--wipe-watches",
        action="store_true",
        help="Also clear watches table (webhook registrations)",
    )
    parser.add_argument(
        "--wipe-tokens",
        action="store_true",
        help="Also clear user_tokens + github_user_tokens (DESTRUCTIVE — credentials lost)",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Wipe everything except encrypted token tables (shortcut for --wipe-rl --wipe-watches)",
    )
    return parser.parse_args(argv)


if __name__ == "__main__":
    args = _parse_args(sys.argv[1:])

    if args.all:
        args.wipe_rl = True
        args.wipe_watches = True

    db = Path(args.path) if args.path else Path(__file__).parent / "sentinel.db"
    print(f"Target DB: {db}")
    flags = []
    if args.wipe_rl:
        flags.append("rl")
    if args.wipe_watches:
        flags.append("watches")
    if args.wipe_tokens:
        flags.append("tokens")
    print(f"Extra wipes: {', '.join(flags) if flags else 'none'}\n")

    clear_cache(
        db,
        wipe_rl=args.wipe_rl,
        wipe_watches=args.wipe_watches,
        wipe_tokens=args.wipe_tokens,
    )
    print("\nDone.")
