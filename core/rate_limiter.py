"""
rate_limiter.py — CertiGuard Login Rate Limiter & Account Lockout
==================================================================
Microsoft SDL Phase 4 (Implementation) — Brute Force Protection.

Mitigates:
  VUL-001: Brute Force Login — No Rate Limiting  (CVSS 8.1 HIGH)

Policy (Microsoft SDL recommended defaults):
  - Max failed attempts : 5 within the observation window
  - Observation window  : 15 minutes
  - Lockout duration    : 15 minutes from the last failed attempt
  - Storage             : SQLite table `login_attempts` (same DB as users)

Thread safety: SQLite WAL mode + per-query connections ensure safe concurrent
use from the threading model used by the UI layer.
"""

import sqlite3
import os
from datetime import datetime, timezone, timedelta
from typing import Tuple

# ── Configuration (Microsoft SDL recommended values) ──────────────────────────
MAX_FAILED_ATTEMPTS: int      = 5          # consecutive failures before lockout
OBSERVATION_WINDOW_MINUTES: int = 15       # rolling window to count failures in
LOCKOUT_DURATION_MINUTES: int  = 15        # how long account stays locked

_DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), 'data', 'users.db'
)


# ── DB Initialization ─────────────────────────────────────────────────────────

def init_rate_limit_table() -> None:
    """
    Create the login_attempts table if it doesn't exist.
    Called by auth.init_db() so the schema is always in sync.
    """
    conn = sqlite3.connect(_DB_PATH)
    conn.execute('PRAGMA journal_mode=WAL')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS login_attempts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT NOT NULL,
            attempted_at TEXT NOT NULL,
            success     INTEGER NOT NULL DEFAULT 0
        )
    ''')
    conn.commit()
    conn.close()


# ── Public API ────────────────────────────────────────────────────────────────

def record_attempt(username: str, success: bool) -> None:
    """
    Persist a login attempt (success or failure).

    Args:
        username: The username that attempted to log in.
        success:  True if the attempt succeeded, False otherwise.
    """
    now_iso = datetime.now(timezone.utc).isoformat()
    conn = sqlite3.connect(_DB_PATH)
    conn.execute('PRAGMA journal_mode=WAL')
    cursor = conn.cursor()
    cursor.execute(
        'INSERT INTO login_attempts (username, attempted_at, success) VALUES (?, ?, ?)',
        (username, now_iso, 1 if success else 0),
    )
    conn.commit()
    conn.close()


def check_lockout(username: str) -> Tuple[bool, int, int]:
    """
    Determine whether a username is currently locked out.

    Returns:
        (is_locked: bool, failed_count: int, seconds_remaining: int)
        - is_locked        : True if the account is currently locked
        - failed_count     : Number of recent failed attempts in the window
        - seconds_remaining: Seconds until lockout expires (0 if not locked)

    VUL-001 Mitigation: Enforces exponential-equivalent backoff via hard lockout.
    """
    now = datetime.now(timezone.utc)
    window_start = (now - timedelta(minutes=OBSERVATION_WINDOW_MINUTES)).isoformat()

    conn = sqlite3.connect(_DB_PATH)
    conn.execute('PRAGMA journal_mode=WAL')
    cursor = conn.cursor()

    # Count consecutive failures within the rolling window
    cursor.execute(
        '''
        SELECT attempted_at FROM login_attempts
        WHERE username = ?
          AND attempted_at >= ?
          AND success = 0
        ORDER BY attempted_at DESC
        ''',
        (username, window_start),
    )
    rows = cursor.fetchall()
    conn.close()

    failed_count = len(rows)

    if failed_count < MAX_FAILED_ATTEMPTS:
        return (False, failed_count, 0)

    # Locked: calculate remaining seconds from the most recent failure
    latest_str = rows[0][0]  # already ordered DESC
    try:
        # Handle ISO strings with or without timezone suffix
        if latest_str.endswith('+00:00'):
            latest = datetime.fromisoformat(latest_str)
        else:
            latest = datetime.fromisoformat(latest_str).replace(tzinfo=timezone.utc)
    except ValueError:
        # Fallback: treat as if just locked now
        latest = now

    unlock_at = latest + timedelta(minutes=LOCKOUT_DURATION_MINUTES)
    remaining = (unlock_at - now).total_seconds()

    if remaining <= 0:
        # Lock has expired — they can try again
        return (False, failed_count, 0)

    return (True, failed_count, int(remaining))


def clear_failed_attempts(username: str) -> None:
    """
    Remove all failed attempts for a username after a successful login.
    This resets the lockout counter without affecting the audit history
    (successful attempts remain in the table for audit purposes).
    """
    conn = sqlite3.connect(_DB_PATH)
    conn.execute('PRAGMA journal_mode=WAL')
    cursor = conn.cursor()
    cursor.execute(
        "DELETE FROM login_attempts WHERE username = ? AND success = 0",
        (username,),
    )
    conn.commit()
    conn.close()


def get_attempt_stats(username: str) -> dict:
    """
    Return a summary dict of recent login statistics for a username.
    Used by the security dashboard in the UI.
    """
    now = datetime.now(timezone.utc)
    window_start = (now - timedelta(minutes=OBSERVATION_WINDOW_MINUTES)).isoformat()

    conn = sqlite3.connect(_DB_PATH)
    conn.execute('PRAGMA journal_mode=WAL')
    cursor = conn.cursor()
    cursor.execute(
        '''
        SELECT success, COUNT(*) FROM login_attempts
        WHERE username = ? AND attempted_at >= ?
        GROUP BY success
        ''',
        (username, window_start),
    )
    rows = cursor.fetchall()
    conn.close()

    stats = {'failed': 0, 'success': 0}
    for success_flag, count in rows:
        if success_flag:
            stats['success'] = count
        else:
            stats['failed'] = count
    return stats
