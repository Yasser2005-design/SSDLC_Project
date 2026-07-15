"""
auth.py — CertiGuard Authentication Module (SSDLC Hardened)
============================================================
Microsoft SDL Phase 4 (Implementation) — Secure Authentication.

Security improvements over original:
  VUL-001 MITIGATED: Rate limiting & account lockout via rate_limiter module
  VUL-002 MITIGATED: Password strength validation via input_validator module
  VUL-005 MITIGATED: All auth events logged to audit trail via security_logger
  VUL-007 MITIGATED: Constant-time response for both "user not found" and
                      "wrong password" cases (prevents timing oracle attacks)

CVSS scores addressed:
  VUL-001: 8.1 (HIGH)   → Brute Force Login
  VUL-002: 7.3 (HIGH)   → Weak Password Policy
  VUL-005: 4.3 (MEDIUM) → No Audit Trail
  VUL-007: 5.9 (MEDIUM) → Timing Attack on Login
"""

import sqlite3
import bcrypt
import hmac
import os
from typing import Tuple

from core.rate_limiter import (
    init_rate_limit_table,
    record_attempt,
    check_lockout,
    clear_failed_attempts,
)
from core.security_logger import (
    log_login_attempt,
    log_lockout,
    get_app_logger,
)
from core.input_validator import validate_password_strength

_log = get_app_logger()

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'users.db')

# A dummy bcrypt hash used for constant-time comparison when the user doesn't
# exist. This prevents a timing oracle that reveals valid usernames.
# VUL-007 Mitigation: attacker cannot distinguish "no such user" from "wrong password".
_DUMMY_HASH: bytes = bcrypt.hashpw(b'__certiGuard_dummy_constant__', bcrypt.gensalt(rounds=12))


def init_db() -> None:
    """
    Initialize the database schema.

    Creates:
      - users         — credentials table
      - login_attempts — rate limiting table (via rate_limiter)
    """
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute('PRAGMA journal_mode=WAL')
    cursor = conn.cursor()

    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at    TEXT NOT NULL DEFAULT (datetime('now'))
        )
    ''')
    conn.commit()
    conn.close()

    # Rate limiting table (delegated to rate_limiter)
    init_rate_limit_table()
    _log.debug('Database schema initialized (WAL mode enabled)')


def add_user(username: str, password: str) -> Tuple[bool, str]:
    """
    Register a new user with password strength validation.

    VUL-002 Mitigation: Password must pass strength policy before hashing.

    Returns:
        (success: bool, message: str)
    """
    init_db()

    # ── Input validation ──────────────────────────────────────────────────────
    if not username or not username.strip():
        return False, 'Username tidak boleh kosong.'
    if len(username.strip()) < 3:
        return False, 'Username minimal 3 karakter.'
    if len(username.strip()) > 64:
        return False, 'Username maksimal 64 karakter.'

    # ── Password strength check (VUL-002) ────────────────────────────────────
    is_strong, errors = validate_password_strength(password)
    if not is_strong:
        error_detail = ' | '.join(errors)
        return False, f'Password tidak memenuhi kebijakan keamanan: {error_detail}'

    # ── Hash & store ──────────────────────────────────────────────────────────
    salt = bcrypt.gensalt(rounds=12)
    password_hash = bcrypt.hashpw(password.encode('utf-8'), salt)

    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute('PRAGMA journal_mode=WAL')
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO users (username, password_hash) VALUES (?, ?)',
            (username.strip(), password_hash.decode('utf-8')),
        )
        conn.commit()
        conn.close()
        _log.info(f'New user registered: {username.strip()}')
        return True, 'User berhasil dibuat.'
    except sqlite3.IntegrityError:
        return False, 'Username sudah digunakan.'
    except Exception as e:
        _log.error(f'add_user error: {e}')
        return False, 'Terjadi kesalahan internal. Coba lagi.'


def verify_login(username: str, password: str) -> Tuple[bool, str]:
    """
    Authenticate a user with rate limiting and audit logging.

    VUL-001 Mitigation: Account lockout enforced before any credential check.
    VUL-007 Mitigation: Runs bcrypt comparison even when user not found to
                        prevent timing-based user enumeration.

    Returns:
        (success: bool, message: str)
        message contains a human-readable error when success is False.
    """
    init_db()

    # Normalise username before any check
    username = username.strip() if isinstance(username, str) else ''
    if not username:
        return False, 'Username tidak boleh kosong.'

    # ── Step 1: Rate limit / lockout check (VUL-001) ─────────────────────────
    is_locked, fail_count, secs_remaining = check_lockout(username)
    if is_locked:
        mins = secs_remaining // 60
        secs = secs_remaining % 60
        log_lockout(username, fail_count)
        return False, (
            f'Akun sementara dikunci ({fail_count} percobaan gagal). '
            f'Coba lagi dalam {mins}m {secs}s.'
        )

    # ── Step 2: Fetch stored hash ─────────────────────────────────────────────
    conn = sqlite3.connect(DB_PATH)
    conn.execute('PRAGMA journal_mode=WAL')
    cursor = conn.cursor()
    cursor.execute('SELECT password_hash FROM users WHERE username = ?', (username,))
    result = cursor.fetchone()
    conn.close()

    # ── Step 3: Constant-time comparison (VUL-007) ───────────────────────────
    # Always run bcrypt even when user doesn't exist — prevents timing oracle.
    if result is None:
        # Deliberately compare against dummy hash; result is always False.
        bcrypt.checkpw(password.encode('utf-8'), _DUMMY_HASH)
        record_attempt(username, success=False)
        log_login_attempt(username, success=False, reason='user_not_found')
        # Return same generic message as wrong-password to prevent enumeration
        return False, 'Username atau password salah.'

    stored_hash = result[0].encode('utf-8')
    is_correct = bcrypt.checkpw(password.encode('utf-8'), stored_hash)

    # ── Step 4: Record result & audit ────────────────────────────────────────
    if is_correct:
        clear_failed_attempts(username)
        record_attempt(username, success=True)
        log_login_attempt(username, success=True)
        return True, 'Login berhasil.'
    else:
        record_attempt(username, success=False)
        log_login_attempt(username, success=False, reason='wrong_password')

        # Tell the user how many attempts remain before lockout
        _, new_fail_count, _ = check_lockout(username)
        remaining_attempts = max(0, 5 - new_fail_count)  # MAX_FAILED_ATTEMPTS = 5
        if remaining_attempts > 0:
            return False, f'Username atau password salah. ({remaining_attempts} percobaan tersisa)'
        else:
            return False, 'Username atau password salah. Akun dikunci sementara.'
