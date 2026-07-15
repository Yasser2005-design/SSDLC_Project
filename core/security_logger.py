"""
security_logger.py — CertiGuard Centralized Security Logger
============================================================
Microsoft SDL Phase 7 (Response) & SSDLC Audit Trail requirement.

Mitigates:
  VUL-004: Sensitive Data Exposure in Logs   (CVSS 4.0 MEDIUM)
  VUL-005: No Audit Trail / Session Logging  (CVSS 4.3 MEDIUM)

All security-relevant events (login, lockout, sign, verify) are written to
data/audit.log with structured fields. Raw print() statements in core modules
are replaced by calls to this logger at the appropriate level.
"""

import logging
import os
from logging.handlers import RotatingFileHandler
from datetime import datetime, timezone
from pathlib import Path

# ── Paths ──────────────────────────────────────────────────────────────────────
_BASE_DIR  = Path(__file__).parent.parent  # certiguard/
_DATA_DIR  = _BASE_DIR / 'data'
_AUDIT_LOG = _DATA_DIR / 'audit.log'
_APP_LOG   = _DATA_DIR / 'app.log'

# ── Logger names ───────────────────────────────────────────────────────────────
AUDIT_LOGGER_NAME = 'certiguard.audit'
APP_LOGGER_NAME   = 'certiguard.app'

_initialized = False


def _ensure_data_dir() -> None:
    _DATA_DIR.mkdir(parents=True, exist_ok=True)


def init_logging() -> None:
    """
    Initialize all loggers. Must be called once at application startup (main.py).
    Safe to call multiple times — subsequent calls are no-ops.
    """
    global _initialized
    if _initialized:
        return
    _initialized = True

    _ensure_data_dir()

    # ── Audit logger (security events → file, NOT console) ──────────────────
    audit_logger = logging.getLogger(AUDIT_LOGGER_NAME)
    audit_logger.setLevel(logging.INFO)
    audit_logger.propagate = False  # never bubble up to root

    audit_fmt = logging.Formatter(
        fmt='%(asctime)s | %(levelname)-8s | %(message)s',
        datefmt='%Y-%m-%dT%H:%M:%S%z',
    )
    audit_handler = RotatingFileHandler(
        str(_AUDIT_LOG),
        maxBytes=5 * 1024 * 1024,  # 5 MB per file
        backupCount=5,
        encoding='utf-8',
    )
    audit_handler.setFormatter(audit_fmt)
    audit_logger.addHandler(audit_handler)

    # ── App / debug logger (operational info → app.log + stderr) ────────────
    app_logger = logging.getLogger(APP_LOGGER_NAME)
    app_logger.setLevel(logging.DEBUG)
    app_logger.propagate = False

    app_fmt = logging.Formatter(
        fmt='%(asctime)s | %(levelname)-8s | %(name)s | %(message)s',
        datefmt='%Y-%m-%dT%H:%M:%S',
    )
    app_file_handler = RotatingFileHandler(
        str(_APP_LOG),
        maxBytes=10 * 1024 * 1024,
        backupCount=3,
        encoding='utf-8',
    )
    app_file_handler.setFormatter(app_fmt)
    app_logger.addHandler(app_file_handler)


# ── Public helper accessors ────────────────────────────────────────────────────

def get_audit_logger() -> logging.Logger:
    """Return the audit security logger (always logs to file)."""
    if not _initialized:
        init_logging()
    return logging.getLogger(AUDIT_LOGGER_NAME)


def get_app_logger() -> logging.Logger:
    """Return the application operational logger."""
    if not _initialized:
        init_logging()
    return logging.getLogger(APP_LOGGER_NAME)


# ── Structured audit event helpers ────────────────────────────────────────────

def log_login_attempt(username: str, success: bool, reason: str = '') -> None:
    """
    Record a login attempt.

    VUL-005 Mitigation: Every authentication attempt is traceable.
    VUL-004 Mitigation: Username is logged but password is NEVER logged.
    """
    _audit = get_audit_logger()
    status = 'SUCCESS' if success else 'FAILURE'
    suffix = f' | reason={reason}' if reason else ''
    # Sanitize username: truncate + strip control chars to prevent log injection
    safe_user = _sanitize_log_value(username, max_len=64)
    _audit.info(f'AUTH_LOGIN | user={safe_user} | status={status}{suffix}')


def log_lockout(username: str, attempt_count: int) -> None:
    """Record account lockout event."""
    _audit = get_audit_logger()
    safe_user = _sanitize_log_value(username, max_len=64)
    _audit.warning(f'AUTH_LOCKOUT | user={safe_user} | attempts={attempt_count}')


def log_sign_event(username: str, doc_name: str, hash_prefix: str, success: bool) -> None:
    """
    Record a document signing event.

    VUL-004 Mitigation: Only first 16 chars of hash logged (not full hash).
    """
    _audit = get_audit_logger()
    status = 'SUCCESS' if success else 'FAILURE'
    safe_user = _sanitize_log_value(username, max_len=64)
    safe_doc  = _sanitize_log_value(doc_name,  max_len=128)
    _audit.info(
        f'DOC_SIGN | user={safe_user} | doc={safe_doc} '
        f'| hash_prefix={hash_prefix[:16]}... | status={status}'
    )


def log_verify_event(username: str, doc_name: str, is_valid: bool) -> None:
    """Record a document verification event."""
    _audit = get_audit_logger()
    result = 'VALID' if is_valid else 'INVALID'
    safe_user = _sanitize_log_value(username, max_len=64)
    safe_doc  = _sanitize_log_value(doc_name,  max_len=128)
    _audit.info(f'DOC_VERIFY | user={safe_user} | doc={safe_doc} | result={result}')


def log_app_start(version: str) -> None:
    """Record application startup."""
    _audit = get_audit_logger()
    _audit.info(f'APP_START | version={version}')


def log_app_stop() -> None:
    """Record application shutdown."""
    _audit = get_audit_logger()
    _audit.info('APP_STOP')


# ── Internal utilities ─────────────────────────────────────────────────────────

def _sanitize_log_value(value: str, max_len: int = 128) -> str:
    """
    Sanitize a string for safe inclusion in log lines.

    VUL-004 Mitigation: Prevents log injection via newline stripping.
    """
    if not isinstance(value, str):
        value = str(value)
    # Strip control characters (newlines, carriage returns, tabs) — log injection prevention
    safe = ''.join(ch if ch.isprintable() and ch not in '\r\n\t' else '_' for ch in value)
    return safe[:max_len]


def get_audit_log_path() -> str:
    """Return the absolute path of the audit log file."""
    return str(_AUDIT_LOG.resolve())
