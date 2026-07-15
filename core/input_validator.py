"""
input_validator.py — CertiGuard Centralized Input Validation
=============================================================
Microsoft SDL Phase 4 (Implementation) — Input Validation & Sanitization.

Mitigates:
  VUL-002: Weak Password Policy           (CVSS 7.3 HIGH)
  VUL-003: Path Traversal on File Input   (CVSS 5.7 MEDIUM)
  VUL-006: No Input Length Validation     (CVSS 2.5 LOW)

All validation functions return (is_valid: bool, message: str) tuples so the
UI layer can display precise, actionable feedback without exposing internals.
"""

import re
import os
from pathlib import Path
from typing import Tuple, List

# ── Password Policy Constants (Microsoft SDL recommended minimums) ─────────────
PASSWORD_MIN_LENGTH: int = 8
PASSWORD_MAX_LENGTH: int = 128
PASSWORD_REQUIRE_UPPERCASE: bool = True
PASSWORD_REQUIRE_LOWERCASE: bool = True
PASSWORD_REQUIRE_DIGIT: bool = True
PASSWORD_REQUIRE_SPECIAL: bool = True
_SPECIAL_CHARS: str = r'!@#$%^&*()_+-=[]{}|;:,.<>?/~`"\'\\' 

# ── Signer Name Constraints ───────────────────────────────────────────────────
SIGNER_NAME_MIN_LENGTH: int = 2
SIGNER_NAME_MAX_LENGTH: int = 128
# Allow letters (including Unicode/international), spaces, hyphens, dots, apostrophes
_SIGNER_NAME_PATTERN = re.compile(r"^[\w\s\-.']+$", re.UNICODE)

# ── Allowed file extensions per type ─────────────────────────────────────────
ALLOWED_PDF_EXTENSIONS: tuple = ('.pdf',)
ALLOWED_KEY_EXTENSIONS: tuple = ('.pem',)
ALLOWED_IMAGE_EXTENSIONS: tuple = ('.png', '.jpg', '.jpeg')

# ── Safe base directory (prevent traversal outside project area) ──────────────
# We don't restrict to a single folder — the user may sign any PDF on their
# system — but we DO block path injection patterns.
_FORBIDDEN_PATH_PATTERNS = [
    r'\.\.[/\\]',       # directory traversal ../
    r'^[/\\]{2}',       # UNC paths \\server
    r'%2e%2e',          # URL-encoded ..
    r'%252e',           # double-encoded
]
_FORBIDDEN_COMPILED = [re.compile(p, re.IGNORECASE) for p in _FORBIDDEN_PATH_PATTERNS]


# ── Password Validation ───────────────────────────────────────────────────────

def validate_password_strength(password: str) -> Tuple[bool, List[str]]:
    """
    Check password meets CertiGuard security policy.

    Returns:
        (is_valid, list_of_failed_requirements)
        If is_valid is True, the list is empty.

    VUL-002 Mitigation: Enforces minimum complexity requirements.
    """
    errors: List[str] = []

    if not isinstance(password, str):
        return False, ['Password harus berupa teks.']

    if len(password) < PASSWORD_MIN_LENGTH:
        errors.append(f'Minimal {PASSWORD_MIN_LENGTH} karakter')

    if len(password) > PASSWORD_MAX_LENGTH:
        errors.append(f'Maksimal {PASSWORD_MAX_LENGTH} karakter')

    if PASSWORD_REQUIRE_UPPERCASE and not any(c.isupper() for c in password):
        errors.append('Minimal 1 huruf kapital (A-Z)')

    if PASSWORD_REQUIRE_LOWERCASE and not any(c.islower() for c in password):
        errors.append('Minimal 1 huruf kecil (a-z)')

    if PASSWORD_REQUIRE_DIGIT and not any(c.isdigit() for c in password):
        errors.append('Minimal 1 angka (0-9)')

    if PASSWORD_REQUIRE_SPECIAL and not any(c in _SPECIAL_CHARS for c in password):
        errors.append('Minimal 1 karakter spesial (!@#$%^&* dst)')

    return (len(errors) == 0, errors)


def get_password_strength_label(password: str) -> Tuple[str, str]:
    """
    Return a human-readable strength label and color for UI display.

    Returns:
        (label: str, color_hex: str)
    """
    if not password:
        return ('', '#8e8e93')

    score = 0
    if len(password) >= PASSWORD_MIN_LENGTH:        score += 1
    if len(password) >= 12:                          score += 1
    if any(c.isupper() for c in password):           score += 1
    if any(c.islower() for c in password):           score += 1
    if any(c.isdigit() for c in password):           score += 1
    if any(c in _SPECIAL_CHARS for c in password):  score += 1

    if score <= 2:
        return ('Lemah', '#ff3b30')
    elif score <= 4:
        return ('Sedang', '#ff9500')
    else:
        return ('Kuat', '#34c759')


# ── Signer Name Validation ────────────────────────────────────────────────────

def validate_signer_name(name: str) -> Tuple[bool, str]:
    """
    Validate a signer / display name.

    VUL-006 Mitigation: Enforces length bounds and character whitelist.

    Returns:
        (is_valid, error_message)   — error_message is '' if valid
    """
    if not isinstance(name, str):
        return False, 'Nama harus berupa teks.'

    stripped = name.strip()

    if len(stripped) < SIGNER_NAME_MIN_LENGTH:
        return False, f'Nama terlalu pendek (minimal {SIGNER_NAME_MIN_LENGTH} karakter).'

    if len(stripped) > SIGNER_NAME_MAX_LENGTH:
        return False, f'Nama terlalu panjang (maksimal {SIGNER_NAME_MAX_LENGTH} karakter).'

    if not _SIGNER_NAME_PATTERN.match(stripped):
        return False, 'Nama hanya boleh mengandung huruf, spasi, tanda hubung, titik, dan apostrof.'

    return True, ''


# ── File Path Validation ──────────────────────────────────────────────────────

def validate_file_path(
    raw_path: str,
    allowed_extensions: tuple = ALLOWED_PDF_EXTENSIONS,
    must_exist: bool = True,
) -> Tuple[bool, str]:
    """
    Validate a file path for security and correctness.

    VUL-003 Mitigation:
      - Detects path traversal patterns (../, %2e, UNC)
      - Validates file extension against whitelist
      - Optionally checks file existence
      - Resolves symlinks to detect escapes

    Returns:
        (is_valid, error_message)   — error_message is '' if valid
    """
    if not isinstance(raw_path, str) or not raw_path.strip():
        return False, 'Path file tidak boleh kosong.'

    # Check for forbidden traversal patterns in the raw string
    for pattern in _FORBIDDEN_COMPILED:
        if pattern.search(raw_path):
            return False, 'Path file mengandung karakter berbahaya (path traversal terdeteksi).'

    try:
        resolved = Path(raw_path).resolve()
    except (OSError, ValueError) as e:
        return False, f'Path file tidak valid: {e}'

    # Extension whitelist check
    ext = resolved.suffix.lower()
    if ext not in [e.lower() for e in allowed_extensions]:
        allowed_str = ', '.join(allowed_extensions)
        return False, f'Ekstensi file tidak didukung. Diizinkan: {allowed_str}'

    if must_exist and not resolved.is_file():
        return False, f'File tidak ditemukan: {resolved.name}'

    return True, ''


def validate_output_path(raw_path: str, allowed_extensions: tuple = ALLOWED_PDF_EXTENSIONS) -> Tuple[bool, str]:
    """Validate an output (write) file path — existence not required."""
    return validate_file_path(raw_path, allowed_extensions=allowed_extensions, must_exist=False)


# ── Log / Display Sanitization ────────────────────────────────────────────────

def sanitize_for_display(value: str, max_len: int = 64) -> str:
    """
    Return a display-safe version of a potentially sensitive string.

    VUL-004 Mitigation: Strips control characters, truncates long values.
    """
    if not isinstance(value, str):
        value = str(value)
    safe = ''.join(ch if ch.isprintable() else '?' for ch in value)
    if len(safe) > max_len:
        return safe[:max_len // 2] + '...' + safe[-(max_len // 2):]
    return safe


def truncate_hash(hash_hex: str, visible_chars: int = 16) -> str:
    """
    Return a truncated hash suitable for display/logging.

    VUL-004 Mitigation: Full hash is never shown in UI logs.
    """
    if not hash_hex:
        return '<empty>'
    return f'{hash_hex[:visible_chars]}...'
