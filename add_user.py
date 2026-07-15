"""
add_user.py — CertiGuard User Registration CLI (SSDLC Hardened)
================================================================
Microsoft SDL Phase 4 (Implementation) — Secure User Provisioning.

Improvements:
  VUL-002 MITIGATED: Password policy displayed before input
  VUL-002 MITIGATED: Old 6-char minimum replaced with full policy check (done in auth.add_user)

Usage:
    python add_user.py
"""

import sys
import os
import getpass

# Add the project root to the path so we can import core modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.security_logger import init_logging
init_logging()  # Must initialize before importing auth

from core.auth import add_user
from core.input_validator import (
    validate_password_strength,
    get_password_strength_label,
    PASSWORD_MIN_LENGTH,
)


def main():
    print('╔══════════════════════════════════════════╗')
    print('║   CertiGuard — Add New User (CLI)        ║')
    print('║   Secured by Microsoft SDL               ║')
    print('╚══════════════════════════════════════════╝')
    print()

    username = input('Enter new username: ').strip()
    if not username:
        print('❌  Username cannot be empty.')
        return

    # Display password policy before prompting (VUL-002)
    print()
    print('Password Policy (Microsoft SDL):')
    print(f'  ✔ Minimum {PASSWORD_MIN_LENGTH} characters')
    print('  ✔ At least 1 uppercase letter (A-Z)')
    print('  ✔ At least 1 lowercase letter (a-z)')
    print('  ✔ At least 1 digit (0-9)')
    print('  ✔ At least 1 special character (!@#$%^&* etc.)')
    print()

    password = getpass.getpass('Enter password: ')
    confirm_password = getpass.getpass('Confirm password: ')

    if password != confirm_password:
        print('❌  Passwords do not match!')
        return

    # Show strength feedback before submitting
    label, color_hint = get_password_strength_label(password)
    print(f'\nPassword strength: {label}')

    is_strong, errors = validate_password_strength(password)
    if not is_strong:
        print('❌  Password does not meet policy requirements:')
        for err in errors:
            print(f'     • {err}')
        return

    print('\nRegistering user...')
    success, msg = add_user(username, password)

    if success:
        print(f'✅  {msg}')
    else:
        print(f'❌  {msg}')


if __name__ == '__main__':
    main()
