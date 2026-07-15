"""
main.py — CertiGuard Entry Point (SSDLC Hardened)
==================================================
Microsoft SDL Phase 4 (Implementation) — Secure Startup.

Initializes the security logging infrastructure before any other module is
loaded, ensuring all events (including import-time operations) are captured.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ── Security infrastructure must be initialized FIRST (VUL-004, VUL-005) ──
from core.security_logger import init_logging, log_app_start, log_app_stop
init_logging()

import customtkinter as ctk
from ui.app import CertiGuardApp

APP_VERSION = '1.1.0'   # SSDLC security hardening release


def main() -> None:
    log_app_start(version=APP_VERSION)

    ctk.set_appearance_mode('light')
    ctk.set_default_color_theme('blue')

    app = CertiGuardApp()

    print('┌─────────────────────────────────────────┐')
    print('│  CertiGuard v1.1.0                      │')
    print('│  Document Authentication System         │')
    print('│  SHA-256 / RSA-PSS / QR Code            │')
    print('│  Secured: Microsoft SDL + CVSS v3.1     │')
    print('└─────────────────────────────────────────┘')

    try:
        app.mainloop()
    finally:
        # Always log shutdown, even on crash
        log_app_stop()


if __name__ == '__main__':
    main()
