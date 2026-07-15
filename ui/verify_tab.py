import threading
from pathlib import Path
from tkinter import filedialog
from typing import Callable, Optional
import base64

import customtkinter as ctk
from core.hasher import hash_pdf_content
from core.signer import load_public_key, verify_signature
from core.qr_manager import decode_qr_payload
from utils.pdf_embedder import extract_qr_from_pdf
from core.input_validator import validate_file_path, ALLOWED_PDF_EXTENSIONS, ALLOWED_KEY_EXTENSIONS
from core.security_logger import log_verify_event


def _section_label(parent, text):
    ctk.CTkLabel(
        parent, text=text,
        font=ctk.CTkFont(family='SF Pro Display', size=11, weight='bold'),
        text_color='#8e8e93', anchor='w',
    ).pack(fill='x', padx=0, pady=(12, 3))


class VerifyTab:
    """Verify tab rendered inside the right panel of app.py."""

    def __init__(self, parent: ctk.CTkFrame, status_callback: Callable[[str], None]) -> None:
        self.parent = parent
        self.status_callback = status_callback
        self._pdf_path: Optional[str] = None
        self._key_path: Optional[str] = None
        self._is_processing = False
        self.current_user: str = 'unknown'  # Set by app.py after login (VUL-005)

        # Root frame — pack/unpack to show/hide
        self._frame = ctk.CTkFrame(parent, fg_color='transparent')
        self._frame.grid_columnconfigure(0, weight=1)
        self._build_ui()

    # ── show / hide API
    def show(self):
        self._frame.pack(fill='both', expand=True, padx=4, pady=4)

    def hide(self):
        self._frame.pack_forget()

    def pack_forget_all(self):
        self._frame.pack_forget()

    # ── Build UI ─────────────────────────────────────────────────────────────
    def _build_ui(self):
        f = self._frame

        # ── Signed PDF picker ──
        _section_label(f, 'SIGNED PDF DOCUMENT')
        pdf_card = ctk.CTkFrame(f, fg_color='#f5f5f7', corner_radius=14,
                                 border_width=1, border_color='#e5e5ea')
        pdf_card.pack(fill='x', pady=(0, 4))
        pdf_card.grid_columnconfigure(0, weight=1)

        self.pdf_path_label = ctk.CTkLabel(
            pdf_card, text='No file selected',
            font=ctk.CTkFont(family='SF Pro Display', size=12),
            text_color='#8e8e93', anchor='w',
        )
        self.pdf_path_label.grid(row=0, column=0, sticky='ew', padx=14, pady=12)

        ctk.CTkButton(
            pdf_card, text='Browse', width=80, height=30,
            font=ctk.CTkFont(family='SF Pro Display', size=12),
            fg_color='#ffffff', hover_color='#e5e5ea',
            text_color='#007aff', corner_radius=8,
            command=self._browse_pdf,
        ).grid(row=0, column=1, padx=(0, 10), pady=10)

        # ── Public Key picker ──
        _section_label(f, 'PUBLIC KEY (.pem)')
        key_card = ctk.CTkFrame(f, fg_color='#f5f5f7', corner_radius=14,
                                 border_width=1, border_color='#e5e5ea')
        key_card.pack(fill='x', pady=(0, 4))
        key_card.grid_columnconfigure(0, weight=1)

        self.key_path_label = ctk.CTkLabel(
            key_card, text='No key selected',
            font=ctk.CTkFont(family='SF Pro Display', size=12),
            text_color='#8e8e93', anchor='w',
        )
        self.key_path_label.grid(row=0, column=0, sticky='ew', padx=14, pady=12)

        ctk.CTkButton(
            key_card, text='Browse', width=80, height=30,
            font=ctk.CTkFont(family='SF Pro Display', size=12),
            fg_color='#ffffff', hover_color='#e5e5ea',
            text_color='#007aff', corner_radius=8,
            command=self._browse_key,
        ).grid(row=0, column=1, padx=(0, 10), pady=10)

        # ── Result badge ──
        _section_label(f, 'VERIFICATION STATUS')
        self.badge_frame = ctk.CTkFrame(f, fg_color='#f5f5f7', corner_radius=14,
                                         border_width=1, border_color='#e5e5ea', height=70)
        self.badge_frame.pack(fill='x', pady=(0, 16))
        self.badge_frame.pack_propagate(False)

        self.badge_label = ctk.CTkLabel(
            self.badge_frame,
            text='Awaiting verification...',
            font=ctk.CTkFont(family='SF Pro Display', size=15, weight='bold'),
            text_color='#8e8e93',
        )
        self.badge_label.place(relx=0.5, rely=0.5, anchor='center')

        # ── Progress bar ──
        self.progress_bar = ctk.CTkProgressBar(
            f, mode='indeterminate', height=3,
            progress_color='#34c759', fg_color='#e5e5ea',
        )
        self.progress_bar.pack(fill='x', pady=(0, 8))
        self.progress_bar.pack_forget()

        # ── Verify button ──
        self.verify_btn = ctk.CTkButton(
            f, text='✅  Verify Document',
            height=52, corner_radius=14,
            fg_color='#34c759', hover_color='#28a745',
            text_color='#ffffff',
            font=ctk.CTkFont(family='SF Pro Display', size=15, weight='bold'),
            command=self._on_verify_click,
        )
        self.verify_btn.pack(fill='x', pady=(0, 4))

    # ── Helpers ──────────────────────────────────────────────────────────────
    def _browse_pdf(self):
        fp = filedialog.askopenfilename(
            title='Select Signed PDF', filetypes=[('PDF files', '*.pdf')])
        if fp:
            # VUL-003 Mitigation: validate path before accepting
            is_valid, err = validate_file_path(fp, allowed_extensions=ALLOWED_PDF_EXTENSIONS)
            if not is_valid:
                self.status_callback(f'❌ File tidak valid: {err}')
                return
            self._pdf_path = fp
            self.pdf_path_label.configure(text=Path(fp).name, text_color='#1d1d1f')
            self.status_callback(f'PDF: {Path(fp).name}')

    def _browse_key(self):
        fp = filedialog.askopenfilename(
            title='Select Public Key', filetypes=[('PEM files', '*.pem')])
        if fp:
            # VUL-003 Mitigation: validate key file path
            is_valid, err = validate_file_path(fp, allowed_extensions=ALLOWED_KEY_EXTENSIONS)
            if not is_valid:
                self.status_callback(f'❌ File key tidak valid: {err}')
                return
            self._key_path = fp
            self.key_path_label.configure(text=Path(fp).name, text_color='#1d1d1f')
            self.status_callback(f'Key: {Path(fp).name}')

    # ── Verify action ────────────────────────────────────────────────────────
    def _on_verify_click(self):
        if self._is_processing:
            return
        if not self._pdf_path:
            self.status_callback('❌ Select a signed PDF first')
            return
        if not self._key_path:
            self.status_callback('❌ Select a public key file')
            return

        self._is_processing = True
        self.verify_btn.configure(state='disabled', text='⏳  Verifying...')
        self.progress_bar.pack(fill='x', pady=(0, 8))
        self.progress_bar.start()
        self.badge_label.configure(text='Verifying...', text_color='#6e6e73')
        self.status_callback('⏳  Verifying document...')

        threading.Thread(
            target=self._perform_verification,
            args=(self._pdf_path, self._key_path),
            daemon=True,
        ).start()

    def _perform_verification(self, pdf_path: str, key_path: str):
        try:
            lines = [
                '═' * 44,
                '  CertiGuard — Verification Report',
                '═' * 44, '',
            ]

            lines.append('[1/4] Extracting QR code from PDF...')
            payload = extract_qr_from_pdf(pdf_path)
            if not payload:
                raise ValueError('No QR code found in the document.')
            parsed = decode_qr_payload(payload)
            lines.append(f'  Signer: {parsed.get("signer", "Unknown")}')
            lines.append(f'  Signed: {parsed.get("timestamp", "Unknown")[:10]}')
            lines.append('')

            lines.append('[2/4] Hashing PDF (SHA-256)...')
            # BUGFIX: hash only the original signed pages, NOT the appended QR page.
            # When signing we hashed N pages; the signed PDF now has N+1 pages (QR page added).
            # We must pass signed_page_count so hash_pdf_content() skips the QR signature page.
            signed_page_count = parsed.get('signed_page_count')
            doc_hash, t2 = hash_pdf_content(pdf_path, page_count=signed_page_count)
            lines.append(f'  Pages hashed: {signed_page_count}')
            lines.append(f'  Hash: {doc_hash[:24]}...')
            if doc_hash != parsed.get('doc_hash'):
                raise ValueError('Document hash mismatch — file may have been tampered.')
            lines.append('  ✓ Hash matched!')
            lines.append('')

            lines.append('[3/4] Loading public key...')
            pub = load_public_key(key_path)
            lines.append(f'  Key: {Path(key_path).name}')
            lines.append('')

            lines.append('[4/4] Verifying RSA-PSS signature...')
            sig_bytes = parsed.get('signature')
            if not isinstance(sig_bytes, (bytes, bytearray)):
                raise ValueError('Signature payload tidak valid.')
            is_valid, t4 = verify_signature(pub, doc_hash, bytes(sig_bytes))
            lines.append('')
            lines.append('─' * 44)

            if is_valid:
                lines.append('✅  SIGNATURE VALID')
                lines.append(f'  Time: {t2 + t4:.2f} ms')
                # VUL-005 Mitigation: audit log verification result
                log_verify_event(self.current_user, Path(pdf_path).name, is_valid=True)
                self._frame.after(0, lambda: self._set_badge(True))
                self._frame.after(0, lambda: self.status_callback('✅ Verification passed — authentic document'))
            else:
                lines.append('❌  INVALID SIGNATURE')
                log_verify_event(self.current_user, Path(pdf_path).name, is_valid=False)
                self._frame.after(0, lambda: self._set_badge(False))
                self._frame.after(0, lambda: self.status_callback('❌ Verification failed — invalid signature'))
            lines.append('─' * 44)

            self._frame.after(0, lambda: self.status_callback('\n' + '\n'.join(lines)))

        except ValueError as e:
            error_message = f'❌ {e}'
            self._frame.after(0, lambda: self._set_badge(False))
            self._frame.after(0, lambda msg=error_message: self.status_callback(msg))
        except Exception as e:
            error_message = f'❌ {type(e).__name__}: {e}'
            self._frame.after(0, lambda: self._set_badge(False))
            self._frame.after(0, lambda msg=error_message: self.status_callback(msg))
        finally:
            self._frame.after(0, self._reset_btn)

    def _set_badge(self, is_valid: bool):
        if is_valid:
            self.badge_frame.configure(fg_color='#eefaf1', border_color='#34c759')
            self.badge_label.configure(text='✅  VALID DOCUMENT', text_color='#248a3d')
        else:
            self.badge_frame.configure(fg_color='#fff0ef', border_color='#ff3b30')
            self.badge_label.configure(text='❌  INVALID DOCUMENT', text_color='#d70015')

    def _reset_btn(self):
        self._is_processing = False
        self.verify_btn.configure(state='normal', text='✅  Verify Document')
        self.progress_bar.stop()
        self.progress_bar.pack_forget()
