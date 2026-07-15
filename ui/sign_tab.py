import os
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path
from tkinter import filedialog
from typing import Callable, Optional

import customtkinter as ctk
from pypdf import PdfReader
from core.hasher import hash_pdf_content
from core.signer import generate_keypair, load_private_key, save_private_key, save_public_key, sign_hash
from core.qr_manager import create_qr_payload, generate_qr_image
from utils.pdf_embedder import embed_qr_to_pdf
from core.input_validator import validate_file_path, validate_signer_name, ALLOWED_PDF_EXTENSIONS, ALLOWED_KEY_EXTENSIONS
from core.security_logger import log_sign_event


# ─── Reusable field row builder ───────────────────────────────────────────────
def _section_label(parent, text):
    ctk.CTkLabel(
        parent, text=text,
        font=ctk.CTkFont(family='SF Pro Display', size=11, weight='bold'),
        text_color='#8e8e93', anchor='w',
    ).pack(fill='x', padx=0, pady=(12, 3))


def _input_row(parent, label_text, right_widget=None):
    """Returns a frame with a label on the left and optional widget on right."""
    row = ctk.CTkFrame(parent, fg_color='#f5f5f7', corner_radius=12,
                       border_width=1, border_color='#e5e5ea', height=52)
    row.pack(fill='x', pady=(0, 8))
    row.pack_propagate(False)
    row.grid_columnconfigure(0, weight=1)

    lbl = ctk.CTkLabel(row, text=label_text,
                        font=ctk.CTkFont(family='SF Pro Display', size=12),
                        text_color='#6e6e73', anchor='w')
    lbl.grid(row=0, column=0, sticky='w', padx=14, pady=0)
    return row, lbl


class SignTab:
    """Sign tab rendered inside the right panel of app.py."""

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

    # ── show / hide API (called by app.py mode switch)
    def show(self):
        self._frame.pack(fill='both', expand=True, padx=4, pady=4)

    def hide(self):
        self._frame.pack_forget()

    # ── Build UI ────────────────────────────────────────────────────────────
    def _build_ui(self):
        f = self._frame

        # ── PDF picker ──
        _section_label(f, 'PDF DOCUMENT')
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

        # ── Key mode ──
        _section_label(f, 'PRIVATE KEY')
        key_card = ctk.CTkFrame(f, fg_color='#f5f5f7', corner_radius=14,
                                 border_width=1, border_color='#e5e5ea')
        key_card.pack(fill='x', pady=(0, 4))
        key_card.grid_columnconfigure(0, weight=1)

        self.key_mode = ctk.StringVar(value='generate')
        key_top = ctk.CTkFrame(key_card, fg_color='transparent')
        key_top.grid(row=0, column=0, columnspan=2, sticky='ew', padx=14, pady=(10, 4))

        ctk.CTkRadioButton(
            key_top, text='Generate new keypair',
            variable=self.key_mode, value='generate',
            font=ctk.CTkFont(family='SF Pro Display', size=12),
            fg_color='#007aff', hover_color='#0066d6',
            command=self._on_key_mode_change,
        ).pack(anchor='w')

        ctk.CTkRadioButton(
            key_top, text='Load existing private key',
            variable=self.key_mode, value='load',
            font=ctk.CTkFont(family='SF Pro Display', size=12),
            fg_color='#007aff', hover_color='#0066d6',
            command=self._on_key_mode_change,
        ).pack(anchor='w', pady=(6, 0))

        # Key file selector (shows only in load mode)
        self.key_load_frame = ctk.CTkFrame(key_card, fg_color='transparent')
        self.key_load_frame.grid(row=1, column=0, columnspan=2, sticky='ew', padx=14, pady=(6, 0))
        self.key_load_frame.grid_columnconfigure(0, weight=1)
        self.key_path_label = ctk.CTkLabel(
            self.key_load_frame, text='No key selected',
            font=ctk.CTkFont(family='SF Pro Display', size=11),
            text_color='#8e8e93', anchor='w',
        )
        self.key_path_label.grid(row=0, column=0, sticky='ew')
        self.key_browse_btn = ctk.CTkButton(
            self.key_load_frame, text='Browse Key', width=88, height=28,
            font=ctk.CTkFont(family='SF Pro Display', size=11),
            fg_color='#ffffff', hover_color='#e5e5ea',
            text_color='#6e6e73', corner_radius=8, state='disabled',
            command=self._browse_key,
        )
        self.key_browse_btn.grid(row=0, column=1, padx=(8, 0))

        # Password
        pw_row = ctk.CTkFrame(key_card, fg_color='transparent')
        pw_row.grid(row=2, column=0, columnspan=2, sticky='ew', padx=14, pady=(8, 12))
        pw_row.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(pw_row, text='Password:',
                     font=ctk.CTkFont(family='SF Pro Display', size=12),
                     text_color='#6e6e73').grid(row=0, column=0, sticky='w', padx=(0, 8))
        self.password_entry = ctk.CTkEntry(
            pw_row, placeholder_text='Required for new private keys',
            show='•', height=32, corner_radius=8,
            fg_color='#ffffff', border_color='#d2d2d7',
            text_color='#1d1d1f',
            font=ctk.CTkFont(family='SF Pro Display', size=12),
        )
        self.password_entry.grid(row=0, column=1, sticky='ew')

        # ── Signer name ──
        _section_label(f, 'SIGNER NAME')
        self.signer_entry = ctk.CTkEntry(
            f, placeholder_text='Enter full name of signer',
            height=48, corner_radius=12,
            fg_color='#f5f5f7', border_color='#d2d2d7',
            text_color='#1d1d1f',
            font=ctk.CTkFont(family='SF Pro Display', size=14),
        )
        self.signer_entry.pack(fill='x', pady=(0, 4))

        # ── QR position ──
        _section_label(f, 'QR CODE POSITION')
        self.qr_position = ctk.CTkOptionMenu(
            f, values=['bottom-right', 'bottom-left', 'top-right', 'top-left'],
            height=42, corner_radius=12,
            fg_color='#f5f5f7', button_color='#ffffff',
            button_hover_color='#e5e5ea',
            text_color='#1d1d1f',
            dropdown_fg_color='#ffffff',
            dropdown_hover_color='#f2f2f7',
            font=ctk.CTkFont(family='SF Pro Display', size=13),
        )
        self.qr_position.set('bottom-right')
        self.qr_position.pack(fill='x', pady=(0, 16))

        # ── Progress bar ──
        self.progress_bar = ctk.CTkProgressBar(
            f, mode='indeterminate', height=3,
            progress_color='#007aff', fg_color='#e5e5ea',
        )
        self.progress_bar.pack(fill='x', pady=(0, 8))
        self.progress_bar.pack_forget()

        # ── Sign button ──
        self.sign_btn = ctk.CTkButton(
            f, text='🔏  Sign Document',
            height=52, corner_radius=14,
            fg_color='#007aff', hover_color='#0066d6',
            text_color='#ffffff',
            font=ctk.CTkFont(family='SF Pro Display', size=15, weight='bold'),
            command=self._on_sign_click,
        )
        self.sign_btn.pack(fill='x', pady=(0, 4))

    # ── Helpers ─────────────────────────────────────────────────────────────
    def _browse_pdf(self):
        fp = filedialog.askopenfilename(
            title='Select PDF', filetypes=[('PDF files', '*.pdf')])
        if fp:
            # VUL-003 Mitigation: validate path before accepting
            is_valid, err = validate_file_path(fp, allowed_extensions=ALLOWED_PDF_EXTENSIONS)
            if not is_valid:
                self.status_callback(f'❌ File tidak valid: {err}')
                return
            self._pdf_path = fp
            self.pdf_path_label.configure(
                text=Path(fp).name, text_color='#1d1d1f')
            self.status_callback(f'PDF: {Path(fp).name}')

    def _browse_key(self):
        fp = filedialog.askopenfilename(
            title='Select Private Key', filetypes=[('PEM files', '*.pem')])
        if fp:
            # VUL-003 Mitigation: validate key file path
            is_valid, err = validate_file_path(fp, allowed_extensions=ALLOWED_KEY_EXTENSIONS)
            if not is_valid:
                self.status_callback(f'❌ File key tidak valid: {err}')
                return
            self._key_path = fp
            self.key_path_label.configure(
                text=Path(fp).name, text_color='#1d1d1f')

    def _on_key_mode_change(self):
        is_load = self.key_mode.get() == 'load'
        self.key_browse_btn.configure(state='normal' if is_load else 'disabled')
        if not is_load:
            self._key_path = None
            self.key_path_label.configure(text='No key selected', text_color='#8e8e93')

    # ── Sign action ─────────────────────────────────────────────────────────
    def _on_sign_click(self):
        if self._is_processing:
            return
        if not self._pdf_path:
            self.status_callback('❌ Pilih file PDF terlebih dahulu')
            return

        # VUL-006 Mitigation: validate signer name length and characters
        signer_raw = self.signer_entry.get().strip()
        name_valid, name_err = validate_signer_name(signer_raw)
        if not name_valid:
            self.status_callback(f'❌ Nama penandatangan tidak valid: {name_err}')
            return

        if self.key_mode.get() == 'load' and not self._key_path:
            self.status_callback('❌ Pilih file private key')
            return
        if self.key_mode.get() == 'generate' and not self.password_entry.get().strip():
            self.status_callback('❌ Masukkan password untuk mengenkripsi private key baru')
            return

        self._is_processing = True
        self.sign_btn.configure(state='disabled', text='⏳  Signing...')
        self.progress_bar.pack(fill='x', pady=(0, 8))
        self.progress_bar.start()
        self.status_callback('⏳  Signing document...')

        threading.Thread(
            target=self._perform_signing,
            args=(self._pdf_path, signer_raw),
            daemon=True,
        ).start()

    def _perform_signing(self, pdf_path: str, signer_name: str):
        try:
            lines = [
                '═' * 44,
                '  CertiGuard — Signing Report',
                '═' * 44, '',
            ]
            lines.append('[1/5] Hashing PDF visual content (SHA-256)...')
            doc_hash, t1 = hash_pdf_content(pdf_path)
            signed_page_count = len(PdfReader(pdf_path).pages)
            lines.append(f'  Hash: {doc_hash[:24]}...')
            lines.append(f'  Pages signed: {signed_page_count}')
            lines.append(f'  Time: {t1:.2f} ms')
            lines.append('')

            password = self.password_entry.get().strip() or None
            pdf_dir = str(Path(pdf_path).parent)
            stem = Path(pdf_path).stem

            if self.key_mode.get() == 'generate':
                lines.append('[2/5] Generating keypair...')
                priv, pub = generate_keypair(2048)
                priv_path = os.path.join(pdf_dir, f'{stem}_private.pem')
                pub_path = os.path.join(pdf_dir, f'{stem}_public.pem')
                save_private_key(priv, priv_path, password)
                save_public_key(pub, pub_path)
                lines.append(f'  Private: {Path(priv_path).name}')
                lines.append(f'  Public:  {Path(pub_path).name}')
            else:
                lines.append('[2/5] Loading private key...')
                priv = load_private_key(self._key_path, password)
                pub = priv.public_key()
                pub_path = os.path.join(pdf_dir, f'{stem}_public.pem')
                save_public_key(pub, pub_path)
                lines.append(f'  Loaded: {Path(self._key_path).name}')

            lines.append('')
            lines.append('[3/5] Signing hash ...')
            sig, t3 = sign_hash(priv, doc_hash)
            import base64
            lines.append(f'  Sig: {base64.b64encode(sig).decode()[:24]}...')
            lines.append(f'  Time: {t3:.2f} ms')
            lines.append('')

            lines.append('[4/5] Generating QR Code...')
            ts = datetime.now(timezone.utc).isoformat()
            payload = create_qr_payload(doc_hash, sig, signer_name, ts, signed_page_count)
            qr_tmp = os.path.join(tempfile.gettempdir(), f'cg_qr_{stem}.png')
            generate_qr_image(payload, qr_tmp)
            lines.append(f'  Payload: {len(payload)} chars')
            lines.append('')

            lines.append('[5/5] Appending signature QR page...')
            pos = self.qr_position.get()
            out_pdf = os.path.join(pdf_dir, f'{stem}_signed.pdf')
            embed_qr_to_pdf(pdf_path, qr_tmp, out_pdf, pos)
            lines.append(f'  Position: {pos}')
            lines.append(f'  Output: {Path(out_pdf).name}')
            lines.append('')
            lines.append('─' * 44)
            lines.append(f'✅  SIGNING COMPLETE')
            lines.append(f'  Signed PDF: {Path(out_pdf).name}')
            lines.append('─' * 44)

            # VUL-005 Mitigation: audit log the sign event
            log_sign_event(
                username=self.current_user,
                doc_name=Path(pdf_path).name,
                hash_prefix=doc_hash[:16],
                success=True,
            )

            try:
                os.remove(qr_tmp)
            except OSError:
                pass

            self._frame.after(0, lambda: self.status_callback(
                f'✅ Signed → {Path(out_pdf).name}'))
            self._frame.after(0, lambda: self._pipe_log('\n'.join(lines)))

        except Exception as e:
            msg = f'❌ {type(e).__name__}: {e}'
            # VUL-005: audit log failure
            log_sign_event(
                username=self.current_user,
                doc_name=Path(pdf_path).name if pdf_path else 'unknown',
                hash_prefix='N/A',
                success=False,
            )
            self._frame.after(0, lambda: self.status_callback(msg))
        finally:
            self._frame.after(0, self._reset_btn)

    def _pipe_log(self, text: str):
        """Send full report text to status callback so app.py can show it in the log panel."""
        self.status_callback(f'\n{text}')

    def _reset_btn(self):
        self._is_processing = False
        self.sign_btn.configure(state='normal', text='🔏  Sign Document')
        self.progress_bar.stop()
        self.progress_bar.pack_forget()
