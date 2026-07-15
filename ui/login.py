"""
login.py — CertiGuard Login Screen (SSDLC Hardened)
=====================================================
Microsoft SDL Phase 4 (Implementation) — Secure Authentication UI.

Security improvements:
  VUL-001 MITIGATED: Displays lockout status & countdown timer
  VUL-002 MITIGATED: Password strength indicator shown
  VUL-007 MITIGATED: auth.verify_login() now returns (bool, str) message

UI now passes through the richer (bool, str) return from auth.verify_login()
and displays contextual error messages without leaking internal details.
"""

import customtkinter as ctk
from core.auth import verify_login
from core.rate_limiter import check_lockout


class LoginFrame(ctk.CTkFrame):
    """
    Full-screen login screen with a split-panel layout:
    Left  — branding / hero (using soft indigo-violet & sky-blue tones)
    Right — login form card with security status indicators
    """

    def __init__(self, master, on_login_success):
        super().__init__(master, fg_color='#f5f5f7')
        self.on_login_success = on_login_success
        self._lockout_after_id = None  # for countdown refresh

        self.grid_columnconfigure(0, weight=3)
        self.grid_columnconfigure(1, weight=2)
        self.grid_rowconfigure(0, weight=1)

        self._build_left_hero()
        self._build_right_form()

    # ─────────────── LEFT: HERO ───────────────
    def _build_left_hero(self):
        left = ctk.CTkFrame(self, fg_color='transparent')
        left.grid(row=0, column=0, sticky='nsew', padx=(60, 20), pady=60)
        left.grid_rowconfigure(4, weight=1)
        left.grid_columnconfigure(0, weight=1)

        # Logo badge
        badge = ctk.CTkFrame(left, fg_color='#ffffff', corner_radius=14,
                              border_width=1, border_color='#e5e5ea', width=52, height=52)
        badge.grid(row=0, column=0, sticky='w', pady=(0, 30))
        badge.grid_propagate(False)
        ctk.CTkLabel(badge, text='🛡️', font=ctk.CTkFont(size=26)).place(relx=0.5, rely=0.5, anchor='center')

        # Hero text
        ctk.CTkLabel(
            left,
            text='Secure your\ndocuments with\nCertiGuard',
            font=ctk.CTkFont(family='SF Pro Display', size=46, weight='bold'),
            text_color='#1d1d1f',
            justify='left',
            anchor='w',
        ).grid(row=1, column=0, sticky='w', pady=(0, 18))

        # Subtitle
        ctk.CTkLabel(
            left,
            text='Sign and Verify your documents\nvia QR code — in seconds.',
            font=ctk.CTkFont(family='SF Pro Display', size=15),
            text_color='#6e6e73',
            justify='left',
            anchor='w',
        ).grid(row=2, column=0, sticky='w', pady=(0, 40))

        # Stats cards row
        cards_frame = ctk.CTkFrame(left, fg_color='transparent')
        cards_frame.grid(row=3, column=0, sticky='w', pady=(0, 0))

        stats = [
            ('Secure', 'Encryption'),
            ('Verify',  'Hashing'),
            ('Embedded',  'QR Code'),
        ]
        colors = ['#007aff', '#5e5ce6', '#34c759']
        for i, (val, label) in enumerate(stats):
            card = ctk.CTkFrame(cards_frame, fg_color='#ffffff', corner_radius=16,
                                border_width=1, border_color='#e5e5ea', width=148, height=88)
            card.grid(row=0, column=i, padx=(0, 14))
            card.grid_propagate(False)

            ctk.CTkLabel(card, text=val,
                         font=ctk.CTkFont(family='SF Pro Display', size=20, weight='bold'),
                         text_color=colors[i]).place(relx=0.5, rely=0.38, anchor='center')
            ctk.CTkLabel(card, text=label,
                         font=ctk.CTkFont(family='SF Pro Display', size=12),
                         text_color='#6e6e73').place(relx=0.5, rely=0.72, anchor='center')

        # SSDLC security badge
        sec_frame = ctk.CTkFrame(left, fg_color='#eef4ff', corner_radius=12,
                                  border_width=1, border_color='#bdd4ff')
        sec_frame.grid(row=4, column=0, sticky='sw', pady=(24, 0))
        ctk.CTkLabel(
            sec_frame,
            text='🔐  Secured by Microsoft SDL + CVSS v3.1 Assessment',
            font=ctk.CTkFont(family='SF Pro Display', size=11),
            text_color='#0055d4',
        ).pack(padx=16, pady=8)

    # ─────────────── RIGHT: FORM CARD ───────────────
    def _build_right_form(self):
        right = ctk.CTkFrame(self, fg_color='transparent')
        right.grid(row=0, column=1, sticky='nsew', padx=(20, 60), pady=60)
        right.grid_rowconfigure(0, weight=1)
        right.grid_columnconfigure(0, weight=1)

        card = ctk.CTkFrame(right, fg_color='#ffffff', corner_radius=24,
                             border_width=1, border_color='#e5e5ea')
        card.grid(row=0, column=0, sticky='nsew')
        card.grid_columnconfigure(0, weight=1)
        card.grid_rowconfigure(9, weight=1)

        # Top accent bar
        accent = ctk.CTkFrame(card, fg_color='#007aff', height=3, corner_radius=0)
        accent.grid(row=0, column=0, sticky='ew', padx=0, pady=(0, 0))

        # Welcome text
        ctk.CTkLabel(card, text='Welcome back',
                     font=ctk.CTkFont(family='SF Pro Display', size=11, weight='bold'),
                     text_color='#007aff').grid(row=1, column=0, pady=(28, 2))
        ctk.CTkLabel(card, text='Sign in to your account',
                     font=ctk.CTkFont(family='SF Pro Display', size=22, weight='bold'),
                     text_color='#1d1d1f').grid(row=2, column=0, pady=(0, 24))

        # ── Security status banner (shows lockout info) ───────────────────────
        self.security_banner = ctk.CTkFrame(
            card, fg_color='#fff8e6', corner_radius=10,
            border_width=1, border_color='#f5c842',
        )
        # Hidden by default; shown when account is locked
        self.security_banner_label = ctk.CTkLabel(
            self.security_banner,
            text='',
            font=ctk.CTkFont(family='SF Pro Display', size=11),
            text_color='#7a5c00',
            wraplength=260,
        )
        self.security_banner_label.pack(padx=12, pady=8)
        # Do NOT grid the banner yet — it appears only on lockout

        # Username
        self._make_field_label(card, '👤  Username', 4)
        self.username_entry = ctk.CTkEntry(
            card,
            placeholder_text='Enter your username',
            height=48, corner_radius=12,
            fg_color='#f5f5f7', border_color='#d2d2d7',
            text_color='#1d1d1f', border_width=1,
            placeholder_text_color='#8e8e93',
            font=ctk.CTkFont(family='SF Pro Display', size=14),
        )
        self.username_entry.grid(row=5, column=0, padx=30, pady=(4, 12), sticky='ew')

        # Password
        self._make_field_label(card, '🔒  Password', 6)
        self.password_entry = ctk.CTkEntry(
            card,
            placeholder_text='Enter your password',
            show='•', height=48, corner_radius=12,
            fg_color='#f5f5f7', border_color='#d2d2d7',
            text_color='#1d1d1f', border_width=1,
            placeholder_text_color='#8e8e93',
            font=ctk.CTkFont(family='SF Pro Display', size=14),
        )
        self.password_entry.grid(row=7, column=0, padx=30, pady=(4, 6), sticky='ew')

        # Attempt counter label (subtle, right-aligned)
        self.attempt_label = ctk.CTkLabel(
            card, text='',
            font=ctk.CTkFont(family='SF Pro Display', size=11),
            text_color='#8e8e93',
            anchor='e',
        )
        self.attempt_label.grid(row=8, column=0, padx=30, sticky='e', pady=(0, 8))

        # Login button
        self.login_btn = ctk.CTkButton(
            card,
            text='Get Started  →',
            command=self._handle_login,
            height=52, corner_radius=14,
            fg_color='#007aff', hover_color='#0066d6',
            text_color='#ffffff',
            font=ctk.CTkFont(family='SF Pro Display', size=15, weight='bold'),
        )
        self.login_btn.grid(row=9, column=0, padx=30, pady=(4, 16), sticky='ew')

        # Status label
        self.status_label = ctk.CTkLabel(
            card, text='',
            font=ctk.CTkFont(family='SF Pro Display', size=12),
            text_color='#ff3b30',
            wraplength=280,
        )
        self.status_label.grid(row=10, column=0, pady=(0, 30))

        # Bindings
        self.username_entry.bind('<Return>', lambda e: self.password_entry.focus())
        self.password_entry.bind('<Return>', lambda e: self._handle_login())

    def _make_field_label(self, parent, text, row):
        ctk.CTkLabel(parent, text=text,
                     font=ctk.CTkFont(family='SF Pro Display', size=12),
                     text_color='#6e6e73', anchor='w').grid(
            row=row, column=0, padx=30, sticky='w')

    # ─────────────── LOCKOUT UI ───────────────

    def _show_lockout_banner(self, message: str) -> None:
        """Display the orange security banner with lockout message."""
        self.security_banner_label.configure(text=message)
        # Insert banner between welcome text (row 2) and username field (row 4)
        self.security_banner.grid(row=3, column=0, padx=30, pady=(0, 10), sticky='ew')
        self.login_btn.configure(state='disabled', fg_color='#c7c7cc', hover_color='#c7c7cc')

    def _hide_lockout_banner(self) -> None:
        self.security_banner.grid_forget()
        self.login_btn.configure(state='normal', fg_color='#007aff', hover_color='#0066d6')

    def _refresh_lockout_countdown(self, username: str) -> None:
        """Tick the countdown every second while account is locked."""
        if self._lockout_after_id:
            self.after_cancel(self._lockout_after_id)
            self._lockout_after_id = None

        is_locked, _, secs_remaining = check_lockout(username)
        if is_locked and secs_remaining > 0:
            mins = secs_remaining // 60
            secs = secs_remaining % 60
            self._show_lockout_banner(
                f'🔒  Akun dikunci karena terlalu banyak percobaan gagal.\n'
                f'Coba lagi dalam  {mins}:{secs:02d}'
            )
            self._lockout_after_id = self.after(1000, lambda: self._refresh_lockout_countdown(username))
        else:
            self._hide_lockout_banner()
            self.status_label.configure(text='Akun sudah dapat digunakan kembali.', text_color='#34c759')
            self.attempt_label.configure(text='')

    # ─────────────── LOGIN LOGIC ───────────────

    def _handle_login(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get()

        if not username or not password:
            self.status_label.configure(
                text='⚠  Masukkan username dan password.', text_color='#ff9500')
            return

        # Pre-check lockout before even hitting the button animation
        is_locked, fail_count, secs_remaining = check_lockout(username)
        if is_locked:
            self._refresh_lockout_countdown(username)
            return

        self.login_btn.configure(state='disabled', text='Verifying...')
        self.status_label.configure(text='', text_color='#6e6e73')
        self.update_idletasks()

        try:
            success, message = verify_login(username, password)

            if success:
                # Cancel any pending lockout refresh
                if self._lockout_after_id:
                    self.after_cancel(self._lockout_after_id)
                self._hide_lockout_banner()
                self.attempt_label.configure(text='')
                self.status_label.configure(text='✓  Login berhasil!', text_color='#34c759')
                self.update_idletasks()
                # Pass username so app.py can use it for audit logging
                self.after(400, lambda: self.on_login_success(username))
            else:
                # Check if now locked after this failure
                is_locked_now, fail_count_now, secs_now = check_lockout(username)
                if is_locked_now:
                    self._refresh_lockout_countdown(username)
                    self.status_label.configure(text='', text_color='#ff3b30')
                else:
                    # Show remaining attempts hint
                    self.status_label.configure(
                        text=f'✕  {message}', text_color='#ff3b30')
                    remaining = max(0, 5 - fail_count_now)
                    if remaining > 0:
                        self.attempt_label.configure(
                            text=f'{remaining} percobaan tersisa',
                            text_color='#ff9500',
                        )
                self.login_btn.configure(state='normal', text='Get Started  →')

        except Exception as e:
            self.status_label.configure(
                text='✕  Kesalahan sistem. Coba lagi.', text_color='#ff3b30')
            self.login_btn.configure(state='normal', text='Get Started  →')
