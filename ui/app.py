"""
app.py — CertiGuard Main Application (SSDLC Hardened)
======================================================
Microsoft SDL Phase 5 (Verification) & Phase 7 (Response).

Security additions:
  VUL-005 MITIGATED: Passes logged-in username to sign/verify tabs for audit trail
"""

import customtkinter as ctk
from ui.sign_tab import SignTab
from ui.verify_tab import VerifyTab
from ui.login import LoginFrame


class CertiGuardApp(ctk.CTk):
    APP_TITLE   = 'CertiGuard — Document Authentication System'
    APP_WIDTH   = 1100
    APP_HEIGHT  = 720
    APP_VERSION = 'v1.1.0'   # SSDLC security hardening release

    def __init__(self) -> None:
        super().__init__()
        self.title(self.APP_TITLE)
        self.geometry(f'{self.APP_WIDTH}x{self.APP_HEIGHT}')
        self.minsize(900, 620)
        self.configure(fg_color='#f5f5f7')

        self._logged_in_user: str = 'unknown'

        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        self.login_frame = LoginFrame(self, self._show_main_app)
        self.login_frame.grid(row=0, column=0, sticky='nsew')

    def _show_main_app(self, username: str = 'unknown'):
        """Called by LoginFrame after successful authentication."""
        self._logged_in_user = username

        if hasattr(self, 'login_frame'):
            self.login_frame.destroy()

        # Main layout: top nav bar + content area + bottom status bar
        self.grid_rowconfigure(0, weight=0)   # top nav
        self.grid_rowconfigure(1, weight=1)   # main content
        self.grid_rowconfigure(2, weight=0)   # status bar
        self.grid_columnconfigure(0, weight=1)

        self._create_navbar()
        self._create_main_content()
        self._create_status_bar()

    # ─────────────────────────── TOP NAV ───────────────────────────
    def _create_navbar(self) -> None:
        nav = ctk.CTkFrame(self, fg_color='#fbfbfd', corner_radius=0, height=64)
        nav.grid(row=0, column=0, sticky='ew')
        nav.grid_propagate(False)
        nav.grid_columnconfigure(1, weight=1)

        # Logo area
        logo_frame = ctk.CTkFrame(nav, fg_color='transparent')
        logo_frame.grid(row=0, column=0, sticky='w', padx=30, pady=12)
        ctk.CTkLabel(logo_frame, text='🛡️',
                     font=ctk.CTkFont(size=28)).pack(side='left', padx=(0, 8))
        ctk.CTkLabel(logo_frame, text='CertiGuard',
                     font=ctk.CTkFont(family='SF Pro Display', size=20, weight='bold'),
                     text_color='#1d1d1f').pack(side='left')

        # Nav right: user indicator + SDL badge + version
        right = ctk.CTkFrame(nav, fg_color='transparent')
        right.grid(row=0, column=2, sticky='e', padx=30)

        # Version pill
        v_pill = ctk.CTkFrame(right, fg_color='#f2f2f7', corner_radius=20,
                               border_width=1, border_color='#d2d2d7')
        v_pill.pack(side='right', padx=(6, 0))
        ctk.CTkLabel(v_pill, text=self.APP_VERSION,
                     font=ctk.CTkFont(family='SF Pro Display', size=12),
                     text_color='#007aff').pack(padx=14, pady=6)

        # SDL security badge
        sdl_pill = ctk.CTkFrame(right, fg_color='#eef4ff', corner_radius=20,
                                 border_width=1, border_color='#bdd4ff')
        sdl_pill.pack(side='right', padx=(6, 0))
        ctk.CTkLabel(sdl_pill, text='🔐 SDL Secured',
                     font=ctk.CTkFont(family='SF Pro Display', size=12),
                     text_color='#0055d4').pack(padx=14, pady=6)

        # Logged-in user indicator
        user_pill = ctk.CTkFrame(right, fg_color='#f9f0ff', corner_radius=20,
                                  border_width=1, border_color='#d4b0ff')
        user_pill.pack(side='right', padx=(0, 0))
        ctk.CTkLabel(user_pill, text=f'👤 {self._logged_in_user}',
                     font=ctk.CTkFont(family='SF Pro Display', size=12),
                     text_color='#5e1fa3').pack(padx=14, pady=6)

        # Separator line
        ctk.CTkFrame(self, fg_color='#d2d2d7', corner_radius=0, height=1
                     ).grid(row=0, column=0, sticky='sew')

    # ─────────────────────────── MAIN CONTENT ───────────────────────────
    def _create_main_content(self) -> None:
        content = ctk.CTkFrame(self, fg_color='transparent')
        content.grid(row=1, column=0, sticky='nsew', padx=0, pady=0)
        content.grid_columnconfigure(0, weight=5)   # left info panel
        content.grid_columnconfigure(1, weight=4)   # right interaction panel
        content.grid_rowconfigure(0, weight=1)

        self._create_left_panel(content)
        self._create_right_panel(content)

    def _create_left_panel(self, parent) -> None:
        """Left: hero heading + metric cards + result console"""
        left = ctk.CTkFrame(parent, fg_color='transparent')
        left.grid(row=0, column=0, sticky='nsew', padx=(36, 16), pady=30)
        left.grid_rowconfigure(3, weight=1)
        left.grid_columnconfigure(0, weight=1)

        # ── Hero heading
        ctk.CTkLabel(
            left,
            text='Document\nAuthentication\nSystem',
            font=ctk.CTkFont(family='SF Pro Display', size=42, weight='bold'),
            text_color='#1d1d1f',
            justify='left',
            anchor='w',
        ).grid(row=0, column=0, sticky='w', pady=(0, 12))

        ctk.CTkLabel(
            left,
            text='Sign & verify PDFs with digital signatures.\nQR codes embedded automatically.',
            font=ctk.CTkFont(family='SF Pro Display', size=14),
            text_color='#6e6e73',
            justify='left',
            anchor='w',
        ).grid(row=1, column=0, sticky='w', pady=(0, 28))

        # ── Metric cards row
        cards_row = ctk.CTkFrame(left, fg_color='transparent')
        cards_row.grid(row=2, column=0, sticky='w', pady=(0, 24))

        metrics = [
            ('Asymmetric', 'Encryption', '#007aff'),
            ('Secure',  'Hash Algo',  '#5e5ce6'),
            ('QR',   'Embedded',   '#34c759'),
        ]
        for i, (val, lbl, color) in enumerate(metrics):
            c = ctk.CTkFrame(cards_row, fg_color='#ffffff', corner_radius=16,
                             border_width=1, border_color='#e5e5ea',
                             width=136, height=80)
            c.grid(row=0, column=i, padx=(0, 12))
            c.grid_propagate(False)
            ctk.CTkLabel(c, text=val,
                         font=ctk.CTkFont(family='SF Pro Display', size=17, weight='bold'),
                         text_color=color).place(relx=0.5, rely=0.37, anchor='center')
            ctk.CTkLabel(c, text=lbl,
                         font=ctk.CTkFont(family='SF Pro Display', size=11),
                         text_color='#8e8e93').place(relx=0.5, rely=0.73, anchor='center')

        # ── Results / log console (bottom of left panel)
        log_header = ctk.CTkFrame(left, fg_color='transparent')
        log_header.grid(row=3, column=0, sticky='new')
        ctk.CTkLabel(log_header, text='●  Operation Log',
                     font=ctk.CTkFont(family='SF Pro Display', size=13, weight='bold'),
                     text_color='#007aff').pack(side='left', pady=(0, 8))

        log_outer = ctk.CTkFrame(left, fg_color='#ffffff', corner_radius=16,
                                  border_width=1, border_color='#e5e5ea')
        log_outer.grid(row=4, column=0, sticky='nsew')
        left.grid_rowconfigure(4, weight=1)

        self.result_textbox = ctk.CTkTextbox(
            log_outer,
            font=ctk.CTkFont(family='Consolas', size=12),
            fg_color='transparent',
            text_color='#1d1d1f',
            state='disabled',
            wrap='word',
        )
        self.result_textbox.pack(fill='both', expand=True, padx=4, pady=4)

    def _create_right_panel(self, parent) -> None:
        """Right: Sign/Verify panel card"""
        right_outer = ctk.CTkFrame(parent, fg_color='transparent')
        right_outer.grid(row=0, column=1, sticky='nsew', padx=(16, 36), pady=30)
        right_outer.grid_rowconfigure(0, weight=1)
        right_outer.grid_columnconfigure(0, weight=1)

        # Main card container
        card = ctk.CTkFrame(right_outer, fg_color='#ffffff', corner_radius=22,
                             border_width=1, border_color='#e5e5ea')
        card.grid(row=0, column=0, sticky='nsew')
        card.grid_columnconfigure(0, weight=1)
        card.grid_rowconfigure(2, weight=1)

        # Top accent line
        ctk.CTkFrame(card, fg_color='#007aff', height=3, corner_radius=0
                     ).grid(row=0, column=0, sticky='ew')

        # ── Segmented switch (Sign / Verify)
        switch_frame = ctk.CTkFrame(card, fg_color='transparent')
        switch_frame.grid(row=1, column=0, padx=24, pady=(20, 10), sticky='ew')
        switch_frame.grid_columnconfigure(0, weight=1)

        self.mode_switch = ctk.CTkSegmentedButton(
            switch_frame,
            values=['  🔏  Sign  ', '  ✅  Verify  '],
            command=self._on_mode_change,
            font=ctk.CTkFont(family='SF Pro Display', size=13, weight='bold'),
            fg_color='#f2f2f7',
            selected_color='#ffffff',
            selected_hover_color='#ffffff',
            unselected_color='#f2f2f7',
            unselected_hover_color='#e5e5ea',
            text_color='#1d1d1f',
            corner_radius=12,
            height=42,
        )
        self.mode_switch.set('  🔏  Sign  ')
        self.mode_switch.grid(row=0, column=0, sticky='ew')

        # ── Content area (changes based on switch)
        self.panel_content = ctk.CTkScrollableFrame(
            card, fg_color='transparent',
            scrollbar_button_color='#d2d2d7',
            scrollbar_button_hover_color='#c7c7cc',
        )
        self.panel_content.grid(row=2, column=0, sticky='nsew', padx=8, pady=(0, 8))
        self.panel_content.grid_columnconfigure(0, weight=1)

        # Build sign/verify tabs — set current user for audit logging (VUL-005)
        self.sign_tab = SignTab(self.panel_content, self._update_status)
        self.sign_tab.current_user = self._logged_in_user

        self.verify_tab = VerifyTab(self.panel_content, self._update_status)
        self.verify_tab.current_user = self._logged_in_user

        self.verify_tab.hide()
        self.sign_tab.show()

    def _on_mode_change(self, value):
        if 'Sign' in value:
            self.verify_tab.hide()
            self.sign_tab.show()
        else:
            self.sign_tab.hide()
            self.verify_tab.show()

    # ─────────────────────────── STATUS BAR ───────────────────────────
    def _create_status_bar(self) -> None:
        bar = ctk.CTkFrame(self, fg_color='#fbfbfd', corner_radius=0, height=40)
        bar.grid(row=2, column=0, sticky='ew')
        bar.grid_propagate(False)

        ctk.CTkFrame(self, fg_color='#d2d2d7', corner_radius=0, height=1
                     ).grid(row=2, column=0, sticky='new')

        self.status_label = ctk.CTkLabel(
            bar, text='Ready — Select a document to begin',
            font=ctk.CTkFont(family='SF Pro Display', size=12),
            text_color='#6e6e73', anchor='w',
        )
        self.status_label.pack(side='left', padx=30, pady=10)

        # Dot indicator
        self.dot_label = ctk.CTkLabel(bar, text='●',
                                       font=ctk.CTkFont(size=10),
                                       text_color='#8e8e93')
        self.dot_label.pack(side='right', padx=(0, 30), pady=10)

    def _update_status(self, message: str) -> None:
        # Multi-line messages → only go to the log panel, not the status bar
        is_report = '\n' in message or '═' in message or '─' in message

        if not is_report:
            short = message[:90] + '...' if len(message) > 90 else message
            self.status_label.configure(text=short)
            color = '#34c759' if '✅' in message else ('#ff3b30' if '❌' in message else '#007aff')
            self.dot_label.configure(text_color=color)

        # All messages go to the log textbox
        if hasattr(self, 'result_textbox'):
            self.result_textbox.configure(state='normal')
            self.result_textbox.insert('end', f'{message}\n')
            self.result_textbox.see('end')
            self.result_textbox.configure(state='disabled')

        self.update_idletasks()
