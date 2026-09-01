from __future__ import annotations

import os
import platform
import queue
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Callable

import secrets
import string

from crypto_utils import AuthenticationError, SecureFileError, decrypt_file, encrypt_file

APP_NAME = "Secure File Encryptor"
APP_VERSION = "2.0.0 RC1"
MIN_ENCRYPT_PASSWORD_LENGTH = 12

# A calm, security-oriented palette. The app intentionally stays light so it
# renders consistently on Windows and macOS without third-party UI packages.
COLORS = {
    "bg": "#F4F7FB",
    "surface": "#FFFFFF",
    "surface_alt": "#F8FAFC",
    "text": "#172033",
    "muted": "#64748B",
    "border": "#DCE3EC",
    "primary": "#2563EB",
    "primary_hover": "#1D4ED8",
    "primary_soft": "#EAF1FF",
    "success": "#059669",
    "success_soft": "#EAF8F3",
    "danger": "#DC2626",
    "danger_soft": "#FEF2F2",
    "warning": "#B45309",
}


def resource_path(relative: str) -> Path:
    """Resolve bundled assets when running from source or a PyInstaller build."""
    base = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
    return base / relative


def preferred_font() -> str:
    system = platform.system()
    if system == "Windows":
        return "Segoe UI"
    if system == "Darwin":
        return "Helvetica Neue"
    return "DejaVu Sans"


def format_bytes(size: int) -> str:
    value = float(size)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{size} B"


class SecureFileEncryptorApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.font_family = preferred_font()
        self.title(f"{APP_NAME} {APP_VERSION}")
        self.geometry("900x650")
        self.minsize(820, 610)
        self.configure(bg=COLORS["bg"])

        self.encrypt_path = tk.StringVar()
        self.decrypt_path = tk.StringVar()
        self.encrypt_file_name = tk.StringVar(value="No file selected")
        self.encrypt_file_meta = tk.StringVar(value="Choose a file — large files are processed in chunks")
        self.decrypt_file_name = tk.StringVar(value="No encrypted file selected")
        self.decrypt_file_meta = tk.StringVar(value="Choose a .sfe or legacy .enc file")
        self.status_text = tk.StringVar(value="Ready")
        self.encrypt_show_password = tk.BooleanVar(value=False)
        self.decrypt_show_password = tk.BooleanVar(value=False)
        self.password_hint = tk.StringVar(value="Use at least 12 characters")
        self.password_hint_color = COLORS["muted"]
        self.current_view = "encrypt"
        self.busy = False
        self.progress_queue: queue.SimpleQueue[tuple[int, int]] = queue.SimpleQueue()
        self._progress_poll_job = None
        self._controls: list[tk.Widget] = []

        self._setup_icon()
        self._setup_ttk()
        self._setup_menu()
        self._build_ui()
        self._bind_shortcuts()

    def _setup_icon(self) -> None:
        icon = resource_path("assets/secure_file.png")
        if icon.exists():
            try:
                self._icon_image = tk.PhotoImage(file=str(icon))
                self.iconphoto(True, self._icon_image)
            except tk.TclError:
                pass

    def _setup_ttk(self) -> None:
        style = ttk.Style(self)
        # clam respects most custom style options on both Windows and macOS.
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure(
            "SFE.Horizontal.TProgressbar",
            troughcolor=COLORS["surface_alt"],
            background=COLORS["primary"],
            bordercolor=COLORS["surface_alt"],
            lightcolor=COLORS["primary"],
            darkcolor=COLORS["primary"],
            thickness=5,
        )

    def _setup_menu(self) -> None:
        menu = tk.Menu(self)
        file_menu = tk.Menu(menu, tearoff=False)
        file_menu.add_command(label="Encrypt a file", command=lambda: self.show_view("encrypt"), accelerator="Ctrl+1")
        file_menu.add_command(label="Decrypt a file", command=lambda: self.show_view("decrypt"), accelerator="Ctrl+2")
        file_menu.add_separator()
        file_menu.add_command(label="Quit", command=self.destroy)
        menu.add_cascade(label="File", menu=file_menu)

        help_menu = tk.Menu(menu, tearoff=False)
        help_menu.add_command(label="About Secure File Encryptor", command=self.show_about)
        menu.add_cascade(label="Help", menu=help_menu)
        self.config(menu=menu)

    def _bind_shortcuts(self) -> None:
        self.bind_all("<Control-Key-1>", lambda _e: self.show_view("encrypt"))
        self.bind_all("<Control-Key-2>", lambda _e: self.show_view("decrypt"))
        if platform.system() == "Darwin":
            self.bind_all("<Command-Key-1>", lambda _e: self.show_view("encrypt"))
            self.bind_all("<Command-Key-2>", lambda _e: self.show_view("decrypt"))

    def _build_ui(self) -> None:
        shell = tk.Frame(self, bg=COLORS["bg"])
        shell.pack(fill="both", expand=True, padx=34, pady=26)
        shell.grid_columnconfigure(0, weight=1)
        shell.grid_rowconfigure(2, weight=1)

        self._build_header(shell)
        self._build_nav(shell)

        self.content = tk.Frame(
            shell,
            bg=COLORS["surface"],
            highlightbackground=COLORS["border"],
            highlightthickness=1,
        )
        self.content.grid(row=2, column=0, sticky="nsew", pady=(16, 0))
        self.content.grid_columnconfigure(0, weight=1)
        self.content.grid_rowconfigure(0, weight=1)

        self.encrypt_view = tk.Frame(self.content, bg=COLORS["surface"])
        self.decrypt_view = tk.Frame(self.content, bg=COLORS["surface"])
        for view in (self.encrypt_view, self.decrypt_view):
            view.grid(row=0, column=0, sticky="nsew")
            view.grid_columnconfigure(0, weight=1)

        self._build_encrypt_view(self.encrypt_view)
        self._build_decrypt_view(self.decrypt_view)
        self._build_status(shell)
        self.show_view("encrypt")

    def _build_header(self, parent: tk.Frame) -> None:
        header = tk.Frame(parent, bg=COLORS["bg"])
        header.grid(row=0, column=0, sticky="ew")
        header.grid_columnconfigure(1, weight=1)

        icon = tk.Canvas(header, width=52, height=52, bg=COLORS["bg"], highlightthickness=0)
        icon.grid(row=0, column=0, rowspan=2, sticky="w", padx=(0, 14))
        # Shield + lock, drawn in Tk so there is no platform-specific UI dependency.
        icon.create_polygon(26, 3, 45, 10, 42, 31, 26, 48, 10, 31, 7, 10, fill=COLORS["primary"], outline="")
        icon.create_arc(18, 14, 34, 31, start=0, extent=180, style="arc", width=3, outline="white")
        icon.create_rectangle(16, 22, 36, 36, fill="white", outline="white")
        icon.create_oval(24, 26, 28, 30, fill=COLORS["primary"], outline="")
        icon.create_rectangle(25, 29, 27, 33, fill=COLORS["primary"], outline="")

        tk.Label(
            header,
            text=APP_NAME,
            font=(self.font_family, 22, "bold"),
            fg=COLORS["text"],
            bg=COLORS["bg"],
        ).grid(row=0, column=1, sticky="w")
        tk.Label(
            header,
            text="Private by design. Protect files locally — no account, upload, or cloud required.",
            font=(self.font_family, 10),
            fg=COLORS["muted"],
            bg=COLORS["bg"],
        ).grid(row=1, column=1, sticky="w", pady=(2, 0))

        version = tk.Label(
            header,
            text=f"v{APP_VERSION}",
            font=(self.font_family, 9, "bold"),
            fg=COLORS["primary"],
            bg=COLORS["primary_soft"],
            padx=10,
            pady=5,
        )
        version.grid(row=0, column=2, rowspan=2, sticky="e")

    def _build_nav(self, parent: tk.Frame) -> None:
        nav = tk.Frame(parent, bg=COLORS["bg"])
        nav.grid(row=1, column=0, sticky="w", pady=(24, 0))
        self.encrypt_nav = self._nav_button(nav, "Encrypt file", lambda: self.show_view("encrypt"))
        self.encrypt_nav.pack(side="left", padx=(0, 8))
        self.decrypt_nav = self._nav_button(nav, "Decrypt file", lambda: self.show_view("decrypt"))
        self.decrypt_nav.pack(side="left")
        self._controls.extend([self.encrypt_nav, self.decrypt_nav])

    def _nav_button(self, parent: tk.Frame, text: str, command: Callable[[], None]) -> tk.Button:
        return tk.Button(
            parent,
            text=text,
            command=command,
            font=(self.font_family, 10, "bold"),
            bd=0,
            relief="flat",
            cursor="hand2",
            padx=16,
            pady=9,
            highlightthickness=0,
        )

    def _section_title(self, parent: tk.Frame, title: str, subtitle: str, row: int) -> None:
        tk.Label(
            parent,
            text=title,
            font=(self.font_family, 15, "bold"),
            fg=COLORS["text"],
            bg=COLORS["surface"],
        ).grid(row=row, column=0, sticky="w")
        tk.Label(
            parent,
            text=subtitle,
            font=(self.font_family, 9),
            fg=COLORS["muted"],
            bg=COLORS["surface"],
        ).grid(row=row + 1, column=0, sticky="w", pady=(3, 0))

    def _build_file_card(
        self,
        parent: tk.Frame,
        row: int,
        name_var: tk.StringVar,
        meta_var: tk.StringVar,
        browse_command: Callable[[], None],
        browse_text: str,
    ) -> tk.Button:
        card = tk.Frame(
            parent,
            bg=COLORS["surface_alt"],
            highlightbackground=COLORS["border"],
            highlightthickness=1,
            padx=16,
            pady=14,
        )
        card.grid(row=row, column=0, sticky="ew", pady=(10, 22))
        card.grid_columnconfigure(0, weight=1)

        tk.Label(
            card,
            textvariable=name_var,
            font=(self.font_family, 10, "bold"),
            fg=COLORS["text"],
            bg=COLORS["surface_alt"],
            anchor="w",
        ).grid(row=0, column=0, sticky="ew")
        tk.Label(
            card,
            textvariable=meta_var,
            font=(self.font_family, 9),
            fg=COLORS["muted"],
            bg=COLORS["surface_alt"],
            anchor="w",
        ).grid(row=1, column=0, sticky="ew", pady=(4, 0))

        browse = self._secondary_button(card, browse_text, browse_command)
        browse.grid(row=0, column=1, rowspan=2, padx=(18, 0))
        self._controls.append(browse)
        return browse

    def _password_entry(self, parent: tk.Frame, row: int, label: str) -> tk.Entry:
        tk.Label(
            parent,
            text=label,
            font=(self.font_family, 9, "bold"),
            fg=COLORS["text"],
            bg=COLORS["surface"],
        ).grid(row=row, column=0, sticky="w", pady=(0, 5))
        entry = tk.Entry(
            parent,
            show="•",
            font=(self.font_family, 11),
            fg=COLORS["text"],
            bg=COLORS["surface_alt"],
            insertbackground=COLORS["text"],
            relief="flat",
            bd=0,
            highlightbackground=COLORS["border"],
            highlightcolor=COLORS["primary"],
            highlightthickness=1,
        )
        entry.grid(row=row + 1, column=0, sticky="ew", ipady=9)
        return entry

    def _primary_button(self, parent: tk.Frame, text: str, command: Callable[[], None]) -> tk.Button:
        button = tk.Button(
            parent,
            text=text,
            command=command,
            font=(self.font_family, 10, "bold"),
            fg="white",
            bg=COLORS["primary"],
            activeforeground="white",
            activebackground=COLORS["primary_hover"],
            bd=0,
            relief="flat",
            cursor="hand2",
            padx=22,
            pady=11,
            highlightthickness=0,
        )
        return button

    def _secondary_button(self, parent: tk.Frame, text: str, command: Callable[[], None]) -> tk.Button:
        return tk.Button(
            parent,
            text=text,
            command=command,
            font=(self.font_family, 9, "bold"),
            fg=COLORS["primary"],
            bg=COLORS["primary_soft"],
            activeforeground=COLORS["primary_hover"],
            activebackground="#DCE8FF",
            bd=0,
            relief="flat",
            cursor="hand2",
            padx=13,
            pady=8,
            highlightthickness=0,
        )

    def _build_encrypt_view(self, parent: tk.Frame) -> None:
        body = tk.Frame(parent, bg=COLORS["surface"], padx=30, pady=26)
        body.grid(row=0, column=0, sticky="nsew")
        body.grid_columnconfigure(0, weight=1)

        self._section_title(body, "Encrypt a file", "The original stays untouched. New files use a modern streaming authenticated format.", 0)
        self._build_file_card(body, 2, self.encrypt_file_name, self.encrypt_file_meta, self.choose_encrypt_file, "Browse…")

        self._section_title(body, "Create a password", "There is no password recovery. Use a long unique password or generate one below.", 3)
        self.encrypt_password = self._password_entry(body, 5, "Password")
        self.encrypt_confirm = self._password_entry(body, 7, "Confirm password")
        self.encrypt_password.bind("<KeyRelease>", self._update_password_hint)

        options = tk.Frame(body, bg=COLORS["surface"])
        options.grid(row=9, column=0, sticky="ew", pady=(8, 20))
        self.encrypt_hint_label = tk.Label(
            options,
            textvariable=self.password_hint,
            font=(self.font_family, 9),
            fg=COLORS["muted"],
            bg=COLORS["surface"],
        )
        self.encrypt_hint_label.pack(side="left")
        generate = self._secondary_button(options, "Generate strong password", self.generate_password)
        generate.pack(side="left", padx=(14, 0))
        self._controls.append(generate)
        show = tk.Checkbutton(
            options,
            text="Show passwords",
            variable=self.encrypt_show_password,
            command=self._toggle_encrypt_password,
            font=(self.font_family, 9),
            fg=COLORS["muted"],
            bg=COLORS["surface"],
            activebackground=COLORS["surface"],
            selectcolor=COLORS["surface"],
            bd=0,
            highlightthickness=0,
        )
        show.pack(side="right")

        actions = tk.Frame(body, bg=COLORS["surface"])
        actions.grid(row=10, column=0, sticky="ew")
        self.encrypt_action = self._primary_button(actions, "Encrypt and save…", self.encrypt_selected_file)
        self.encrypt_action.pack(side="left")
        clear = self._secondary_button(actions, "Clear", self.clear_encrypt)
        clear.pack(side="left", padx=(10, 0))
        self._controls.extend([self.encrypt_action, clear, show])

    def _build_decrypt_view(self, parent: tk.Frame) -> None:
        body = tk.Frame(parent, bg=COLORS["surface"], padx=30, pady=26)
        body.grid(row=0, column=0, sticky="nsew")
        body.grid_columnconfigure(0, weight=1)

        self._section_title(body, "Decrypt a file", "Restore a .sfe or legacy .enc file using the original password.", 0)
        self._build_file_card(body, 2, self.decrypt_file_name, self.decrypt_file_meta, self.choose_decrypt_file, "Browse…")

        self._section_title(body, "Enter the password", "Wrong passwords and modified encrypted files are rejected without writing an output file.", 3)
        self.decrypt_password = self._password_entry(body, 5, "Password")

        options = tk.Frame(body, bg=COLORS["surface"])
        options.grid(row=7, column=0, sticky="ew", pady=(8, 20))
        tk.Label(
            options,
            text="Decrypts current .sfe files plus legacy .enc files from the original prototype and v1.x.",
            font=(self.font_family, 9),
            fg=COLORS["muted"],
            bg=COLORS["surface"],
        ).pack(side="left")
        show = tk.Checkbutton(
            options,
            text="Show password",
            variable=self.decrypt_show_password,
            command=self._toggle_decrypt_password,
            font=(self.font_family, 9),
            fg=COLORS["muted"],
            bg=COLORS["surface"],
            activebackground=COLORS["surface"],
            selectcolor=COLORS["surface"],
            bd=0,
            highlightthickness=0,
        )
        show.pack(side="right")

        actions = tk.Frame(body, bg=COLORS["surface"])
        actions.grid(row=8, column=0, sticky="ew")
        self.decrypt_action = self._primary_button(actions, "Decrypt and save…", self.decrypt_selected_file)
        self.decrypt_action.pack(side="left")
        clear = self._secondary_button(actions, "Clear", self.clear_decrypt)
        clear.pack(side="left", padx=(10, 0))
        self._controls.extend([self.decrypt_action, clear, show])

    def _build_status(self, parent: tk.Frame) -> None:
        status = tk.Frame(parent, bg=COLORS["bg"])
        status.grid(row=3, column=0, sticky="ew", pady=(13, 0))
        status.grid_columnconfigure(1, weight=1)

        self.status_dot = tk.Canvas(status, width=12, height=12, bg=COLORS["bg"], highlightthickness=0)
        self.status_dot.grid(row=0, column=0, sticky="w")
        self.status_dot_id = self.status_dot.create_oval(2, 2, 10, 10, fill=COLORS["success"], outline="")
        tk.Label(
            status,
            textvariable=self.status_text,
            font=(self.font_family, 9, "bold"),
            fg=COLORS["muted"],
            bg=COLORS["bg"],
        ).grid(row=0, column=1, sticky="w", padx=(6, 0))
        tk.Label(
            status,
            text="Local-only  •  Streaming encryption  •  Original files never auto-deleted",
            font=(self.font_family, 9),
            fg=COLORS["muted"],
            bg=COLORS["bg"],
        ).grid(row=0, column=2, sticky="e")

        self.progress = ttk.Progressbar(status, mode="determinate", maximum=100, style="SFE.Horizontal.TProgressbar")
        self.progress.grid(row=1, column=0, columnspan=3, sticky="ew", pady=(8, 0))
        self.progress.grid_remove()

    def show_view(self, view: str) -> None:
        if self.busy:
            return
        self.current_view = view
        if view == "encrypt":
            self.encrypt_view.tkraise()
        else:
            self.decrypt_view.tkraise()
        self._style_nav()

    def _style_nav(self) -> None:
        for name, button in (("encrypt", self.encrypt_nav), ("decrypt", self.decrypt_nav)):
            active = name == self.current_view
            button.configure(
                bg=COLORS["primary"] if active else COLORS["surface"],
                fg="white" if active else COLORS["muted"],
                activebackground=COLORS["primary_hover"] if active else COLORS["surface_alt"],
                activeforeground="white" if active else COLORS["text"],
            )

    def _set_file_info(self, path: str, *, encrypt: bool) -> None:
        p = Path(path)
        try:
            size = format_bytes(p.stat().st_size)
        except OSError:
            size = "Unknown size"
        if encrypt:
            self.encrypt_path.set(path)
            self.encrypt_file_name.set(p.name)
            self.encrypt_file_meta.set(f"{size}  •  {p.parent}")
        else:
            self.decrypt_path.set(path)
            self.decrypt_file_name.set(p.name)
            self.decrypt_file_meta.set(f"{size}  •  {p.parent}")
        self._set_status(f"Selected {p.name}", "ready")

    def choose_encrypt_file(self) -> None:
        filename = filedialog.askopenfilename(title="Choose a file to encrypt")
        if filename:
            self._set_file_info(filename, encrypt=True)

    def choose_decrypt_file(self) -> None:
        filename = filedialog.askopenfilename(
            title="Choose an encrypted file",
            filetypes=[("Secure File Encryptor", "*.sfe *.enc"), ("SFE files", "*.sfe"), ("Legacy ENC files", "*.enc"), ("All files", "*.*")],
        )
        if filename:
            self._set_file_info(filename, encrypt=False)

    def _toggle_encrypt_password(self) -> None:
        show = "" if self.encrypt_show_password.get() else "•"
        self.encrypt_password.configure(show=show)
        self.encrypt_confirm.configure(show=show)

    def _toggle_decrypt_password(self) -> None:
        self.decrypt_password.configure(show="" if self.decrypt_show_password.get() else "•")

    def _update_password_hint(self, _event: tk.Event | None = None) -> None:
        password = self.encrypt_password.get()
        if not password:
            text, color = "Use at least 12 characters", COLORS["muted"]
        elif len(password) < MIN_ENCRYPT_PASSWORD_LENGTH:
            text, color = f"{MIN_ENCRYPT_PASSWORD_LENGTH - len(password)} more character(s) required", COLORS["warning"]
        else:
            classes = sum(
                [
                    any(c.islower() for c in password),
                    any(c.isupper() for c in password),
                    any(c.isdigit() for c in password),
                    any(not c.isalnum() for c in password),
                ]
            )
            if len(password) >= 16 and classes >= 3:
                text, color = "Good length and character variety", COLORS["success"]
            else:
                text, color = "Minimum length met", COLORS["primary"]
        self.password_hint.set(text)
        self.encrypt_hint_label.configure(fg=color)

    def generate_password(self) -> None:
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
        while True:
            password = "".join(secrets.choice(alphabet) for _ in range(20))
            if (any(c.islower() for c in password) and any(c.isupper() for c in password)
                    and any(c.isdigit() for c in password) and any(not c.isalnum() for c in password)):
                break
        for entry in (self.encrypt_password, self.encrypt_confirm):
            entry.delete(0, tk.END)
            entry.insert(0, password)
        self.encrypt_show_password.set(True)
        self._toggle_encrypt_password()
        self._update_password_hint()
        self._set_status("Strong password generated — save it somewhere safe", "ready")

    def encrypt_selected_file(self) -> None:
        input_file = self.encrypt_path.get().strip()
        password = self.encrypt_password.get()
        confirm = self.encrypt_confirm.get()

        if not input_file:
            messagebox.showerror("Choose a file", "Choose a file to encrypt first.", parent=self)
            return
        if len(password) < MIN_ENCRYPT_PASSWORD_LENGTH:
            messagebox.showerror(
                "Password too short",
                f"Use at least {MIN_ENCRYPT_PASSWORD_LENGTH} characters for new encrypted files.",
                parent=self,
            )
            return
        if password != confirm:
            messagebox.showerror("Passwords do not match", "Enter the same password in both boxes.", parent=self)
            return

        input_path = Path(input_file)
        output_file = filedialog.asksaveasfilename(
            title="Save encrypted file as",
            initialdir=str(input_path.parent),
            initialfile=input_path.name + ".sfe",
            defaultextension=".sfe",
            filetypes=[("Secure File Encryptor", "*.sfe"), ("All files", "*.*")],
        )
        if not output_file:
            return
        overwrite = self._confirm_overwrite(output_file)
        if overwrite is None:
            return

        self._run_operation(
            label="Encrypting securely…",
            function=encrypt_file,
            args=(input_file, output_file, password),
            kwargs={"overwrite": overwrite, "progress_callback": self._progress_callback},
            success=lambda saved: self._encrypt_success(saved),
        )

    def decrypt_selected_file(self) -> None:
        input_file = self.decrypt_path.get().strip()
        password = self.decrypt_password.get()

        if not input_file:
            messagebox.showerror("Choose a file", "Choose an encrypted .sfe or .enc file first.", parent=self)
            return
        if not password:
            messagebox.showerror("Enter the password", "Enter the password used to encrypt this file.", parent=self)
            return

        input_path = Path(input_file)
        default_name = input_path.name[:-4] if input_path.name.lower().endswith((".enc", ".sfe")) else input_path.name + ".decrypted"
        output_file = filedialog.asksaveasfilename(
            title="Save decrypted file as",
            initialdir=str(input_path.parent),
            initialfile=default_name,
            filetypes=[("All files", "*.*")],
        )
        if not output_file:
            return
        overwrite = self._confirm_overwrite(output_file)
        if overwrite is None:
            return

        self._run_operation(
            label="Decrypting and verifying…",
            function=decrypt_file,
            args=(input_file, output_file, password),
            kwargs={"overwrite": overwrite, "progress_callback": self._progress_callback},
            success=lambda saved: self._decrypt_success(saved),
        )

    def _run_operation(
        self,
        *,
        label: str,
        function: Callable,
        args: tuple,
        kwargs: dict,
        success: Callable[[Path], None],
    ) -> None:
        self._set_busy(True, label)

        def worker() -> None:
            try:
                result = function(*args, **kwargs)
            except Exception as exc:  # Handled on the Tk main thread below.
                self.after(0, lambda exc=exc: self._operation_failed(exc))
            else:
                self.after(0, lambda result=result: self._operation_succeeded(result, success))

        threading.Thread(target=worker, daemon=True).start()

    def _progress_callback(self, processed: int, total: int) -> None:
        # Called from the worker thread: queue data only; never touch Tk here.
        self.progress_queue.put((processed, total))

    def _poll_progress(self) -> None:
        latest = None
        while True:
            try:
                latest = self.progress_queue.get_nowait()
            except queue.Empty:
                break
        if latest is not None:
            processed, total = latest
            percent = 100 if total == 0 else max(0, min(100, int(processed * 100 / total)))
            self.progress.configure(value=percent)
        if self.busy:
            self._progress_poll_job = self.after(80, self._poll_progress)
        else:
            self._progress_poll_job = None

    def _operation_succeeded(self, result: Path, callback: Callable[[Path], None]) -> None:
        self._set_busy(False, "Ready")
        callback(result)

    def _operation_failed(self, exc: Exception) -> None:
        self._set_busy(False, "Operation failed", state="error")
        if isinstance(exc, AuthenticationError):
            messagebox.showerror(
                "Could not decrypt file",
                "The password is incorrect, or the encrypted file was modified/corrupted.\n\nNo output file was written.",
                parent=self,
            )
        elif isinstance(exc, (SecureFileError, OSError, FileExistsError)):
            messagebox.showerror("Operation failed", str(exc), parent=self)
        else:
            messagebox.showerror("Operation failed", f"Unexpected error: {exc}", parent=self)

    def _encrypt_success(self, saved: Path) -> None:
        self._set_status("Encryption complete", "success")
        self.encrypt_password.delete(0, tk.END)
        self.encrypt_confirm.delete(0, tk.END)
        self.encrypt_show_password.set(False)
        self._toggle_encrypt_password()
        self._update_password_hint()
        messagebox.showinfo(
            "Encryption complete",
            f"Encrypted copy created successfully.\n\nSaved as:\n{saved}\n\nYour original file was not changed or deleted.",
            parent=self,
        )

    def _decrypt_success(self, saved: Path) -> None:
        self._set_status("Decryption complete", "success")
        self.decrypt_password.delete(0, tk.END)
        self.decrypt_show_password.set(False)
        self._toggle_decrypt_password()
        messagebox.showinfo(
            "Decryption complete",
            f"File restored and verified successfully.\n\nSaved as:\n{saved}",
            parent=self,
        )

    def _set_busy(self, busy: bool, text: str, state: str = "busy") -> None:
        self.busy = busy
        for control in self._controls:
            try:
                control.configure(state="disabled" if busy else "normal")
            except tk.TclError:
                pass
        if busy:
            while True:
                try:
                    self.progress_queue.get_nowait()
                except queue.Empty:
                    break
            self.progress.configure(value=0)
            self.progress.grid()
            if self._progress_poll_job is None:
                self._progress_poll_job = self.after(80, self._poll_progress)
        else:
            self.progress.configure(value=0)
            self.progress.grid_remove()
        self._set_status(text, state)

    def _set_status(self, text: str, state: str = "ready") -> None:
        self.status_text.set(text)
        color = {
            "ready": COLORS["success"],
            "success": COLORS["success"],
            "busy": COLORS["primary"],
            "error": COLORS["danger"],
        }.get(state, COLORS["success"])
        self.status_dot.itemconfigure(self.status_dot_id, fill=color)

    def clear_encrypt(self) -> None:
        if self.busy:
            return
        self.encrypt_path.set("")
        self.encrypt_file_name.set("No file selected")
        self.encrypt_file_meta.set("Choose a file — large files are processed in chunks")
        self.encrypt_password.delete(0, tk.END)
        self.encrypt_confirm.delete(0, tk.END)
        self.encrypt_show_password.set(False)
        self._toggle_encrypt_password()
        self._update_password_hint()
        self._set_status("Ready")

    def clear_decrypt(self) -> None:
        if self.busy:
            return
        self.decrypt_path.set("")
        self.decrypt_file_name.set("No encrypted file selected")
        self.decrypt_file_meta.set("Choose a .sfe or legacy .enc file")
        self.decrypt_password.delete(0, tk.END)
        self.decrypt_show_password.set(False)
        self._toggle_decrypt_password()
        self._set_status("Ready")

    @staticmethod
    def _confirm_overwrite(output_file: str) -> bool | None:
        if not os.path.exists(output_file):
            return False
        replace = messagebox.askyesno(
            "File already exists",
            f"{Path(output_file).name} already exists.\n\nReplace it?",
        )
        return True if replace else None

    def show_about(self) -> None:
        messagebox.showinfo(
            f"About {APP_NAME}",
            f"{APP_NAME} {APP_VERSION}\n\n"
            "Password-based authenticated file encryption.\n"
            "New .sfe files use Argon2id + AES-256-GCM streaming encryption.\n"
            "Legacy .enc files remain decryptable. No network connection is used.\n\n"
            "The app cannot recover a forgotten password.",
            parent=self,
        )


def main() -> None:
    app = SecureFileEncryptorApp()
    app.mainloop()


if __name__ == "__main__":
    main()
