# pyright: reportUnknownMemberType=false, reportUnknownArgumentType=false
"""Login dialog for the Revenant GUI.

LoginDialog: credentials, identity discovery, and save (Layer 1 -> 2).
The server connection dialog lives in ``connect_dialog``.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from ...config import (
    get_active_profile,
    get_credential_storage_info,
    get_credentials,
    get_signer_info,
    is_keyring_available,
    register_profile_tls_mode,
    save_credentials,
    save_signer_info,
)
from ...core.cert_info import discover_identity_from_server
from ...errors import AuthError, RevenantError, TLSError
from .utils import run_in_thread

if TYPE_CHECKING:
    import tkinter as tk
    from collections.abc import Callable

_logger = logging.getLogger(__name__)

# ── LoginDialog ──────────────────────────────────────────────────────

_LOGIN_STEP_CREDENTIALS = 0
_LOGIN_STEP_IDENTITY = 1
_LOGIN_STEP_DONE = 2
_LOGIN_STEP_TITLES = ["Credentials", "Signer Identity", "Complete"]
_LOGIN_NUM_STEPS = len(_LOGIN_STEP_TITLES)


class LoginDialog:
    """Multi-step login wizard: credentials, identity discovery, and save."""

    def __init__(
        self, parent: tk.Tk | tk.Toplevel, on_complete_action: Callable[[], None] | None = None
    ) -> None:
        import tkinter as tk
        from tkinter import ttk

        self._tk = tk
        self._ttk = ttk
        self._on_complete_action = on_complete_action

        # Wizard state
        self._step = _LOGIN_STEP_CREDENTIALS
        self._profile = get_active_profile()
        self._username = ""
        self._password = ""
        self._identity: dict[str, str | None] | None = None

        # Window
        self._win = tk.Toplevel(parent)
        self._win.withdraw()
        self._win.title("Log In")
        self._win.resizable(False, False)
        self._win.transient(parent)
        self._win.grab_set()

        outer = ttk.Frame(self._win, padding=16)
        outer.grid(sticky="nsew")

        # Header row: title + step indicator
        self._title_var = tk.StringVar(value=_LOGIN_STEP_TITLES[0])
        ttk.Label(outer, textvariable=self._title_var, font=("", 14, "bold")).grid(
            row=0, column=0, sticky="w", pady=(0, 8)
        )
        self._step_var = tk.StringVar()
        ttk.Label(outer, textvariable=self._step_var, foreground="gray").grid(
            row=0, column=1, sticky="e", pady=(0, 8)
        )

        # Content frame (replaced each step)
        self._content = ttk.Frame(outer)
        self._content.grid(row=1, column=0, columnspan=2, sticky="nsew", pady=8)

        # Navigation buttons
        nav = ttk.Frame(outer)
        nav.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(8, 0))
        self._back_btn = ttk.Button(nav, text="Back", command=self._go_back)
        self._back_btn.pack(side="left")
        ttk.Button(nav, text="Cancel", command=self._cancel).pack(side="right", padx=(8, 0))
        self._next_btn = ttk.Button(nav, text="Next", command=self._go_next)
        self._next_btn.pack(side="right")

        # Status label
        self._status_var = tk.StringVar()
        ttk.Label(outer, textvariable=self._status_var, foreground="gray", wraplength=380).grid(
            row=3, column=0, columnspan=2, sticky="w", pady=(4, 0)
        )

        self._show_step()

        from . import center_on_parent

        center_on_parent(self._win, parent)

    # ── Step rendering ──────────────────────────────────────────────

    def _show_step(self) -> None:
        """Clear content frame and build the current step."""
        for w in self._content.winfo_children():
            w.destroy()
        self._status_var.set("")
        self._title_var.set(_LOGIN_STEP_TITLES[self._step])
        self._step_var.set(f"Step {self._step + 1} of {_LOGIN_NUM_STEPS}")
        self._back_btn.configure(
            state="normal" if self._step > _LOGIN_STEP_CREDENTIALS else "disabled"
        )
        self._next_btn.configure(state="normal", text="Next")

        builders = [
            self._build_credentials,
            self._build_identity,
            self._build_done,
        ]
        builders[self._step]()

    def _build_credentials(self) -> None:
        """Step 1: Enter username and password."""
        tk, ttk, f = self._tk, self._ttk, self._content

        if self._profile is not None and self._profile.max_auth_attempts:
            ttk.Label(
                f,
                text=f"Warning: account locks after {self._profile.max_auth_attempts} failed attempts!",
                foreground="#cc7700",
            ).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 8))

        self._user_var = tk.StringVar(value=self._username)
        self._pass_var = tk.StringVar(value=self._password)

        # Pre-fill from saved config if empty
        if not self._username and not self._password:
            self._status_var.set("Loading saved credentials...")
            self._win.update_idletasks()
            saved_user, saved_pass = get_credentials()
            if saved_user is not None:
                self._user_var.set(saved_user)
            if saved_pass is not None:
                self._pass_var.set(saved_pass)
            if saved_user and not saved_pass and is_keyring_available():
                self._status_var.set(
                    "Could not read password from system keychain.\nPlease re-enter your password."
                )
            else:
                self._status_var.set("")

        ttk.Label(f, text="Username:").grid(row=1, column=0, sticky="e", padx=(0, 8), pady=4)
        ttk.Entry(f, textvariable=self._user_var, width=30).grid(
            row=1, column=1, sticky="w", pady=4
        )
        ttk.Label(f, text="Password:").grid(row=2, column=0, sticky="e", padx=(0, 8), pady=4)
        ttk.Entry(f, textvariable=self._pass_var, width=30, show="\u2022").grid(
            row=2, column=1, sticky="w", pady=4
        )

    def _build_identity(self) -> None:
        """Step 2: Discover signer identity."""
        self._next_btn.configure(state="disabled")
        # Back stays enabled so the user can escape if discovery hangs

        self._id_status = self._tk.StringVar(value="Discovering signer identity...")
        self._ttk.Label(self._content, textvariable=self._id_status, wraplength=400).grid(
            row=0, column=0, sticky="w", pady=4
        )
        self._id_frame = self._ttk.Frame(self._content)
        self._id_frame.grid(row=1, column=0, sticky="nsew", pady=4)

        if self._profile is not None and self._profile.has_identity_method("server"):
            run_in_thread(
                self._win, self._task_discover, self._on_discover_ok, self._on_discover_fail
            )
        else:
            self._show_fallbacks()

    def _task_discover(self) -> dict[str, str | None]:
        from ...network.soap_transport import SoapSigningTransport

        if self._profile is not None:
            register_profile_tls_mode(self._profile)
        url = self._profile.url if self._profile is not None else ""
        timeout = self._profile.timeout if self._profile is not None else 30
        transport = SoapSigningTransport(url)
        return discover_identity_from_server(transport, self._username, self._password, timeout)

    def _on_discover_ok(self, info: dict[str, str | None]) -> None:
        if info and info.get("name"):
            self._identity = info
            self._show_identity(info)
            self._next_btn.configure(state="normal")
        else:
            self._id_status.set("Could not determine identity from server.")
            self._show_fallbacks()

    def _on_discover_fail(self, exc: Exception) -> None:
        if isinstance(exc, AuthError):
            self._id_status.set(f"Authentication failed: {exc}")
        elif isinstance(exc, (TLSError, RevenantError)):
            self._id_status.set(f"Server error: {exc}")
        else:
            self._id_status.set(f"Error: {exc}")
        self._show_fallbacks()

    def _show_identity(self, info: dict[str, str | None]) -> None:
        """Display discovered identity info using cert_fields when available."""
        from ...core.appearance.fields import extract_cert_fields

        for w in self._id_frame.winfo_children():
            w.destroy()
        self._id_status.set("Signer identity found:")
        row = 0

        if self._profile is not None and self._profile.cert_fields:
            extracted = extract_cert_fields(self._profile.cert_fields, info)
            for cf in self._profile.cert_fields:
                value = extracted.get(cf.id)
                if value:
                    self._ttk.Label(self._id_frame, text=f"{cf.label}: {value}").grid(
                        row=row, column=0, sticky="w", padx=16
                    )
                    row += 1
        else:
            # Fallback for custom servers: raw name, email, org
            for key, label in [
                ("name", "Name"),
                ("email", "Email"),
                ("organization", "Organization"),
            ]:
                val = info.get(key)
                if val:
                    self._ttk.Label(self._id_frame, text=f"{label}: {val}").grid(
                        row=row, column=0, sticky="w", padx=16
                    )
                    row += 1

    def _show_fallbacks(self) -> None:
        """Show recovery options after identity discovery failure.

        Profiles with cert_fields (e.g., EKENG) get "Retry" only -- manual entry
        won't work because regex patterns won't match hand-typed data.
        Custom servers get "Enter manually..." since there's no structured extraction.
        """
        self._back_btn.configure(state="normal")
        for w in self._id_frame.winfo_children():
            w.destroy()

        has_cert_fields = self._profile is not None and bool(self._profile.cert_fields)

        self._ttk.Button(self._id_frame, text="Retry", command=self._id_retry).grid(
            row=0, column=0, sticky="w", pady=4
        )
        if not has_cert_fields:
            self._ttk.Button(
                self._id_frame, text="Enter manually...", command=self._id_manual
            ).grid(row=0, column=1, sticky="w", padx=(8, 0), pady=4)

    def _id_retry(self) -> None:
        """Re-run the identity discovery step from scratch."""
        self._identity = None
        self._show_step()

    def _id_manual(self) -> None:
        """Show manual identity entry fields."""
        tk, ttk = self._tk, self._ttk
        for w in self._id_frame.winfo_children():
            w.destroy()
        self._id_status.set("Enter signer identity:")

        saved = get_signer_info()
        self._manual_name = tk.StringVar(value=saved.get("name") or "")
        self._manual_email = tk.StringVar(value=saved.get("email") or "")
        self._manual_org = tk.StringVar(value=saved.get("organization") or "")

        ttk.Label(self._id_frame, text="Name (required):").grid(
            row=0, column=0, sticky="e", padx=(0, 8)
        )
        ttk.Entry(self._id_frame, textvariable=self._manual_name, width=30).grid(
            row=0, column=1, sticky="w"
        )
        ttk.Label(self._id_frame, text="Email:").grid(
            row=1, column=0, sticky="e", padx=(0, 8), pady=4
        )
        ttk.Entry(self._id_frame, textvariable=self._manual_email, width=30).grid(
            row=1, column=1, sticky="w"
        )
        ttk.Label(self._id_frame, text="Organization:").grid(
            row=2, column=0, sticky="e", padx=(0, 8), pady=4
        )
        ttk.Entry(self._id_frame, textvariable=self._manual_org, width=30).grid(
            row=2, column=1, sticky="w"
        )
        self._next_btn.configure(state="normal")

    def _build_done(self) -> None:
        """Step 3: Summary and save."""
        tk, ttk, f = self._tk, self._ttk, self._content

        ttk.Label(f, text="Setup complete! Summary:", font=("", 11, "bold")).grid(
            row=0, column=0, columnspan=2, sticky="w", pady=(0, 8)
        )
        row = 1
        if self._identity is not None:
            ttk.Label(f, text=f"Signer: {self._identity.get('name', '')}").grid(
                row=row, column=0, columnspan=2, sticky="w", padx=8
            )
            row += 1
        ttk.Label(f, text=f"Username: {self._username}").grid(
            row=row, column=0, columnspan=2, sticky="w", padx=8
        )

        self._save_creds_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            f, text="Save credentials (username/password)", variable=self._save_creds_var
        ).grid(row=row + 2, column=0, columnspan=2, sticky="w", padx=8, pady=8)

        storage = get_credential_storage_info()
        ttk.Label(f, text=f"Storage: {storage}", foreground="gray").grid(
            row=row + 3, column=0, columnspan=2, sticky="w", padx=24
        )

        self._next_btn.configure(text="Save", state="normal")

    # ── Navigation ──────────────────────────────────────────────────

    def _go_next(self) -> None:
        """Advance to the next step, validating current step first."""
        from tkinter import messagebox

        if self._step == _LOGIN_STEP_CREDENTIALS:
            user = self._user_var.get().strip()
            pwd = self._pass_var.get().strip()
            if not user or not pwd:
                messagebox.showwarning(
                    "Login", "Username and password are required.", parent=self._win
                )
                return
            self._username = user
            self._password = pwd

        elif self._step == _LOGIN_STEP_IDENTITY:
            if self._identity is None and hasattr(self, "_manual_name"):
                name = self._manual_name.get().strip()
                if not name:
                    messagebox.showwarning("Login", "Name is required.", parent=self._win)
                    return
                self._identity = {
                    "name": name,
                    "email": self._manual_email.get().strip() or None,
                    "organization": self._manual_org.get().strip() or None,
                    "dn": None,
                }
            elif self._identity is None:
                has_cert_fields = self._profile is not None and bool(self._profile.cert_fields)
                if has_cert_fields:
                    msg = "Signer identity is required. Retry the connection or go back to fix credentials."
                else:
                    msg = "Signer identity is required. Click 'Enter manually...' to provide it."
                messagebox.showwarning("Login", msg, parent=self._win)
                return

        elif self._step == _LOGIN_STEP_DONE:
            self._save_and_close()
            return

        self._step += 1
        self._show_step()

    def _go_back(self) -> None:
        """Go back one step."""
        if self._step > _LOGIN_STEP_CREDENTIALS:
            if self._step == _LOGIN_STEP_IDENTITY:
                self._identity = None
            self._step -= 1
            self._show_step()

    def _cancel(self) -> None:
        self._win.destroy()

    def _save_and_close(self) -> None:
        """Save configuration and close the dialog."""
        from ...config import clear_credentials, set_session_credentials

        if self._identity is not None:
            name = self._identity.get("name") or ""
            save_signer_info(
                name=name,
                email=self._identity.get("email"),
                organization=self._identity.get("organization"),
                dn=self._identity.get("dn"),
            )
        if self._save_creds_var.get():
            _logger.info("Login: saving credentials (checkbox checked)")
            self._status_var.set("Saving credentials...")
            self._win.update_idletasks()
            stored_securely = save_credentials(self._username, self._password)
            if not stored_securely and is_keyring_available():
                from tkinter import messagebox

                messagebox.showwarning(
                    "Revenant",
                    "Could not save password to system keychain\n"
                    "(access was denied or unavailable).\n\n"
                    "Your password was saved to the config file instead.\n"
                    "To use secure storage, allow keychain access\n"
                    "when prompted.",
                    parent=self._win,
                )
        else:
            _logger.info("Login: clearing credentials (checkbox unchecked)")
            self._status_var.set("Clearing saved credentials...")
            self._win.update_idletasks()
            clear_credentials()

        # Always cache in session so user can sign without restarting
        set_session_credentials(self._username, self._password)

        # Clear sensitive data from memory
        self._password = ""
        if hasattr(self, "_pass_var"):
            self._pass_var.set("")

        self._win.destroy()
        if self._on_complete_action is not None:
            self._on_complete_action()
