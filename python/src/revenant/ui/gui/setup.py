# SPDX-License-Identifier: Apache-2.0
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
from .i18n import _
from .utils import run_in_thread

if TYPE_CHECKING:
    import tkinter as tk
    from collections.abc import Callable

_logger = logging.getLogger(__name__)

# ── LoginDialog ──────────────────────────────────────────────────────

_LOGIN_STEP_CREDENTIALS = 0
_LOGIN_STEP_IDENTITY = 1
_LOGIN_STEP_DONE = 2


def _login_step_titles() -> list[str]:
    return [_("gui.credentials"), _("gui.signer_identity"), _("gui.complete")]


_LOGIN_NUM_STEPS = 3


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
        self._win.title(_("gui.log_in"))
        self._win.resizable(False, False)
        self._win.transient(parent)
        self._win.grab_set()

        outer = ttk.Frame(self._win, padding=16)
        outer.grid(sticky="nsew")

        # Header row: title + step indicator
        self._title_var = tk.StringVar(value=_login_step_titles()[0])
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
        self._back_btn = ttk.Button(nav, text=_("gui.back"), command=self._go_back)
        self._back_btn.pack(side="left")
        ttk.Button(nav, text=_("gui.cancel"), command=self._cancel).pack(side="right", padx=(8, 0))
        self._next_btn = ttk.Button(nav, text=_("gui.next"), command=self._go_next)
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
        self._title_var.set(_login_step_titles()[self._step])
        self._step_var.set(
            _("gui.step_current_of_total").format(current=self._step + 1, total=_LOGIN_NUM_STEPS)
        )
        self._back_btn.configure(
            state="normal" if self._step > _LOGIN_STEP_CREDENTIALS else "disabled"
        )
        self._next_btn.configure(state="normal", text=_("gui.next"))

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
                text=_("gui.warning_account_locks_after_max_attempts_failed_attempts").format(
                    max_attempts=self._profile.max_auth_attempts
                ),
                foreground="#cc7700",
            ).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 8))

        self._user_var = tk.StringVar(value=self._username)
        self._pass_var = tk.StringVar(value=self._password)

        # Pre-fill from saved config if empty
        if not self._username and not self._password:
            self._status_var.set(_("gui.loading_saved_credentials_ellipsis"))
            self._win.update_idletasks()
            saved_user, saved_pass = get_credentials()
            if saved_user is not None:
                self._user_var.set(saved_user)
            if saved_pass is not None:
                self._pass_var.set(saved_pass)
            if saved_user and not saved_pass and is_keyring_available():
                self._status_var.set(
                    _("gui.could_not_read_password_from_system_keychain_pleas_a490f2d1")
                )
            else:
                self._status_var.set("")

        ttk.Label(f, text=_("gui.username_label")).grid(
            row=1, column=0, sticky="e", padx=(0, 8), pady=4
        )
        ttk.Entry(f, textvariable=self._user_var, width=30).grid(
            row=1, column=1, sticky="w", pady=4
        )
        ttk.Label(f, text=_("gui.password_label")).grid(
            row=2, column=0, sticky="e", padx=(0, 8), pady=4
        )
        pwd_frame = ttk.Frame(f)
        pwd_frame.grid(row=2, column=1, sticky="w", pady=4)
        self._pass_entry = ttk.Entry(
            pwd_frame, textvariable=self._pass_var, width=26, show="\u2022"
        )
        self._pass_entry.pack(side="left")
        self._pass_visible = False
        self._toggle_btn = ttk.Button(
            pwd_frame,
            text=_("gui.show"),
            width=5,
            command=self._toggle_password_visibility,
        )
        self._toggle_btn.pack(side="left", padx=(4, 0))

    def _build_identity(self) -> None:
        """Step 2: Discover signer identity."""
        self._next_btn.configure(state="disabled")
        # Back stays enabled so the user can escape if discovery hangs

        self._id_status = self._tk.StringVar(value=_("gui.discovering_signer_identity_ellipsis"))
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
            self._id_status.set(_("gui.could_not_determine_identity_from_server"))
            self._show_fallbacks()

    def _on_discover_fail(self, exc: Exception) -> None:
        if isinstance(exc, AuthError):
            self._id_status.set(_("gui.authentication_failed_error").format(error=exc))
        elif isinstance(exc, (TLSError, RevenantError)):
            self._id_status.set(_("gui.server_error_error").format(error=exc))
        else:
            self._id_status.set(_("gui.error_error").format(error=exc))
        self._show_fallbacks()

    def _show_identity(self, info: dict[str, str | None]) -> None:
        """Display discovered identity info using cert_fields when available."""
        from ...core.appearance.fields import extract_cert_fields

        for w in self._id_frame.winfo_children():
            w.destroy()
        self._id_status.set(_("gui.signer_identity_found_label"))
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
                ("name", _("gui.name")),
                ("email", _("gui.email")),
                ("organization", _("gui.organization")),
            ]:
                val = info.get(key)
                if val:
                    self._ttk.Label(self._id_frame, text=f"{label}: {val}").grid(
                        row=row, column=0, sticky="w", padx=16
                    )
                    row += 1

        # Show certificate validity period
        from ...core.cert_expiry import format_expiry_summary, format_validity_period

        not_before = info.get("not_before")
        not_after = info.get("not_after")
        if not_before or not_after:
            validity = format_validity_period(not_before, not_after)
            summary = format_expiry_summary(not_after)
            self._ttk.Label(
                self._id_frame,
                text=f"{_('gui.valid_label')} {validity}",
                foreground="gray",
            ).grid(row=row, column=0, sticky="w", padx=16, pady=(4, 0))
            row += 1
            color = "red" if "EXPIRED" in summary else "orange" if "soon" in summary else "gray"
            self._ttk.Label(
                self._id_frame,
                text=f"{_('gui.status_label')} {summary}",
                foreground=color,
            ).grid(row=row, column=0, sticky="w", padx=16)

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

        self._ttk.Button(self._id_frame, text=_("gui.retry"), command=self._id_retry).grid(
            row=0, column=0, sticky="w", pady=4
        )
        if not has_cert_fields:
            self._ttk.Button(
                self._id_frame, text=_("gui.enter_manually_ellipsis"), command=self._id_manual
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
        self._id_status.set(_("gui.enter_signer_identity_label"))

        saved = get_signer_info()
        self._manual_name = tk.StringVar(value=saved.get("name") or "")
        self._manual_email = tk.StringVar(value=saved.get("email") or "")
        self._manual_org = tk.StringVar(value=saved.get("organization") or "")

        ttk.Label(self._id_frame, text=_("gui.name_required_label")).grid(
            row=0, column=0, sticky="e", padx=(0, 8)
        )
        ttk.Entry(self._id_frame, textvariable=self._manual_name, width=30).grid(
            row=0, column=1, sticky="w"
        )
        ttk.Label(self._id_frame, text=_("gui.email_label")).grid(
            row=1, column=0, sticky="e", padx=(0, 8), pady=4
        )
        ttk.Entry(self._id_frame, textvariable=self._manual_email, width=30).grid(
            row=1, column=1, sticky="w"
        )
        ttk.Label(self._id_frame, text=_("gui.organization_label")).grid(
            row=2, column=0, sticky="e", padx=(0, 8), pady=4
        )
        ttk.Entry(self._id_frame, textvariable=self._manual_org, width=30).grid(
            row=2, column=1, sticky="w"
        )
        self._next_btn.configure(state="normal")

    def _build_done(self) -> None:
        """Step 3: Summary and save."""
        tk, ttk, f = self._tk, self._ttk, self._content

        ttk.Label(f, text=_("gui.setup_complete_summary_label"), font=("", 11, "bold")).grid(
            row=0, column=0, columnspan=2, sticky="w", pady=(0, 8)
        )
        row = 1
        if self._identity is not None:
            ttk.Label(
                f, text=_("gui.signer_name").format(name=self._identity.get("name", ""))
            ).grid(row=row, column=0, columnspan=2, sticky="w", padx=8)
            row += 1
        ttk.Label(f, text=_("gui.username_username").format(username=self._username)).grid(
            row=row, column=0, columnspan=2, sticky="w", padx=8
        )

        self._save_creds_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            f, text=_("gui.save_credentials_username_password"), variable=self._save_creds_var
        ).grid(row=row + 2, column=0, columnspan=2, sticky="w", padx=8, pady=8)

        storage = get_credential_storage_info()
        ttk.Label(f, text=_("gui.storage_storage").format(storage=storage), foreground="gray").grid(
            row=row + 3, column=0, columnspan=2, sticky="w", padx=24
        )

        self._next_btn.configure(text=_("gui.save"), state="normal")

    # ── UI helpers ──────────────────────────────────────────────────

    def _toggle_password_visibility(self) -> None:
        """Toggle password field between masked and plain text."""
        self._pass_visible = not self._pass_visible
        self._pass_entry.configure(show="" if self._pass_visible else "\u2022")
        self._toggle_btn.configure(text=_("gui.hide") if self._pass_visible else _("gui.show"))

    # ── Navigation ──────────────────────────────────────────────────

    def _go_next(self) -> None:
        """Advance to the next step, validating current step first."""
        from tkinter import messagebox

        if self._step == _LOGIN_STEP_CREDENTIALS:
            user = self._user_var.get().strip()
            pwd = self._pass_var.get().strip()
            if not user or not pwd:
                messagebox.showwarning(
                    _("gui.login"), _("gui.username_and_password_are_required"), parent=self._win
                )
                return
            if not user.isascii() or not pwd.isascii():
                messagebox.showwarning(
                    _("gui.login"),
                    _("gui.credentials_must_contain_only_latin_characters_ple_e9a0742d"),
                    parent=self._win,
                )
                return
            self._username = user
            self._password = pwd

        elif self._step == _LOGIN_STEP_IDENTITY:
            if self._identity is None and hasattr(self, "_manual_name"):
                name = self._manual_name.get().strip()
                if not name:
                    messagebox.showwarning(
                        _("gui.login"), _("gui.name_is_required"), parent=self._win
                    )
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
                    msg = _("gui.signer_identity_is_required_retry_the_connection_o_6eb0ccec")
                else:
                    msg = _("gui.signer_identity_is_required_click_enter_manually_t_397d205e")
                messagebox.showwarning(_("gui.login"), msg, parent=self._win)
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
                not_before=self._identity.get("not_before"),
                not_after=self._identity.get("not_after"),
            )
        if self._save_creds_var.get():
            _logger.info("Login: saving credentials (checkbox checked)")
            self._status_var.set(_("gui.saving_credentials_ellipsis"))
            self._win.update_idletasks()
            stored_securely = save_credentials(self._username, self._password)
            if not stored_securely and is_keyring_available():
                from tkinter import messagebox

                messagebox.showwarning(
                    "Revenant",
                    _("gui.could_not_save_password_to_system_keychain_access_04b14699"),
                    parent=self._win,
                )
        else:
            _logger.info("Login: clearing credentials (checkbox unchecked)")
            self._status_var.set(_("gui.clearing_saved_credentials_ellipsis"))
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
