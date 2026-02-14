# pyright: reportUnknownMemberType=false, reportUnknownArgumentType=false
"""
Minimal cross-platform GUI for Revenant PDF signing.

Uses only tkinter (stdlib) -- no extra dependencies.

Launch:
    revenant gui
    revenant-gui
    python -m revenant gui
"""

from __future__ import annotations

import logging
import platform
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import tkinter as tk
    from collections.abc import Callable

from ...config import (
    get_active_profile,
    get_config_layer,
    get_server_config,
    get_signer_info,
    logout,
    reset_all,
)
from ...constants import __version__
from .connect_dialog import ConnectDialog
from .dialogs import about_footer, login_dialog, show_about
from .setup import LoginDialog
from .sign_form import SignForm, build_server_only, build_unconfigured
from .utils import bind_macos_shortcuts, check_tkinter, enable_dpi_awareness

_logger = logging.getLogger(__name__)


# ── Server Bar ──────────────────────────────────────────────────────


class ServerBar:
    """Persistent server info bar above the notebook tabs."""

    def __init__(
        self,
        parent: tk.Widget,
        on_connect_action: Callable[[], None],
        on_disconnect_action: Callable[[], None],
    ) -> None:
        from tkinter import ttk

        self._on_connect_action = on_connect_action
        self._on_disconnect_action = on_disconnect_action

        self._frame = ttk.Frame(parent, padding=(12, 6))
        self._frame.columnconfigure(0, weight=1)

        import tkinter as tk

        self._label_var = tk.StringVar()
        self._label = ttk.Label(self._frame, textvariable=self._label_var)
        self._label.grid(row=0, column=0, sticky="w")

        self._btn = ttk.Button(self._frame)
        self._btn.grid(row=0, column=1, sticky="e", padx=(8, 0))

        self.refresh()

    @property
    def frame(self) -> tk.Widget:
        return self._frame

    def refresh(self) -> None:
        """Update display based on current config layer."""
        layer = get_config_layer()
        if layer == 0:
            self._label_var.set("No server configured")
            self._label.configure(foreground="gray", font=("", 10))
            self._btn.configure(text="Connect", command=self._on_connect_action)
        else:
            profile = get_active_profile()
            name = profile.display_name if profile else "Server"
            self._label_var.set(name)
            self._label.configure(foreground="", font=("", 10, "bold"))
            self._btn.configure(text="Disconnect", command=self._on_disconnect_action)


# ── Main Application ────────────────────────────────────────────────


class RevenantGUI:
    """Main application window -- coordinates sign form, verify panel, and dialogs."""

    def __init__(self, root: tk.Tk) -> None:
        import tkinter as tk

        self._tk = tk
        self.root = root
        self.root.title(f"Revenant v{__version__}")
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)

        self.pdf_path = tk.StringVar()
        self.image_path = tk.StringVar()
        self.output_path = tk.StringVar()
        self.signing_mode = tk.StringVar(value="embedded")
        self.position = tk.StringVar(value="right-bottom")
        self.page = tk.StringVar(value="last")
        self.font_key = tk.StringVar(value="noto-sans")
        self.invisible = tk.BooleanVar(value=False)
        self.status_text = tk.StringVar(value="Ready")
        self._signer_info = get_signer_info()
        self._content_frame: tk.Widget | None = None
        self._sign_form: SignForm | None = None
        self._server_bar: ServerBar | None = None

        self._build_ui()

        # Set minimum size after content is built so it doesn't collapse
        self.root.update_idletasks()
        self.root.minsize(self.root.winfo_reqwidth(), self.root.winfo_reqheight())
        self._center_window()

    # ── Window management ────────────────────────────────────────

    def _center_window(self) -> None:
        """Center the window on screen."""
        from . import center_on_screen

        center_on_screen(self.root)

    def _refit_window(self) -> None:
        """Reset window size to fit current content and re-center."""
        self.root.minsize(0, 0)
        self.root.update_idletasks()
        req_w = self.root.winfo_reqwidth()
        req_h = self.root.winfo_reqheight()
        self.root.geometry(f"{req_w}x{req_h}")
        self.root.minsize(req_w, req_h)
        self._center_window()

    def _clear_content(self) -> None:
        """Destroy current content frame to switch views."""
        if self._content_frame is not None:
            self._content_frame.destroy()
            self._content_frame = None

    # ── UI construction ──────────────────────────────────────────

    def _build_ui(self) -> None:
        from tkinter import ttk

        self._clear_content()

        frame = ttk.Frame(self.root, padding=12)
        frame.grid(sticky="nsew")
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(1, weight=1)
        self._content_frame = frame

        # ── Server bar ──────────────────────────────────────────
        self._server_bar = ServerBar(
            frame,
            on_connect_action=self._on_connect,
            on_disconnect_action=self._on_disconnect,
        )
        self._server_bar.frame.grid(row=0, column=0, sticky="ew")

        # ── Notebook with Sign / Verify tabs ────────────────────
        notebook = ttk.Notebook(frame)
        notebook.grid(row=1, column=0, sticky="nsew", pady=(4, 0))

        self._sign_tab = ttk.Frame(notebook)
        notebook.add(self._sign_tab, text="Sign")
        self._refresh_sign_tab()

        verify_tab = ttk.Frame(notebook)
        notebook.add(verify_tab, text="Verify")
        from .verify import VerifyPanel

        self._verify_panel = VerifyPanel(verify_tab, self.root)

        # ── Footer ──────────────────────────────────────────────
        about_footer(frame, self.root, row=2)

    def _refresh_sign_tab(self) -> None:
        """Rebuild Sign tab content based on configuration layer."""
        for child in self._sign_tab.winfo_children():
            child.destroy()

        layer = get_config_layer()

        if layer == 2:
            self._signer_info = get_signer_info()
            self.status_text.set("Ready")
            self._sign_form = SignForm(
                self._sign_tab,
                self.root,
                pdf_path=self.pdf_path,
                image_path=self.image_path,
                output_path=self.output_path,
                signing_mode=self.signing_mode,
                position=self.position,
                page=self.page,
                font_key=self.font_key,
                invisible=self.invisible,
                status_text=self.status_text,
                signer_info=self._signer_info,
                on_sign_action=self._on_sign,
                on_logout_action=self._on_logout,
            )
        elif layer == 1:
            self._sign_form = None
            build_server_only(self._sign_tab, on_login_action=self._on_login)
        else:
            self._sign_form = None
            build_unconfigured(self._sign_tab, on_connect_action=self._on_connect)

    # ── Signing ──────────────────────────────────────────────────

    def _on_sign(self) -> None:
        """Collect form values and delegate to signing worker."""
        from .sign_worker import start_signing

        if self._sign_form is None:
            return

        def _prompt_and_refresh() -> tuple[str, str] | None:
            result = login_dialog(self.root)
            if result is not None and self._sign_form is not None:
                self._sign_form.refresh_credential_status()
            return result

        start_signing(
            self.root,
            pdf_path=self.pdf_path.get().strip(),
            output_path=self.output_path.get().strip(),
            signing_mode=self.signing_mode.get(),
            position=self.position.get(),
            page=self.page.get().strip(),
            font_key=self.font_key.get(),
            invisible=self.invisible.get(),
            image_path=self.image_path.get().strip(),
            signer_name=self._signer_info.get("name"),
            sign_btn=self._sign_form.sign_btn,
            status_text=self.status_text,
            login_dialog_fn=_prompt_and_refresh,
        )

    # ── Server connection lifecycle ──────────────────────────────

    def _on_connect(self) -> None:
        """Open the connect dialog to select and test a server."""
        ConnectDialog(self.root, on_complete_action=self._on_connect_complete)

    def _on_connect_complete(self) -> None:
        """Refresh UI after server connection."""
        if self._server_bar is not None:
            self._server_bar.refresh()
        self._refresh_sign_tab()
        self._refit_window()

    def _on_disconnect(self) -> None:
        """Disconnect from server, clearing all config."""
        from tkinter import messagebox

        profile = get_active_profile()
        name = profile.display_name if profile else "the server"
        layer = get_config_layer()

        if layer == 2:
            msg = (
                f"Disconnect from {name}?\n\n"
                "This will also remove your credentials\nand signer identity."
            )
        else:
            msg = f"Disconnect from {name}?"

        if not messagebox.askyesno("Revenant", msg):
            return

        self.status_text.set("Disconnecting...")
        self.root.update_idletasks()
        reset_all()
        if self._server_bar is not None:
            self._server_bar.refresh()
        self._refresh_sign_tab()
        self._refit_window()

    # ── Login lifecycle ──────────────────────────────────────────

    def _on_login(self) -> None:
        """Open the login dialog for credentials and identity."""
        LoginDialog(self.root, on_complete_action=self._on_login_complete)

    def _on_login_complete(self) -> None:
        """Refresh UI after login."""
        self._refresh_sign_tab()
        self._refit_window()

    def _on_logout(self) -> None:
        """Clear credentials and identity, keeping server config."""
        from tkinter import messagebox

        if not messagebox.askyesno("Revenant", "Log out?\nServer connection will be preserved."):
            return
        self.status_text.set("Logging out...")
        self.root.update_idletasks()
        logout()
        if self._server_bar is not None:
            self._server_bar.refresh()
        self._refresh_sign_tab()
        self._refit_window()


def _set_windows_icon(root: tk.Tk) -> None:
    """Set the window icon on Windows from the bundled .ico file.

    Nuitka embeds the icon in the PE header (for Explorer/taskbar),
    but tkinter needs a separate .ico file for the window title bar.
    """
    import tkinter as tk
    from pathlib import Path

    # Bundled .ico next to the executable (Nuitka --include-data-files)
    ico = Path(sys.executable).parent / "icons" / "revenant.ico"
    if ico.exists():
        try:
            root.iconbitmap(default=str(ico))
        except tk.TclError:
            _logger.debug("Failed to set icon from bundled .ico")
        else:
            return

    # Fallback: try extracting from the PE header
    try:
        root.iconbitmap(default=sys.executable)
    except (tk.TclError, Exception):
        _logger.debug("Failed to set icon from PE header")


def main() -> None:
    """Launch the Revenant GUI."""
    ok, err = check_tkinter()
    if not ok:
        print(f"ERROR: {err}", file=sys.stderr)
        sys.exit(1)

    # Windows: must be called before tk.Tk() so the OS reports real DPI
    enable_dpi_awareness()

    import tkinter as tk
    from tkinter import ttk

    root = tk.Tk()
    root.withdraw()  # hide until positioned

    # Set window icon (replaces default Tk feather)
    if platform.system() == "Windows":
        _set_windows_icon(root)

    # Try to set a modern theme
    style = ttk.Style(root)
    available = style.theme_names()
    for preferred in ("aqua", "vista", "clam", "default"):
        if preferred in available:
            style.theme_use(preferred)
            break

    # All keychain access is deferred to first use (LoginDialog pre-fill or signing)
    # to avoid triggering a macOS Keychain prompt before the UI appears.
    _logger.info("GUI startup: config=%s", get_server_config())

    _app = RevenantGUI(root)  # must stay alive during mainloop

    # macOS: system menu integration + keyboard shortcut fix for non-Latin layouts
    if platform.system() == "Darwin":
        root.createcommand("tkAboutDialog", lambda: show_about(root))
        root.createcommand("::tk::mac::ShowHelp", lambda: show_about(root))
        bind_macos_shortcuts(root)

    root.mainloop()


if __name__ == "__main__":
    main()
