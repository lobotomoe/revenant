"""Sign form panel -- file pickers, signature options, and account info."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import tkinter as tk
    from collections.abc import Callable

from ...config import (
    get_active_profile,
    get_credential_storage_info,
)
from ...core.appearance import AVAILABLE_FONTS, extract_cert_fields
from ...core.pdf import POSITION_PRESETS

# Position labels for the dropdown (full names only, sorted)
_POSITIONS = sorted(POSITION_PRESETS)

# Page choices (1-based for user display, converted to 0-based internally)
_PAGES = ["last", "first", "1", "2", "3", "4", "5"]


def build_unconfigured(parent: tk.Widget, on_connect_action: Callable[[], None]) -> None:
    """Build the Sign tab for unconfigured state (Layer 0: connect prompt)."""
    from tkinter import ttk

    frame = ttk.Frame(parent, padding=40)
    frame.pack(fill="both", expand=True)
    frame.columnconfigure(0, weight=1)

    ttk.Label(
        frame,
        text="Connect to a server\nto sign documents.",
        justify="center",
        foreground="gray",
    ).grid(row=0, column=0, pady=(0, 20))
    ttk.Button(frame, text="Connect", command=on_connect_action, style="Accent.TButton").grid(
        row=1, column=0, ipady=4, ipadx=16
    )


def build_server_only(parent: tk.Widget, on_login_action: Callable[[], None]) -> None:
    """Build the Sign tab for server-configured state (Layer 1: login prompt).

    Server is connected but no credentials/identity configured yet.
    """
    from tkinter import ttk

    frame = ttk.Frame(parent, padding=40)
    frame.pack(fill="both", expand=True)
    frame.columnconfigure(0, weight=1)

    ttk.Label(
        frame,
        text="Server connected.\nLog in to sign documents.",
        justify="center",
        foreground="gray",
    ).grid(row=0, column=0, pady=(0, 20))
    ttk.Button(frame, text="Log In", command=on_login_action, style="Accent.TButton").grid(
        row=1, column=0, ipady=4, ipadx=16
    )


class SignForm:
    """Sign tab content: file pickers, signature settings, and account info.

    Follows the VerifyPanel pattern -- self-contained panel that receives
    parent/root refs and manages its own state/UI.
    """

    def __init__(
        self,
        parent: tk.Widget,
        root: tk.Tk,
        *,
        pdf_path: tk.StringVar,
        image_path: tk.StringVar,
        output_path: tk.StringVar,
        signing_mode: tk.StringVar,
        position: tk.StringVar,
        page: tk.StringVar,
        font_key: tk.StringVar,
        invisible: tk.BooleanVar,
        status_text: tk.StringVar,
        signer_info: dict[str, str | None],
        on_sign_action: Callable[[], None],
        on_logout_action: Callable[[], None],
    ) -> None:
        self._root = root
        self._pdf_path = pdf_path
        self._image_path = image_path
        self._output_path = output_path
        self._signing_mode = signing_mode
        self._position = position
        self._page = page
        self._font_key = font_key
        self._invisible = invisible
        self._status_text = status_text
        self._signer_info = signer_info
        self._on_sign_action = on_sign_action
        self._on_logout_action = on_logout_action
        self._auto_output = ""

        self._build(parent)

    def _build(self, tab: tk.Widget) -> None:
        """Build the signing form inside the Sign tab."""
        from tkinter import ttk

        # Any: tkinter stubs don't support typed **kwargs unpacking for grid()
        pad: dict[str, Any] = {"padx": 8, "pady": 4}
        frame = ttk.Frame(tab, padding=12)
        frame.pack(fill="both", expand=True)
        frame.columnconfigure(1, weight=1)

        row = 0

        # File pickers: PDF, image, output
        ttk.Label(frame, text="PDF file:").grid(row=row, column=0, sticky="e", **pad)
        ttk.Entry(frame, textvariable=self._pdf_path).grid(row=row, column=1, sticky="ew", **pad)
        ttk.Button(frame, text="Browse...", command=self._browse_pdf).grid(row=row, column=2, **pad)
        row += 1

        self._image_entry = ttk.Entry(frame, textvariable=self._image_path)
        self._image_entry.grid(row=row, column=1, sticky="ew", **pad)
        ttk.Label(frame, text="Image (opt):").grid(row=row, column=0, sticky="e", **pad)
        self._image_browse_btn = ttk.Button(frame, text="Browse...", command=self._browse_image)
        self._image_browse_btn.grid(row=row, column=2, **pad)
        row += 1

        ttk.Label(frame, text="Output (opt):").grid(row=row, column=0, sticky="e", **pad)
        ttk.Entry(frame, textvariable=self._output_path).grid(row=row, column=1, sticky="ew", **pad)
        ttk.Button(frame, text="Browse...", command=self._browse_output).grid(
            row=row, column=2, **pad
        )
        row += 1

        ttk.Separator(frame, orient="horizontal").grid(
            row=row, column=0, columnspan=3, sticky="ew", pady=8
        )
        row += 1

        # ── Two-column layout: Signature options | Account info ──
        cols = ttk.Frame(frame)
        cols.grid(row=row, column=0, columnspan=3, sticky="nsew")
        cols.columnconfigure(0, weight=1, uniform="half")
        cols.columnconfigure(1, weight=1, uniform="half")
        row += 1

        opt_pad: dict[str, Any] = {"padx": 4, "pady": 3}

        # Add bottom margin below LabelFrame titles
        ttk.Style().configure("TLabelframe", labelmargins=[0, 0, 0, 6])

        # Left: Signature options
        left = ttk.LabelFrame(cols, text="Signature", padding=8, labelanchor="n")
        left.grid(row=0, column=0, sticky="nsew")
        left.columnconfigure(1, weight=1)

        # Mode selector
        mode_frame = ttk.Frame(left)
        mode_frame.grid(row=0, column=0, columnspan=2, sticky="w", **opt_pad)
        ttk.Radiobutton(
            mode_frame,
            text="Embedded",
            variable=self._signing_mode,
            value="embedded",
            command=self._on_mode_change,
        ).pack(side="left", padx=(0, 12))
        ttk.Radiobutton(
            mode_frame,
            text="Detached (.p7s)",
            variable=self._signing_mode,
            value="detached",
            command=self._on_mode_change,
        ).pack(side="left")

        self._pos_combo = ttk.Combobox(
            left, textvariable=self._position, values=_POSITIONS, state="readonly"
        )
        ttk.Label(left, text="Position:").grid(row=1, column=0, sticky="e", **opt_pad)
        self._pos_combo.grid(row=1, column=1, sticky="ew", **opt_pad)

        page_validate = frame.register(self._validate_page)
        self._page_combo = ttk.Combobox(
            left,
            textvariable=self._page,
            values=_PAGES,
            validate="key",
            validatecommand=(page_validate, "%P"),
        )
        ttk.Label(left, text="Page:").grid(row=2, column=0, sticky="e", **opt_pad)
        self._page_combo.grid(row=2, column=1, sticky="ew", **opt_pad)

        profile = get_active_profile()
        default_font = profile.font if profile else "noto-sans"
        self._font_key.set(default_font)
        self._font_combo = ttk.Combobox(
            left,
            textvariable=self._font_key,
            values=list(AVAILABLE_FONTS),
            state="readonly",
        )
        ttk.Label(left, text="Font:").grid(row=3, column=0, sticky="e", **opt_pad)
        self._font_combo.grid(row=3, column=1, sticky="ew", **opt_pad)

        self._invisible_cb = ttk.Checkbutton(
            left,
            text="Invisible signature",
            variable=self._invisible,
            command=self._on_invisible_toggle,
        )
        self._invisible_cb.grid(row=4, column=0, columnspan=2, sticky="w", **opt_pad)

        # Right: Account info (server name is in ServerBar, not duplicated here)
        right = ttk.LabelFrame(cols, text="Account", padding=8, labelanchor="n")
        right.grid(row=0, column=1, sticky="nsew", padx=(8, 0))

        info_row = 0
        if profile and profile.cert_fields:
            extracted = extract_cert_fields(profile.cert_fields, self._signer_info)
            for cf in profile.cert_fields:
                value = extracted.get(cf.id)
                if value:
                    ttk.Label(right, text=f"{cf.label}:", foreground="gray").grid(
                        row=info_row, column=0, sticky="e", padx=(0, 4), pady=1
                    )
                    ttk.Label(right, text=value).grid(row=info_row, column=1, sticky="w", pady=1)
                    info_row += 1
        else:
            # Fallback for custom servers: raw name, org, email
            for key, label in [("name", "Name"), ("organization", "Org"), ("email", "Email")]:
                val = self._signer_info.get(key)
                if val:
                    ttk.Label(right, text=f"{label}:", foreground="gray").grid(
                        row=info_row, column=0, sticky="e", padx=(0, 4), pady=1
                    )
                    ttk.Label(right, text=val).grid(row=info_row, column=1, sticky="w", pady=1)
                    info_row += 1

        if info_row == 0:
            ttk.Label(right, text="(no signer)", foreground="gray").grid(
                row=info_row, column=0, columnspan=2, sticky="w", pady=1
            )
            info_row += 1

        import tkinter as tk

        self._storage_var = tk.StringVar(value=get_credential_storage_info())
        ttk.Label(right, textvariable=self._storage_var, foreground="gray").grid(
            row=info_row, column=0, columnspan=2, sticky="w", pady=1
        )

        ttk.Button(right, text="Log Out", command=self._on_logout_action).grid(
            row=info_row + 1, column=0, columnspan=2, sticky="w", pady=(6, 0)
        )

        # ── Sign button ──────────────────────────────────────────
        self.sign_btn = ttk.Button(
            frame, text="Sign PDF", command=self._on_sign_action, style="Accent.TButton"
        )
        self.sign_btn.grid(row=row, column=0, columnspan=3, pady=12, ipady=6)
        row += 1

        # ── Status bar ────────────────────────────────────────────
        ttk.Label(frame, textvariable=self._status_text, foreground="gray", wraplength=400).grid(
            row=row, column=0, columnspan=3, sticky="ew", **pad
        )

    def refresh_credential_status(self) -> None:
        """Update the credential storage label to reflect current state."""
        self._storage_var.set(get_credential_storage_info())

    # ── Form state handlers ──────────────────────────────────────

    @staticmethod
    def _validate_page(value: str) -> bool:
        """Allow empty, digits, or partial matches of 'first'/'last'."""
        if not value:
            return True
        if value.isdigit():
            return True
        # Allow typing "first" or "last" character by character
        return "first".startswith(value.lower()) or "last".startswith(value.lower())

    def _on_invisible_toggle(self) -> None:
        """Enable/disable visual controls based on invisible checkbox."""
        # In detached mode, appearance controls stay disabled regardless
        if self._signing_mode.get() == "detached":
            return
        if self._invisible.get():
            self._pos_combo.configure(state="disabled")
            self._page_combo.configure(state="disabled")
            self._font_combo.configure(state="disabled")
        else:
            self._pos_combo.configure(state="readonly")
            self._page_combo.configure(state="normal")
            self._font_combo.configure(state="readonly")

    def _on_mode_change(self) -> None:
        """Toggle appearance controls and output path based on signing mode."""
        detached = self._signing_mode.get() == "detached"

        if detached:
            # Disable all appearance controls
            self._pos_combo.configure(state="disabled")
            self._page_combo.configure(state="disabled")
            self._font_combo.configure(state="disabled")
            self._invisible_cb.configure(state="disabled")
            self._image_entry.configure(state="disabled")
            self._image_browse_btn.configure(state="disabled")
            self.sign_btn.configure(text="Sign (Detached)")
        else:
            # Restore controls, respecting invisible checkbox state
            self._invisible_cb.configure(state="normal")
            self._image_entry.configure(state="normal")
            self._image_browse_btn.configure(state="normal")
            self._on_invisible_toggle()
            self.sign_btn.configure(text="Sign PDF")

        self._update_auto_output()

    def _update_auto_output(self) -> None:
        """Recalculate auto-generated output path based on current mode."""
        pdf = self._pdf_path.get().strip()
        if not pdf:
            return

        current_output = self._output_path.get().strip()
        # Only auto-update if empty or matches previous auto-value
        if current_output and current_output != self._auto_output:
            return

        from ..helpers import default_detached_output_path, default_output_path

        pdf_p = Path(pdf)
        if self._signing_mode.get() == "detached":
            new_output = str(default_detached_output_path(pdf_p))
        else:
            new_output = str(default_output_path(pdf_p))

        self._output_path.set(new_output)
        self._auto_output = new_output

    # ── File dialogs ──────────────────────────────────────────────

    def _browse_pdf(self) -> None:
        from tkinter import filedialog

        path = filedialog.askopenfilename(
            title="Select PDF", filetypes=[("PDF files", "*.pdf"), ("All files", "*.*")]
        )
        if not path:
            return
        self._pdf_path.set(path)
        if not self._output_path.get():
            from ..helpers import default_detached_output_path, default_output_path

            pdf_p = Path(path)
            if self._signing_mode.get() == "detached":
                auto = str(default_detached_output_path(pdf_p))
            else:
                auto = str(default_output_path(pdf_p))
            self._output_path.set(auto)
            self._auto_output = auto

    def _browse_image(self) -> None:
        from tkinter import filedialog

        path = filedialog.askopenfilename(
            title="Select signature image",
            filetypes=[("Images", "*.png *.jpg *.jpeg"), ("All files", "*.*")],
        )
        if path:
            self._image_path.set(path)

    def _browse_output(self) -> None:
        from tkinter import filedialog

        if self._signing_mode.get() == "detached":
            path = filedialog.asksaveasfilename(
                title="Save signature as",
                defaultextension=".p7s",
                filetypes=[("PKCS#7 signature", "*.p7s"), ("All files", "*.*")],
            )
        else:
            path = filedialog.asksaveasfilename(
                title="Save signed PDF as",
                defaultextension=".pdf",
                filetypes=[("PDF files", "*.pdf")],
            )
        if path:
            self._output_path.set(path)
            self._auto_output = ""  # User chose manually
