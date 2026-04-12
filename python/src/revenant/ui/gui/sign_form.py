# SPDX-License-Identifier: Apache-2.0
# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false
"""Sign form panel -- file pickers, signature options, and account info."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any  # Any: tkinter grid() kwargs require it

if TYPE_CHECKING:
    import tkinter as tk
    from collections.abc import Callable

from ...config import get_active_profile
from ...core.appearance import AVAILABLE_FONTS
from .i18n import _
from .position_preview import PREVIEW_H, PREVIEW_W, draw_position_preview
from .sign_panels import build_account_panel

# Page/position display: translated labels mapped to internal keys.
# All _() calls use string literals so the i18n consistency checker finds them.


def _page_pairs() -> list[tuple[str, str]]:
    """Return (internal_key, display_label) pairs for page choices."""
    return [
        ("last", _("gui.page_last")),
        ("first", _("gui.page_first")),
        ("1", "1"),
        ("2", "2"),
        ("3", "3"),
        ("4", "4"),
        ("5", "5"),
    ]


def page_display_values() -> list[str]:
    return [display for _, display in _page_pairs()]


def page_key_from_display(display: str) -> str:
    for key, label in _page_pairs():
        if label == display:
            return key
    return display


def page_display_from_key(key: str) -> str:
    for k, label in _page_pairs():
        if k == key:
            return label
    return key


def _position_pairs() -> list[tuple[str, str]]:
    """Return (internal_key, display_label) pairs for positions, sorted by key."""
    pairs = [
        ("bottom-center", _("gui.pos_bottom_center")),
        ("bottom-left", _("gui.pos_bottom_left")),
        ("bottom-right", _("gui.pos_bottom_right")),
        ("top-left", _("gui.pos_top_left")),
        ("top-right", _("gui.pos_top_right")),
    ]
    pairs.sort(key=lambda p: p[0])
    return pairs


def position_display_names() -> list[str]:
    return [display for _, display in _position_pairs()]


def position_key_from_display(display: str) -> str:
    for key, label in _position_pairs():
        if label == display:
            return key
    return display


def position_display_from_key(key: str) -> str:
    for k, label in _position_pairs():
        if k == key:
            return label
    return key


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
        reason: tk.StringVar,
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
        self._reason = reason
        self._status_text = status_text
        self._signer_info = signer_info
        self._on_sign_action = on_sign_action
        self._on_logout_action = on_logout_action
        self._auto_output = ""
        self._file_paths: list[str] = []

        self._build(parent)

    @property
    def pdf_paths(self) -> list[str]:
        """Return selected PDF file paths (1 for single, N for batch)."""
        if self._file_paths:
            return list(self._file_paths)
        # Fallback: single-file mode via StringVar
        path = self._pdf_path.get().strip()
        return [path] if path else []

    def _build(self, tab: tk.Widget) -> None:
        """Build the signing form inside the Sign tab."""
        from tkinter import ttk

        # Any: tkinter stubs don't support typed **kwargs unpacking for grid()
        pad: dict[str, Any] = {"padx": 8, "pady": 4}
        frame = ttk.Frame(tab, padding=12)
        frame.pack(fill="both", expand=True)
        frame.columnconfigure(1, weight=1)

        row = 0

        # File picker: PDF(s)
        ttk.Label(frame, text=_("gui.pdf_file_label")).grid(row=row, column=0, sticky="ne", **pad)

        file_frame = ttk.Frame(frame)
        file_frame.grid(row=row, column=1, sticky="ew", **pad)
        file_frame.columnconfigure(0, weight=1)

        self._pdf_entry = ttk.Entry(file_frame, textvariable=self._pdf_path)
        self._pdf_entry.grid(row=0, column=0, sticky="ew")

        import tkinter as real_tk

        self._file_listbox = real_tk.Listbox(file_frame, height=3, selectmode="extended")
        # Listbox hidden by default -- shown when multiple files selected
        self._file_listbox_visible = False

        btn_frame = ttk.Frame(frame)
        btn_frame.grid(row=row, column=2, **pad)
        ttk.Button(btn_frame, text=_("gui.browse_ellipsis"), command=self._browse_pdf).pack(
            side="top", fill="x"
        )
        self._remove_btn = ttk.Button(
            btn_frame, text=_("gui.remove"), command=self._remove_selected_files
        )
        row += 1

        # Image picker
        self._image_entry = ttk.Entry(frame, textvariable=self._image_path)
        self._image_entry.grid(row=row, column=1, sticky="ew", **pad)
        ttk.Label(frame, text=_("gui.image_opt_label")).grid(row=row, column=0, sticky="e", **pad)
        self._image_browse_btn = ttk.Button(
            frame, text=_("gui.browse_ellipsis"), command=self._browse_image
        )
        self._image_browse_btn.grid(row=row, column=2, **pad)
        row += 1

        # Output path (hidden in batch mode)
        self._output_row = row
        self._output_label = ttk.Label(frame, text=_("gui.output_opt_label"))
        self._output_label.grid(row=row, column=0, sticky="e", **pad)
        self._output_entry = ttk.Entry(frame, textvariable=self._output_path)
        self._output_entry.grid(row=row, column=1, sticky="ew", **pad)
        self._output_browse_btn = ttk.Button(
            frame, text=_("gui.browse_ellipsis"), command=self._browse_output
        )
        self._output_browse_btn.grid(row=row, column=2, **pad)
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

        # Left: Signature options (settings + position preview)
        left = ttk.LabelFrame(cols, text=_("gui.signature"), padding=8, labelanchor="n")
        left.grid(row=0, column=0, sticky="nsew")

        # Settings sub-frame on the left side
        settings = ttk.Frame(left)
        settings.pack(side="left", fill="y")

        # Mode selector
        mode_frame = ttk.Frame(settings)
        mode_frame.grid(row=0, column=0, columnspan=2, sticky="w", **opt_pad)
        ttk.Radiobutton(
            mode_frame,
            text=_("gui.embedded"),
            variable=self._signing_mode,
            value="embedded",
            command=self._on_mode_change,
        ).pack(side="left", padx=(0, 12))
        ttk.Radiobutton(
            mode_frame,
            text=_("gui.detached_p7s"),
            variable=self._signing_mode,
            value="detached",
            command=self._on_mode_change,
        ).pack(side="left")

        # Set the display name for the current position
        self._position.set(position_display_from_key(self._position.get()))
        self._pos_combo = ttk.Combobox(
            settings, textvariable=self._position, values=position_display_names(), state="readonly"
        )
        ttk.Label(settings, text=_("gui.position_label")).grid(
            row=1, column=0, sticky="e", **opt_pad
        )
        self._pos_combo.grid(row=1, column=1, sticky="w", **opt_pad)

        self._page.set(page_display_from_key(self._page.get()))
        page_validate = frame.register(self._validate_page)
        self._page_combo = ttk.Combobox(
            settings,
            textvariable=self._page,
            values=page_display_values(),
            validate="key",
            validatecommand=(page_validate, "%P"),
        )
        ttk.Label(settings, text=_("gui.page_label")).grid(row=2, column=0, sticky="e", **opt_pad)
        self._page_combo.grid(row=2, column=1, sticky="w", **opt_pad)

        profile = get_active_profile()
        default_font = profile.font if profile else "noto-sans"
        self._font_key.set(default_font)
        self._font_combo = ttk.Combobox(
            settings,
            textvariable=self._font_key,
            values=list(AVAILABLE_FONTS),
            state="readonly",
        )
        ttk.Label(settings, text=_("gui.font_label")).grid(row=3, column=0, sticky="e", **opt_pad)
        self._font_combo.grid(row=3, column=1, sticky="w", **opt_pad)

        self._invisible_cb = ttk.Checkbutton(
            settings,
            text=_("gui.invisible_signature"),
            variable=self._invisible,
            command=self._on_invisible_toggle,
        )
        self._invisible_cb.grid(row=4, column=0, columnspan=2, sticky="w", **opt_pad)

        self._reason_entry = ttk.Entry(settings, textvariable=self._reason)
        ttk.Label(settings, text=_("gui.reason_label")).grid(row=5, column=0, sticky="e", **opt_pad)
        self._reason_entry.grid(row=5, column=1, sticky="w", **opt_pad)

        # Position preview canvas on the right side
        import tkinter as real_tk

        self._preview = real_tk.Canvas(
            left,
            width=PREVIEW_W,
            height=PREVIEW_H,
            highlightthickness=1,
            highlightbackground="#ccc",
        )
        self._preview.pack(side="right", padx=(8, 0), pady=4)
        self._draw_position_preview()
        self._pos_combo.bind("<<ComboboxSelected>>", lambda _: self._draw_position_preview())

        # Right: Account info (server name is in ServerBar, not duplicated here)
        right = ttk.LabelFrame(cols, text=_("gui.account"), padding=8, labelanchor="n")
        right.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
        self._storage_var = build_account_panel(right, self._signer_info, self._on_logout_action)

        # ── Sign button ──────────────────────────────────────────
        self.sign_btn = ttk.Button(
            frame, text=_("gui.sign_pdf"), command=self._on_sign_action, style="Accent.TButton"
        )
        self.sign_btn.grid(row=row, column=0, columnspan=3, pady=12, ipady=6)
        row += 1

        # ── Status bar ────────────────────────────────────────────
        ttk.Label(frame, textvariable=self._status_text, foreground="gray", wraplength=400).grid(
            row=row, column=0, columnspan=3, sticky="ew", **pad
        )

    def refresh_credential_status(self) -> None:
        """Update the credential storage label to reflect current state."""
        from ...config import get_credential_storage_info

        self._storage_var.set(get_credential_storage_info())

    def confirm_output_for_sandbox(self) -> bool:
        """Ensure sandbox write permission for the output file.

        When the output path was auto-generated (not chosen via Browse), the
        macOS sandbox has not granted write access to that path.  Show a Save
        Panel pre-filled with the auto-generated name so the user confirms the
        location — the system save panel is what grants the write permission.

        Returns True if the caller should proceed, False if user cancelled.
        """
        if not self._auto_output:
            # Path was explicitly chosen via Browse — already has permission.
            return True

        from pathlib import Path
        from tkinter import filedialog

        current = self._output_path.get().strip()
        is_detached = self._signing_mode.get() == "detached"
        initial_dir = str(Path(current).parent) if current else ""
        initial_file = Path(current).name if current else ""

        if is_detached:
            path = filedialog.asksaveasfilename(
                title=_("gui.save_signature_as"),
                initialdir=initial_dir,
                initialfile=initial_file,
                defaultextension=".p7s",
                filetypes=[(_("gui.pkcs_7_signature"), "*.p7s"), (_("gui.all_files"), "*.*")],
            )
        else:
            path = filedialog.asksaveasfilename(
                title=_("gui.save_signed_pdf_as"),
                initialdir=initial_dir,
                initialfile=initial_file,
                defaultextension=".pdf",
                filetypes=[(_("gui.pdf_files"), "*.pdf")],
            )

        if not path:
            return False

        self._output_path.set(path)
        self._auto_output = ""  # Now user-confirmed
        return True

    # ── Position preview ───────────────────────────────────────────

    def _draw_position_preview(self) -> None:
        """Draw a mini page diagram showing where the signature stamp will land."""
        key = position_key_from_display(self._position.get())
        draw_position_preview(self._preview, key)

    # ── Form state handlers ──────────────────────────────────────

    @staticmethod
    def _validate_page(value: str) -> bool:
        """Allow empty, digits, or partial matches of translated page names."""
        if not value:
            return True
        if value.isdigit():
            return True
        lower = value.lower()
        # Allow typing translated "first"/"last" character by character
        first_display = _("gui.page_first").lower()
        last_display = _("gui.page_last").lower()
        return (
            first_display.startswith(lower)
            or last_display.startswith(lower)
            or "first".startswith(lower)
            or "last".startswith(lower)
        )

    def _on_invisible_toggle(self) -> None:
        """Enable/disable visual controls based on invisible checkbox."""
        # In detached mode, appearance controls stay disabled regardless
        if self._signing_mode.get() == "detached":
            return
        if self._invisible.get():
            self._pos_combo.configure(state="disabled")
            self._page_combo.configure(state="disabled")
            self._font_combo.configure(state="disabled")
            self._preview.pack_forget()
        else:
            self._pos_combo.configure(state="readonly")
            self._page_combo.configure(state="normal")
            self._font_combo.configure(state="readonly")
            self._preview.pack(side="right", padx=(8, 0), pady=4)
            self._draw_position_preview()

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
            self._preview.pack_forget()
            self.sign_btn.configure(text=_("gui.sign_detached"))
        else:
            # Restore controls, respecting invisible checkbox state
            self._invisible_cb.configure(state="normal")
            self._image_entry.configure(state="normal")
            self._image_browse_btn.configure(state="normal")
            self._on_invisible_toggle()
            if not self._invisible.get():
                self._preview.pack(side="right", padx=(8, 0), pady=4)
                self._draw_position_preview()
            self.sign_btn.configure(text=_("gui.sign_pdf"))

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

        paths = filedialog.askopenfilenames(
            title=_("gui.select_pdf"),
            filetypes=[(_("gui.pdf_files"), "*.pdf"), (_("gui.all_files"), "*.*")],
        )
        if not paths:
            return

        if len(paths) == 1 and not self._file_paths:
            # Single file selected, no existing batch -- use simple mode
            self._pdf_path.set(paths[0])
            self._file_paths = []
            self._switch_to_single_mode()
            if not self._output_path.get():
                self._auto_fill_output(paths[0])
        else:
            # Multiple files or adding to existing batch
            for p in paths:
                if p not in self._file_paths:
                    self._file_paths.append(p)
            if len(self._file_paths) == 1:
                self._pdf_path.set(self._file_paths[0])
                self._switch_to_single_mode()
            else:
                self._switch_to_batch_mode()

    def _remove_selected_files(self) -> None:
        """Remove selected files from the batch listbox."""
        selection = list(self._file_listbox.curselection())
        for idx in reversed(selection):
            self._file_paths.pop(idx)
            self._file_listbox.delete(idx)

        if len(self._file_paths) <= 1:
            if self._file_paths:
                self._pdf_path.set(self._file_paths[0])
            self._file_paths = []
            self._switch_to_single_mode()

    def _switch_to_batch_mode(self) -> None:
        """Switch UI to multi-file mode."""
        self._pdf_entry.grid_remove()
        if not self._file_listbox_visible:
            self._file_listbox.grid(row=0, column=0, sticky="ew")
            self._remove_btn.pack(side="top", fill="x", pady=(2, 0))
            self._file_listbox_visible = True
        self._file_listbox.delete(0, "end")
        for p in self._file_paths:
            self._file_listbox.insert("end", Path(p).name)
        # Hide output row in batch mode (auto-generated per file)
        self._output_label.grid_remove()
        self._output_entry.grid_remove()
        self._output_browse_btn.grid_remove()
        self.sign_btn.configure(text=_("gui.sign_n_pdfs").format(n=len(self._file_paths)))

    def _switch_to_single_mode(self) -> None:
        """Switch UI back to single-file mode."""
        if self._file_listbox_visible:
            self._file_listbox.grid_remove()
            self._remove_btn.pack_forget()
            self._file_listbox_visible = False
        self._pdf_entry.grid(row=0, column=0, sticky="ew")
        # Restore output row
        pad: dict[str, Any] = {"padx": 8, "pady": 4}
        self._output_label.grid(row=self._output_row, column=0, sticky="e", **pad)
        self._output_entry.grid(row=self._output_row, column=1, sticky="ew", **pad)
        self._output_browse_btn.grid(row=self._output_row, column=2, **pad)
        self.sign_btn.configure(text=_("gui.sign_pdf"))

    def _auto_fill_output(self, pdf_path: str) -> None:
        """Auto-fill output path from input PDF path."""
        from ..helpers import default_detached_output_path, default_output_path

        pdf_p = Path(pdf_path)
        if self._signing_mode.get() == "detached":
            auto = str(default_detached_output_path(pdf_p))
        else:
            auto = str(default_output_path(pdf_p))
        self._output_path.set(auto)
        self._auto_output = auto

    def _browse_image(self) -> None:
        from tkinter import filedialog

        path = filedialog.askopenfilename(
            title=_("gui.select_signature_image"),
            filetypes=[(_("gui.images"), "*.png *.jpg *.jpeg"), (_("gui.all_files"), "*.*")],
        )
        if path:
            self._image_path.set(path)

    def _browse_output(self) -> None:
        from tkinter import filedialog

        if self._signing_mode.get() == "detached":
            path = filedialog.asksaveasfilename(
                title=_("gui.save_signature_as"),
                defaultextension=".p7s",
                filetypes=[(_("gui.pkcs_7_signature"), "*.p7s"), (_("gui.all_files"), "*.*")],
            )
        else:
            path = filedialog.asksaveasfilename(
                title=_("gui.save_signed_pdf_as"),
                defaultextension=".pdf",
                filetypes=[(_("gui.pdf_files"), "*.pdf")],
            )
        if path:
            self._output_path.set(path)
            self._auto_output = ""  # User chose manually
