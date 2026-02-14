# pyright: reportUnknownMemberType=false, reportUnknownArgumentType=false
"""
Standalone verify dialog and formatting helpers for verification results.

Provides:
- ``show_verify_dialog()`` -- opens a file picker + result dialog (welcome screen).
- ``_VerifyResultDialog`` -- modal dialog showing verification results.
- Formatting functions shared between VerifyPanel and _VerifyResultDialog.
"""

from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    import tkinter as tk

    from ...network.soap import ServerVerifyResult

from ...core.pdf import (
    CmsInspection,
    VerificationResult,
    verify_all_embedded_signatures,
)
from ...errors import RevenantError

_logger = logging.getLogger(__name__)


class AppendFn(Protocol):
    """Callback for appending text to a results widget."""

    def __call__(self, text: str, tag: str | None = None) -> None: ...


# Text widget tag colors (shared with VerifyPanel)
COLOR_VALID = "#228B22"
COLOR_FAILED = "#CC0000"
COLOR_HEADER = "#AAAAAA"
COLOR_WARNING = "#CC8800"

# Dialog dimensions
_DIALOG_WIDTH = 520
_DIALOG_HEIGHT = 380


# ── Formatting helpers ───────────────────────────────────────────


def format_results(
    append: AppendFn,
    results: list[VerificationResult],
) -> None:
    """Format embedded verification results using an append callback.

    Shared between VerifyPanel and _VerifyResultDialog.
    """
    from ..workflows import format_verify_results

    vr = format_verify_results(results)

    for entry in vr.entries:
        if vr.total_count > 1:
            append(f"Signature {entry.index + 1}/{entry.total} ({entry.signer_name})\n", "header")

        for line in entry.detail_lines:
            append(f"  {line}\n")

        if entry.valid:
            append("  VALID\n\n", "valid")
        else:
            append("  FAILED\n\n", "failed")

    # Summary
    if vr.all_valid:
        summary = (
            f"All {vr.total_count} signatures VALID" if vr.total_count > 1 else "Signature VALID"
        )
        append(summary + "\n", "valid")
    else:
        append(f"{vr.failed_count} of {vr.total_count} signature(s) FAILED\n", "failed")


def format_detached_result(append: AppendFn, result: VerificationResult) -> None:
    """Format detached signature verification result."""
    append("Detached signature\n", "header")

    for line in result["details"]:
        for sub in line.split("\n"):
            append(f"  {sub}\n")

    if result["valid"]:
        append("\nSignature VALID\n", "valid")
    else:
        append("\nSignature FAILED\n", "failed")


def format_inspection(append: AppendFn, result: CmsInspection) -> None:
    """Format CMS inspection result (no cryptographic verification)."""
    append("Certificate inspection\n", "header")
    append(
        "  Note: cryptographic verification requires the original PDF.\n"
        "  Add the PDF to verify the signature integrity.\n\n",
        "warning",
    )

    for line in result["details"]:
        append(f"  {line}\n")


# ── Server-side verification ──────────────────────────────────────


def try_server_verify(pdf_bytes: bytes) -> ServerVerifyResult | None:
    """Attempt server-side verification if a server is configured.

    Returns None if no server is configured.
    Never raises -- errors are captured in ServerVerifyResult.
    """
    from ...config import get_server_config, register_active_profile_tls

    url, timeout, _ = get_server_config()
    if not url or not timeout:
        return None

    register_active_profile_tls()

    from ...network.soap_transport import verify_pdf_server

    return verify_pdf_server(url, pdf_bytes, timeout)


def format_server_result(append: AppendFn, result: ServerVerifyResult) -> None:
    """Format server verification result using an append callback."""
    append("\nServer verification\n", "header")

    if result.error:
        append(f"  Unavailable: {result.error}\n", "failed")
        return

    if result.signer_name:
        append(f"  Signer: {result.signer_name}\n")
    if result.sign_time:
        append(f"  Signed: {result.sign_time}\n")
    if result.certificate_status:
        append(f"  Certificate: {result.certificate_status}\n")

    if result.valid:
        append("  VALID\n", "valid")
    else:
        append("  FAILED\n", "failed")


# ── Standalone dialog (for welcome screen) ───────────────────────


def show_verify_dialog(parent: tk.Tk | tk.Toplevel) -> None:
    """Open a file picker and verify the selected PDF's signatures.

    Used on the welcome screen where there's no tab to embed into.

    Args:
        parent: Parent window for the file dialog and result window.
    """
    from tkinter import filedialog

    path = filedialog.askopenfilename(
        title="Select PDF to verify",
        filetypes=[("PDF files", "*.pdf"), ("All files", "*.*")],
    )
    if not path:
        return

    _VerifyResultDialog(parent, Path(path))


class _VerifyResultDialog:
    """Modal dialog that verifies a PDF and shows results."""

    def __init__(self, parent: tk.Tk | tk.Toplevel, pdf_path: Path) -> None:
        import tkinter as tk
        from tkinter import ttk

        self._win = tk.Toplevel(parent)
        self._win.withdraw()
        self._win.title("Verify Signature")
        self._win.resizable(True, True)
        self._win.transient(parent)
        self._win.grab_set()

        outer = ttk.Frame(self._win, padding=16)
        outer.grid(sticky="nsew")
        self._win.columnconfigure(0, weight=1)
        self._win.rowconfigure(0, weight=1)
        outer.columnconfigure(0, weight=1)
        outer.rowconfigure(1, weight=1)

        # Header
        from ..helpers import format_size_kb

        try:
            file_size = pdf_path.stat().st_size
            size_str = format_size_kb(file_size)
        except OSError:
            size_str = "?"
        header_text = f"{pdf_path.name} ({size_str})"
        ttk.Label(outer, text=header_text, font=("", 11, "bold")).grid(
            row=0, column=0, sticky="w", pady=(0, 8)
        )

        # Scrolled text area
        text_frame = ttk.Frame(outer)
        text_frame.grid(row=1, column=0, sticky="nsew")
        text_frame.columnconfigure(0, weight=1)
        text_frame.rowconfigure(0, weight=1)

        self._text = tk.Text(
            text_frame,
            wrap="word",
            state="disabled",
            font=("TkDefaultFont", 10),
            padx=8,
            pady=8,
            borderwidth=1,
            relief="sunken",
        )
        scrollbar = ttk.Scrollbar(text_frame, orient="vertical", command=self._text.yview)
        self._text.configure(yscrollcommand=scrollbar.set)
        self._text.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")

        self._text.tag_configure("valid", foreground=COLOR_VALID)
        self._text.tag_configure("failed", foreground=COLOR_FAILED)
        self._text.tag_configure(
            "header", foreground=COLOR_HEADER, font=("TkDefaultFont", 10, "bold")
        )

        # OK button
        ttk.Button(outer, text="OK", command=self._win.destroy).grid(row=2, column=0, pady=(12, 0))

        self._append("Verifying...\n")
        self._pdf_path = pdf_path

        from . import center_on_parent

        self._win.geometry(f"{_DIALOG_WIDTH}x{_DIALOG_HEIGHT}")
        center_on_parent(self._win, parent)

        threading.Thread(target=self._do_verify, daemon=True).start()

    def _append(self, text: str, tag: str | None = None) -> None:
        self._text.configure(state="normal")
        if tag:
            self._text.insert("end", text, tag)
        else:
            self._text.insert("end", text)
        self._text.configure(state="disabled")
        self._text.see("end")

    def _clear(self) -> None:
        self._text.configure(state="normal")
        self._text.delete("1.0", "end")
        self._text.configure(state="disabled")

    def _do_verify(self) -> None:
        try:
            pdf_bytes = self._pdf_path.read_bytes()
        except OSError as e:
            msg = f"Cannot read file: {e}"
            self._win.after(0, lambda m=msg: self._show_error(m))
            return

        try:
            results = verify_all_embedded_signatures(pdf_bytes)
        except RevenantError as e:
            msg = str(e)
            self._win.after(0, lambda m=msg: self._show_error(m))
            return
        except Exception as e:
            _logger.exception("Unexpected error during verification")
            msg = f"Unexpected error: {e}"
            self._win.after(0, lambda m=msg: self._show_error(m))
            return

        server_result = try_server_verify(pdf_bytes)
        self._win.after(0, lambda r=results, s=server_result: self._show_results(r, s))

    def _show_error(self, message: str) -> None:
        self._clear()
        self._append(message + "\n", "failed")

    def _show_results(
        self,
        results: list[VerificationResult],
        server_result: ServerVerifyResult | None = None,
    ) -> None:
        self._clear()
        format_results(self._append, results)
        if server_result is not None:
            format_server_result(self._append, server_result)
