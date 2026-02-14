# pyright: reportUnknownMemberType=false, reportUnknownArgumentType=false
"""
Verify panel for the Revenant GUI main window.

Inline tab panel embedded in the main screen's Notebook widget.
Supports three verification modes:
- Embedded: PDF with embedded signatures (PDF only)
- Detached: PDF + .p7s file (cryptographic verification)
- Inspect: .p7s only (certificate info, no crypto verification)

The standalone dialog for the welcome screen lives in ``verify_dialog``.
"""

from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import tkinter as tk

    from ...network.soap import ServerVerifyResult

from ...core.pdf import (
    CmsInspection,
    VerificationResult,
    verify_all_embedded_signatures,
    verify_detached_signature,
)
from ...errors import RevenantError
from .verify_dialog import (
    COLOR_FAILED,
    COLOR_HEADER,
    COLOR_VALID,
    COLOR_WARNING,
    format_detached_result,
    format_inspection,
    format_results,
    format_server_result,
    try_server_verify,
)

_logger = logging.getLogger(__name__)


class VerifyPanel:
    """Inline verification UI with file pickers, verify button, and results area.

    Supports embedded (PDF only), detached (PDF + .p7s), and
    inspect-only (.p7s only) modes.
    """

    def __init__(self, parent: tk.Widget, root: tk.Tk) -> None:
        import tkinter as tk
        from tkinter import ttk

        self._root = root

        frame = ttk.Frame(parent, padding=12)
        frame.pack(fill="both", expand=True)
        frame.columnconfigure(1, weight=1)

        # Any: tkinter stubs don't support typed **kwargs unpacking for grid()
        pad: dict[str, Any] = {"padx": 8, "pady": 4}

        # ── File picker: PDF ──────────────────────────────────────
        self._pdf_var = tk.StringVar()
        ttk.Label(frame, text="PDF file:").grid(row=0, column=0, sticky="e", **pad)
        ttk.Entry(frame, textvariable=self._pdf_var).grid(row=0, column=1, sticky="ew", **pad)
        ttk.Button(frame, text="Browse...", command=self._browse_pdf).grid(row=0, column=2, **pad)

        # ── File picker: Signature (.p7s) ─────────────────────────
        self._sig_var = tk.StringVar()
        ttk.Label(frame, text="Signature (.p7s):").grid(row=1, column=0, sticky="e", **pad)
        ttk.Entry(frame, textvariable=self._sig_var).grid(row=1, column=1, sticky="ew", **pad)
        ttk.Button(frame, text="Browse...", command=self._browse_sig).grid(row=1, column=2, **pad)

        # ── Verify button ────────────────────────────────────────
        self._verify_btn = ttk.Button(
            frame, text="Verify", command=self._on_verify, style="Accent.TButton"
        )
        self._verify_btn.grid(row=2, column=0, columnspan=3, pady=(8, 8), ipady=4)

        # ── Results area ─────────────────────────────────────────
        results_frame = ttk.Frame(frame)
        results_frame.grid(row=3, column=0, columnspan=3, sticky="nsew")
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)
        frame.rowconfigure(3, weight=1)

        self._text = tk.Text(
            results_frame,
            wrap="word",
            state="disabled",
            font=("TkDefaultFont", 10),
            padx=8,
            pady=8,
            borderwidth=1,
            relief="sunken",
            width=40,
            height=8,
        )
        scrollbar = ttk.Scrollbar(results_frame, orient="vertical", command=self._text.yview)
        self._text.configure(yscrollcommand=scrollbar.set)
        self._text.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")

        self._text.tag_configure("valid", foreground=COLOR_VALID)
        self._text.tag_configure("failed", foreground=COLOR_FAILED)
        self._text.tag_configure("warning", foreground=COLOR_WARNING)
        self._text.tag_configure(
            "header", foreground=COLOR_HEADER, font=("TkDefaultFont", 10, "bold")
        )
        self._text.tag_configure("placeholder", foreground="#999999")

        # Initial placeholder
        self._text.configure(state="normal")
        self._text.insert(
            "end",
            "Select a PDF file and click Verify to check signatures.\n\n"
            "Modes:\n"
            "  PDF only -- verify embedded signatures\n"
            "  PDF + .p7s -- verify detached signature\n"
            "  .p7s only -- inspect certificate (no crypto verification)",
            "placeholder",
        )
        self._text.configure(state="disabled")

    # ── File dialogs ──────────────────────────────────────────────

    def _browse_pdf(self) -> None:
        from tkinter import filedialog

        path = filedialog.askopenfilename(
            title="Select PDF to verify",
            filetypes=[("PDF files", "*.pdf"), ("All files", "*.*")],
        )
        if not path:
            return
        self._pdf_var.set(path)
        # Auto-fill .p7s if a matching file exists
        if not self._sig_var.get().strip():
            p7s_path = Path(path).with_suffix(".pdf.p7s")
            if p7s_path.is_file():
                self._sig_var.set(str(p7s_path))

    def _browse_sig(self) -> None:
        from tkinter import filedialog

        path = filedialog.askopenfilename(
            title="Select signature file",
            filetypes=[("PKCS#7 signatures", "*.p7s"), ("All files", "*.*")],
        )
        if not path:
            return
        self._sig_var.set(path)
        # Auto-fill PDF if a matching file exists
        if not self._pdf_var.get().strip():
            sig_p = Path(path)
            # document.pdf.p7s -> document.pdf
            if sig_p.suffixes == [".pdf", ".p7s"]:
                pdf_path = sig_p.with_suffix("")  # strip .p7s
                if pdf_path.is_file():
                    self._pdf_var.set(str(pdf_path))

    # ── Verify dispatch ───────────────────────────────────────────

    def _on_verify(self) -> None:
        from tkinter import messagebox

        pdf = self._pdf_var.get().strip()
        sig = self._sig_var.get().strip()

        if not pdf and not sig:
            messagebox.showwarning("Revenant", "Please select a file to verify.")
            return
        if pdf and not Path(pdf).is_file():
            messagebox.showerror("Revenant", f"File not found:\n{pdf}")
            return
        if sig and not Path(sig).is_file():
            messagebox.showerror("Revenant", f"File not found:\n{sig}")
            return

        self._verify_btn.configure(state="disabled")
        self._clear()

        from ..helpers import format_size_kb

        if pdf and sig:
            # Detached mode
            pdf_size = Path(pdf).stat().st_size
            sig_size = Path(sig).stat().st_size
            self._append(f"{Path(pdf).name} ({format_size_kb(pdf_size)})", "header")
            self._append(f" + {Path(sig).name} ({format_size_kb(sig_size)})\n", "header")
            self._append("Verifying detached signature...\n\n")
            threading.Thread(
                target=self._do_verify_detached,
                args=(Path(pdf), Path(sig)),
                daemon=True,
            ).start()
        elif pdf:
            # Embedded mode
            file_size = Path(pdf).stat().st_size
            self._append(f"{Path(pdf).name} ({format_size_kb(file_size)})\n", "header")
            self._append("Verifying embedded signatures...\n\n")
            threading.Thread(
                target=self._do_verify_embedded,
                args=(Path(pdf),),
                daemon=True,
            ).start()
        else:
            # Inspect-only mode
            sig_size = Path(sig).stat().st_size
            self._append(f"{Path(sig).name} ({format_size_kb(sig_size)})\n", "header")
            self._append("Inspecting signature...\n\n")
            threading.Thread(
                target=self._do_inspect,
                args=(Path(sig),),
                daemon=True,
            ).start()

    # ── Verification threads ──────────────────────────────────────

    def _do_verify_embedded(self, pdf_path: Path) -> None:
        try:
            pdf_bytes = pdf_path.read_bytes()
        except OSError as e:
            msg = f"Cannot read file: {e}"
            self._root.after(0, lambda m=msg: self._finish_error(m))
            return

        try:
            results = verify_all_embedded_signatures(pdf_bytes)
        except RevenantError as e:
            msg = str(e)
            self._root.after(0, lambda m=msg: self._finish_error(m))
            return
        except Exception as e:
            _logger.exception("Unexpected error during verification")
            msg = f"Unexpected error: {e}"
            self._root.after(0, lambda m=msg: self._finish_error(m))
            return

        server_result = try_server_verify(pdf_bytes)
        self._root.after(0, lambda r=results, s=server_result: self._finish_embedded(r, s))

    def _do_verify_detached(self, pdf_path: Path, sig_path: Path) -> None:
        try:
            pdf_bytes = pdf_path.read_bytes()
            cms_bytes = sig_path.read_bytes()
        except OSError as e:
            msg = f"Cannot read file: {e}"
            self._root.after(0, lambda m=msg: self._finish_error(m))
            return

        try:
            detached_result = verify_detached_signature(pdf_bytes, cms_bytes)
        except Exception as e:
            _logger.exception("Unexpected error during detached verification")
            msg = f"Unexpected error: {e}"
            self._root.after(0, lambda m=msg: self._finish_error(m))
            return

        # Also check for embedded signatures in the PDF
        embedded_results: list[VerificationResult] = []
        try:
            embedded_results = verify_all_embedded_signatures(pdf_bytes)
        except RevenantError:
            pass  # No embedded signatures -- that's fine

        server_result = try_server_verify(pdf_bytes) if embedded_results else None
        self._root.after(
            0,
            lambda d=detached_result, e=embedded_results, s=server_result: self._finish_detached(
                d, e, s
            ),
        )

    def _do_inspect(self, sig_path: Path) -> None:
        from ...core.pdf import inspect_cms_blob

        try:
            cms_bytes = sig_path.read_bytes()
        except OSError as e:
            msg = f"Cannot read file: {e}"
            self._root.after(0, lambda m=msg: self._finish_error(m))
            return

        try:
            result = inspect_cms_blob(cms_bytes)
        except Exception as e:
            _logger.exception("Unexpected error during inspection")
            msg = f"Unexpected error: {e}"
            self._root.after(0, lambda m=msg: self._finish_error(m))
            return

        self._root.after(0, lambda r=result: self._finish_inspect(r))

    # ── Result display ────────────────────────────────────────────

    def _finish_error(self, message: str) -> None:
        self._verify_btn.configure(state="normal")
        self._clear()
        self._append(message + "\n", "failed")

    def _finish_embedded(
        self,
        results: list[VerificationResult],
        server_result: ServerVerifyResult | None = None,
    ) -> None:
        self._verify_btn.configure(state="normal")
        self._clear()
        format_results(self._append, results)
        if server_result is not None:
            format_server_result(self._append, server_result)

    def _finish_detached(
        self,
        detached_result: VerificationResult,
        embedded_results: list[VerificationResult] | None = None,
        server_result: ServerVerifyResult | None = None,
    ) -> None:
        self._verify_btn.configure(state="normal")
        self._clear()
        format_detached_result(self._append, detached_result)
        if embedded_results:
            self._append("\nEmbedded signatures\n", "header")
            format_results(self._append, embedded_results)
        if server_result is not None:
            format_server_result(self._append, server_result)

    def _finish_inspect(self, result: CmsInspection) -> None:
        self._verify_btn.configure(state="normal")
        self._clear()
        format_inspection(self._append, result)

    # ── Text widget helpers ───────────────────────────────────────

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
