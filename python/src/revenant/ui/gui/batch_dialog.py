# SPDX-License-Identifier: Apache-2.0
"""Batch signing progress dialog -- modal progress display with cancel support."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import threading
    import tkinter as tk

from .i18n import _


class BatchProgressDialog:
    """Modal dialog showing batch signing progress.

    Thread-safe: all public methods schedule updates via root.after()
    and can be called from any thread.
    """

    def __init__(
        self,
        parent: tk.Tk,
        total: int,
        cancel_event: threading.Event,
    ) -> None:
        import tkinter as real_tk
        from tkinter import ttk

        self._parent = parent
        self._total = total
        self._cancel_event = cancel_event
        self._succeeded = 0
        self._failed = 0

        self._win = real_tk.Toplevel(parent)
        self._win.title(_("gui.batch_signing"))
        self._win.transient(parent)
        self._win.resizable(False, False)
        self._win.protocol("WM_DELETE_WINDOW", self._on_cancel)

        frame = ttk.Frame(self._win, padding=20)
        frame.pack(fill="both", expand=True)

        self._status_var = real_tk.StringVar(value=_("gui.preparing_ellipsis"))
        ttk.Label(frame, textvariable=self._status_var, wraplength=350).pack(
            anchor="w", pady=(0, 8)
        )

        self._progress = ttk.Progressbar(
            frame, orient="horizontal", length=350, mode="determinate", maximum=total
        )
        self._progress.pack(fill="x", pady=(0, 8))

        self._detail_var = real_tk.StringVar()
        ttk.Label(frame, textvariable=self._detail_var, foreground="gray").pack(
            anchor="w", pady=(0, 12)
        )

        self._cancel_btn = ttk.Button(frame, text=_("gui.cancel"), command=self._on_cancel)
        self._cancel_btn.pack()

        self._win.update_idletasks()
        from . import center_on_parent

        center_on_parent(self._win, parent)
        self._win.grab_set()

    def update(self, index: int, filename: str) -> None:
        """Update progress for the current file (call from any thread)."""

        def _do() -> None:
            self._progress["value"] = index
            self._status_var.set(
                _("gui.signing_n_of_total_filename").format(
                    n=index + 1, total=self._total, filename=filename
                )
            )

        self._parent.after(0, _do)

    def record_result(self, success: bool) -> None:
        """Record the result of a single file signing."""
        if success:
            self._succeeded += 1
        else:
            self._failed += 1

    def finish_success(self) -> None:
        """Show summary and close dialog (call from any thread)."""

        def _do() -> None:
            from tkinter import messagebox

            self._win.grab_release()
            self._win.destroy()
            msg = _("gui.batch_complete_succeeded_failed").format(
                succeeded=self._succeeded, failed=self._failed
            )
            messagebox.showinfo("Revenant", msg)

        self._parent.after(0, _do)

    def finish_error(self, message: str) -> None:
        """Show error and close dialog (call from any thread)."""

        def _do() -> None:
            from tkinter import messagebox

            self._win.grab_release()
            self._win.destroy()
            messagebox.showerror("Revenant", message)

        self._parent.after(0, _do)

    def _on_cancel(self) -> None:
        """User clicked cancel -- signal the worker thread."""
        self._cancel_event.set()
        self._cancel_btn.configure(state="disabled")
        self._status_var.set(_("gui.cancelling_ellipsis"))
