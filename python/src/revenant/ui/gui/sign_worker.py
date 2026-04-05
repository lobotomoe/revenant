# SPDX-License-Identifier: Apache-2.0
"""Signing workflow -- validation, credential handling, and background execution."""

from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import tkinter as tk
    from collections.abc import Callable

from ...config import (
    get_server_config,
    resolve_credentials,
)
from ...constants import BYTES_PER_MB, DEFAULT_TIMEOUT_SOAP, PDF_WARN_SIZE
from ...errors import RevenantError
from ..workflows import SigningResult, resolve_sig_fields, sign_one_detached, sign_one_embedded
from .i18n import _
from .utils import reveal_file

_logger = logging.getLogger(__name__)


def start_signing(
    root: tk.Tk,
    *,
    pdf_path: str,
    output_path: str,
    signing_mode: str,
    position: str,
    page: str,
    font_key: str,
    invisible: bool,
    image_path: str,
    signer_name: str | None,
    sign_btn: Any,
    status_text: tk.StringVar,
    login_dialog_fn: Callable[[], tuple[str, str] | None],
) -> None:
    """Validate inputs and start signing in a background thread."""
    from tkinter import messagebox

    if not pdf_path:
        messagebox.showwarning("Revenant", _("Please select a PDF file."))
        return
    if not Path(pdf_path).is_file():
        messagebox.showerror("Revenant", _("File not found:\n{path}").format(path=pdf_path))
        return

    pdf_size = Path(pdf_path).stat().st_size
    if pdf_size > PDF_WARN_SIZE:
        size_mb = pdf_size / BYTES_PER_MB
        if not messagebox.askyesno(
            "Revenant",
            _(
                "This PDF is {size_mb} MB.\n\nFiles over 30 MB may take a long time to sign\nor fail on the server.\n\nContinue?"
            ).format(size_mb=f"{size_mb:.0f}"),
        ):
            return

    if output_path and not Path(output_path).is_absolute():
        messagebox.showwarning(
            "Revenant",
            _("Output path must be absolute.\nUse 'Browse...' to select a location."),
        )
        return

    if (
        output_path
        and Path(output_path).exists()
        and not messagebox.askyesno(
            "Revenant",
            _("File already exists:\n{filename}\n\nOverwrite?").format(
                filename=Path(output_path).name
            ),
        )
    ):
        return

    status_text.set(_("Loading credentials..."))
    root.update_idletasks()
    user, pwd = resolve_credentials()
    status_text.set(_("Ready"))
    if not user or not pwd:
        creds = login_dialog_fn()
        if creds is None:
            return
        user, pwd = creds

    sign_btn.configure(state="disabled")
    status_text.set(_("Signing..."))
    root.update_idletasks()

    threading.Thread(
        target=_do_sign,
        args=(
            root,
            signing_mode,
            pdf_path,
            output_path,
            position,
            page,
            font_key,
            invisible,
            image_path,
            signer_name,
            user,
            pwd,
            sign_btn,
            status_text,
        ),
        daemon=True,
    ).start()


def _do_sign(
    root: tk.Tk,
    signing_mode: str,
    pdf_path: str,
    output_path: str,
    position: str,
    page_raw: str,
    font_key: str,
    invisible: bool,
    image_path: str,
    signer_name: str | None,
    username: str,
    password: str,
    sign_btn: Any,
    status_text: tk.StringVar,
) -> None:
    """Perform signing using shared workflow (runs in background thread)."""
    from ..helpers import default_detached_output_path, default_output_path, format_size_kb

    url, timeout, _profile = get_server_config()
    if not url:
        _finish_sign(
            root,
            sign_btn,
            status_text,
            False,
            _("No server configured.\nClick 'Setup...' to configure."),
        )
        return

    timeout = timeout or DEFAULT_TIMEOUT_SOAP

    try:
        pdf_bytes = Path(pdf_path).read_bytes()
    except PermissionError:
        _finish_sign(
            root,
            sign_btn,
            status_text,
            False,
            _(
                "Permission denied:\n{path}\n\nTry selecting the file again using 'Browse...'."
            ).format(path=pdf_path),
        )
        return

    if signing_mode == "detached":
        out = Path(output_path) if output_path else default_detached_output_path(Path(pdf_path))
        result = sign_one_detached(pdf_bytes, out, url, username, password, timeout)
    else:
        out = Path(output_path) if output_path else default_output_path(Path(pdf_path))

        from ...core.pdf import parse_page_spec

        try:
            page = parse_page_spec(page_raw)
        except RevenantError as e:
            _finish_sign(root, sign_btn, status_text, False, str(e))
            return

        visible = not invisible
        font = font_key if visible else None
        image = image_path or None
        fields = resolve_sig_fields()

        result = sign_one_embedded(
            pdf_bytes,
            out,
            url,
            username,
            password,
            timeout,
            position=position,
            page=page,
            name=signer_name,
            image_path=image,
            fields=fields,
            visible=visible,
            font=font,
        )

    _present_result(root, sign_btn, status_text, result, out, signing_mode, format_size_kb)


def _present_result(
    root: tk.Tk,
    sign_btn: Any,
    status_text: tk.StringVar,
    result: SigningResult,
    output_path: Path,
    signing_mode: str,
    format_size_kb: Callable[[int], str],
) -> None:
    """Map SigningResult to UI feedback."""
    if result.ok:
        if signing_mode == "detached":
            size_str = f"{result.output_size} bytes"
        else:
            size_str = format_size_kb(result.output_size)
        _finish_sign(
            root,
            sign_btn,
            status_text,
            True,
            _("Signed! -> {filename} ({size})").format(filename=output_path.name, size=size_str),
            str(output_path),
        )
    elif result.auth_failed:
        _finish_sign(
            root,
            sign_btn,
            status_text,
            False,
            _("Auth failed: {error}").format(error=result.error_message),
        )
    elif result.tls_error:
        _finish_sign(
            root,
            sign_btn,
            status_text,
            False,
            _("TLS error: {error}").format(error=result.error_message),
        )
    elif result.error_message and "Permission denied" in result.error_message:
        _finish_sign(
            root,
            sign_btn,
            status_text,
            False,
            _(
                "Permission denied:\n{path}\n\nTry saving to a different location\nusing 'Browse...'."
            ).format(path=output_path),
        )
    else:
        _finish_sign(
            root,
            sign_btn,
            status_text,
            False,
            _("Error: {error}").format(error=result.error_message),
        )


def _finish_sign(
    root: tk.Tk,
    sign_btn: Any,
    status_text: tk.StringVar,
    success: bool,
    message: str,
    output_file: str | None = None,
) -> None:
    """Update UI after signing (called from background thread)."""

    def _update() -> None:
        from tkinter import messagebox

        sign_btn.configure(state="normal")
        if success:
            status_text.set(message)
            messagebox.showinfo("Revenant", message)
            if output_file:
                reveal_file(output_file)
        else:
            status_text.set(_("Failed"))
            messagebox.showerror("Revenant", message)

    root.after(0, _update)
