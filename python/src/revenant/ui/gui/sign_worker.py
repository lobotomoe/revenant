# SPDX-License-Identifier: Apache-2.0
"""Signing workflow -- validation, credential handling, and background execution."""

from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import tkinter as tk
    from collections.abc import Callable
    from tkinter import ttk

    from .batch_dialog import BatchProgressDialog
    from .sign_options import SignOptions

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

# ── User-friendly error messages ─────────────────────────────────────

_FRIENDLY_ERRORS: list[tuple[str, str]] = [
    ("timed out", _("gui.server_is_not_responding_check_your_internet_conne_cd87621d")),
    ("Cannot connect", _("gui.cannot_connect_to_the_server_check_your_internet_connection")),
    ("Connection refused", _("gui.server_is_not_available_it_may_be_down_for_maintenance")),
    ("Name or service not known", _("gui.server_address_not_found_check_the_server_url")),
    ("SSL error", _("gui.secure_connection_failed_contact_your_system_administrator")),
    ("HTTP 403", _("gui.access_denied_your_account_may_not_have_permission_to_sign")),
    ("HTTP 401", _("gui.authentication_rejected_check_your_username_and_password")),
    ("HTTP 5", _("gui.server_error_the_signing_service_may_be_temporaril_d8163695")),
    ("HTTP 4", _("gui.request_rejected_by_server_contact_your_system_administrator")),
]


def _friendly_error(raw: str) -> str:
    """Map a technical error message to a user-friendly one."""
    for pattern, friendly in _FRIENDLY_ERRORS:
        if pattern in raw:
            return friendly
    return raw


# ── Single-file signing ──────────────────────────────────────────────


def start_signing(
    root: tk.Tk,
    *,
    pdf_path: str,
    output_path: str,
    opts: SignOptions,
    sign_btn: ttk.Button,
    status_text: tk.StringVar,
    login_dialog_fn: Callable[[], tuple[str, str] | None],
) -> None:
    """Validate inputs and start single-file signing in a background thread."""
    from tkinter import messagebox

    if not pdf_path:
        messagebox.showwarning("Revenant", _("gui.please_select_a_pdf_file"))
        return
    if not Path(pdf_path).is_file():
        messagebox.showerror("Revenant", _("gui.file_not_found_path").format(path=pdf_path))
        return

    pdf_size = Path(pdf_path).stat().st_size
    if pdf_size > PDF_WARN_SIZE:
        size_mb = pdf_size / BYTES_PER_MB
        if not messagebox.askyesno(
            "Revenant",
            _("gui.this_pdf_is_size_mb_mb_files_over_30_mb_may_take_a_64b3d55a").format(
                size_mb=f"{size_mb:.0f}"
            ),
        ):
            return

    if output_path and not Path(output_path).is_absolute():
        messagebox.showwarning(
            "Revenant",
            _("gui.output_path_must_be_absolute_use_browse_to_select_a_location"),
        )
        return

    if (
        output_path
        and Path(output_path).exists()
        and not messagebox.askyesno(
            "Revenant",
            _("gui.file_already_exists_filename_overwrite").format(filename=Path(output_path).name),
        )
    ):
        return

    sign_btn.configure(state="disabled")
    status_text.set(_("gui.loading_credentials_ellipsis"))
    root.update_idletasks()

    def _on_credentials(username: str, password: str) -> None:
        threading.Thread(
            target=_do_sign,
            args=(root, opts, pdf_path, output_path, username, password, sign_btn, status_text),
            daemon=True,
        ).start()

    _resolve_creds_then(root, sign_btn, status_text, login_dialog_fn, _on_credentials)


# ── Batch signing ────────────────────────────────────────────────────


def start_batch_signing(
    root: tk.Tk,
    *,
    pdf_paths: list[str],
    opts: SignOptions,
    sign_btn: ttk.Button,
    status_text: tk.StringVar,
    login_dialog_fn: Callable[[], tuple[str, str] | None],
) -> None:
    """Validate inputs and start batch signing with a progress dialog."""
    from tkinter import messagebox

    # Validate all files exist
    missing = [p for p in pdf_paths if not Path(p).is_file()]
    if missing:
        messagebox.showerror(
            "Revenant",
            _("gui.file_not_found_path").format(path=missing[0]),
        )
        return

    sign_btn.configure(state="disabled")
    status_text.set(_("gui.loading_credentials_ellipsis"))
    root.update_idletasks()

    def _on_credentials(username: str, password: str) -> None:
        from .batch_dialog import BatchProgressDialog

        cancel_event = threading.Event()
        dialog = BatchProgressDialog(root, len(pdf_paths), cancel_event)

        threading.Thread(
            target=_do_sign_batch,
            args=(
                root,
                opts,
                pdf_paths,
                username,
                password,
                dialog,
                cancel_event,
                sign_btn,
                status_text,
            ),
            daemon=True,
        ).start()

    _resolve_creds_then(root, sign_btn, status_text, login_dialog_fn, _on_credentials)


# ── Credential resolution ────────────────────────────────────────────


def _resolve_creds_then(
    root: tk.Tk,
    sign_btn: ttk.Button,
    status_text: tk.StringVar,
    login_dialog_fn: Callable[[], tuple[str, str] | None],
    on_credentials: Callable[[str, str], None],
) -> None:
    """Resolve credentials, prompting if needed, then call on_credentials."""

    def _resolve() -> None:
        user, pwd = resolve_credentials()
        if not user or not pwd:

            def _prompt() -> None:
                creds = login_dialog_fn()
                if creds is None:
                    sign_btn.configure(state="normal")
                    status_text.set(_("gui.ready"))
                    return
                u, p = creds
                status_text.set(_("gui.signing_ellipsis"))
                root.update_idletasks()
                on_credentials(u, p)

            root.after(0, _prompt)
            return

        root.after(0, lambda: status_text.set(_("gui.signing_ellipsis")))
        on_credentials(user, pwd)

    threading.Thread(target=_resolve, daemon=True).start()


# ── Single-file worker ───────────────────────────────────────────────


def _do_sign(
    root: tk.Tk,
    opts: SignOptions,
    pdf_path: str,
    output_path: str,
    username: str,
    password: str,
    sign_btn: ttk.Button,
    status_text: tk.StringVar,
) -> None:
    """Perform single-file signing (runs in background thread)."""
    from ..helpers import format_size_kb

    url, timeout, _profile = get_server_config()
    if not url:
        _finish_sign(
            root,
            sign_btn,
            status_text,
            False,
            _("gui.no_server_configured_click_setup_to_configure"),
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
            _("gui.permission_denied_path_try_selecting_the_file_agai_de400967").format(
                path=pdf_path
            ),
        )
        return

    sign_result = _sign_one_file(
        opts, pdf_bytes, pdf_path, output_path, url, username, password, timeout
    )
    if sign_result is None:
        _finish_sign(root, sign_btn, status_text, False, _("gui.invalid_page_specification"))
        return

    result, out = sign_result
    _present_result(root, sign_btn, status_text, result, out, opts.signing_mode, format_size_kb)


# ── Batch worker ─────────────────────────────────────────────────────


def _do_sign_batch(
    root: tk.Tk,
    opts: SignOptions,
    pdf_paths: list[str],
    username: str,
    password: str,
    dialog: BatchProgressDialog,
    cancel_event: threading.Event,
    sign_btn: ttk.Button,
    status_text: tk.StringVar,
) -> None:
    """Sign multiple files sequentially (runs in background thread)."""
    url, timeout, _profile = get_server_config()
    if not url:
        dialog.finish_error(_("gui.no_server_configured_click_setup_to_configure"))
        root.after(0, lambda: sign_btn.configure(state="normal"))
        return

    timeout = timeout or DEFAULT_TIMEOUT_SOAP

    for i, pdf_path in enumerate(pdf_paths):
        if cancel_event.is_set():
            break

        filename = Path(pdf_path).name
        dialog.update(i, filename)

        try:
            pdf_bytes = Path(pdf_path).read_bytes()
        except (PermissionError, OSError) as e:
            _logger.warning("Batch: cannot read %s: %s", pdf_path, e)
            dialog.record_result(success=False)
            continue

        sign_result = _sign_one_file(
            opts, pdf_bytes, pdf_path, "", url, username, password, timeout
        )
        if sign_result is None:
            dialog.record_result(success=False)
            continue

        result, _out_path = sign_result
        if result.auth_failed:
            raw = result.error_message or ""
            dialog.finish_error(_friendly_error(raw))
            root.after(0, lambda: sign_btn.configure(state="normal"))
            return

        if result.tls_error:
            raw = result.error_message or ""
            dialog.finish_error(_friendly_error(raw))
            root.after(0, lambda: sign_btn.configure(state="normal"))
            return

        dialog.record_result(success=result.ok)

    dialog.finish_success()
    root.after(0, lambda: sign_btn.configure(state="normal"))
    root.after(0, lambda: status_text.set(_("gui.ready")))


# ── Shared signing logic ─────────────────────────────────────────────


def _sign_one_file(
    opts: SignOptions,
    pdf_bytes: bytes,
    pdf_path: str,
    output_path: str,
    url: str,
    username: str,
    password: str,
    timeout: int,
) -> tuple[SigningResult, Path] | None:
    """Sign a single file, returning (result, output_path) or None on parse error."""
    from ..helpers import default_detached_output_path, default_output_path

    if opts.signing_mode == "detached":
        out = Path(output_path) if output_path else default_detached_output_path(Path(pdf_path))
        result = sign_one_detached(pdf_bytes, out, url, username, password, timeout)
        return result, out

    out = Path(output_path) if output_path else default_output_path(Path(pdf_path))

    from ...core.pdf import parse_page_spec

    try:
        page = parse_page_spec(opts.page)
    except RevenantError:
        return None

    visible = not opts.invisible
    font = opts.font_key if visible else None
    image = opts.image_path or None
    fields = resolve_sig_fields()

    result = sign_one_embedded(
        pdf_bytes,
        out,
        url,
        username,
        password,
        timeout,
        position=opts.position,
        page=page,
        name=opts.signer_name,
        image_path=image,
        fields=fields,
        visible=visible,
        font=font,
        reason=opts.reason,
    )
    return result, out


# ── UI feedback ──────────────────────────────────────────────────────


def _present_result(
    root: tk.Tk,
    sign_btn: ttk.Button,
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
            _("gui.signed_filename_size").format(filename=output_path.name, size=size_str),
            str(output_path),
        )
    elif result.auth_failed:
        raw = result.error_message or ""
        _logger.error("Auth failed: %s", raw)
        _finish_sign(root, sign_btn, status_text, False, _friendly_error(raw))
    elif result.tls_error:
        raw = result.error_message or ""
        _logger.error("TLS error: %s", raw)
        _finish_sign(root, sign_btn, status_text, False, _friendly_error(raw))
    elif result.error_message and "Permission denied" in result.error_message:
        _finish_sign(
            root,
            sign_btn,
            status_text,
            False,
            _("gui.permission_denied_path_try_saving_to_a_different_l_51ac0570").format(
                path=output_path
            ),
        )
    else:
        raw = result.error_message or ""
        _logger.error("Signing error: %s", raw)
        _finish_sign(root, sign_btn, status_text, False, _friendly_error(raw))


def _finish_sign(
    root: tk.Tk,
    sign_btn: ttk.Button,
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
            status_text.set(_("gui.failed"))
            messagebox.showerror("Revenant", message)

    root.after(0, _update)
