"""Smoke tests for revenant.ui.gui -- verify imports and non-UI logic."""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

if TYPE_CHECKING:
    from revenant.core.pdf import CmsInspection, VerificationResult

# ── Import smoke tests ──────────────────────────────────────────────────


def test_gui_main_importable():
    """GUI main function is importable without tkinter."""
    from revenant.ui.gui import main

    assert callable(main)


def test_gui_app_class_importable():
    """RevenantGUI class is importable."""
    from revenant.ui.gui.app import RevenantGUI

    assert RevenantGUI is not None


def test_gui_verify_panel_importable():
    """VerifyPanel is importable."""
    from revenant.ui.gui.verify import VerifyPanel

    assert VerifyPanel is not None


def test_gui_sign_form_importable():
    """SignForm is importable."""
    from revenant.ui.gui.sign_form import SignForm

    assert SignForm is not None


def test_gui_connect_dialog_importable():
    """ConnectDialog is importable."""
    from revenant.ui.gui.connect_dialog import ConnectDialog

    assert ConnectDialog is not None


def test_gui_login_dialog_importable():
    """LoginDialog is importable."""
    from revenant.ui.gui.setup import LoginDialog

    assert LoginDialog is not None


def test_gui_verify_dialog_importable():
    """Verify dialog helpers are importable."""
    from revenant.ui.gui.verify_dialog import (
        format_detached_result,
        format_inspection,
        format_results,
        format_server_result,
        show_verify_dialog,
        try_server_verify,
    )

    assert callable(format_results)
    assert callable(format_detached_result)
    assert callable(format_inspection)
    assert callable(try_server_verify)
    assert callable(format_server_result)
    assert callable(show_verify_dialog)


def test_gui_utils_importable():
    """GUI utilities are importable."""
    from revenant.ui.gui.utils import (
        bind_macos_shortcuts,
        check_tkinter,
        reveal_file,
        run_in_thread,
    )

    assert callable(check_tkinter)
    assert callable(bind_macos_shortcuts)
    assert callable(reveal_file)
    assert callable(run_in_thread)


# ── check_tkinter ────────────────────────────────────────────────────────


def test_check_tkinter_returns_tuple():
    """check_tkinter returns (bool, str) tuple."""
    from revenant.ui.gui.utils import check_tkinter

    ok, msg = check_tkinter()
    assert isinstance(ok, bool)
    assert isinstance(msg, str)
    if ok:
        assert msg == ""
    else:
        assert "tkinter" in msg.lower()


# ── Verify dialog formatting helpers ─────────────────────────────────────


def test_format_results_single_valid():
    """format_results handles a single valid signature."""
    from revenant.ui.gui.verify_dialog import format_results

    result: VerificationResult = {
        "valid": True,
        "structure_ok": True,
        "hash_ok": True,
        "signer": {"name": "Test User", "email": None, "organization": None, "dn": None},
        "details": ["Signer: Test User", "Algorithm: SHA-256"],
    }

    lines: list[tuple[str, str | None]] = []

    def mock_append(text: str, tag: str | None = None) -> None:
        lines.append((text, tag))

    format_results(mock_append, [result])
    all_text = "".join(t for t, _ in lines)
    assert "VALID" in all_text


def test_format_results_single_failed():
    """format_results handles a single failed signature."""
    from revenant.ui.gui.verify_dialog import format_results

    result: VerificationResult = {
        "valid": False,
        "structure_ok": True,
        "hash_ok": False,
        "signer": {"name": "Test User", "email": None, "organization": None, "dn": None},
        "details": ["Signer: Test User", "Integrity: FAILED"],
    }

    lines: list[tuple[str, str | None]] = []

    def mock_append(text: str, tag: str | None = None) -> None:
        lines.append((text, tag))

    format_results(mock_append, [result])
    all_text = "".join(t for t, _ in lines)
    assert "FAILED" in all_text


def test_format_server_result_valid():
    """format_server_result handles a valid server result."""
    from revenant.network.soap import ServerVerifyResult
    from revenant.ui.gui.verify_dialog import format_server_result

    result = ServerVerifyResult(
        valid=True,
        signer_name="Test User",
        sign_time="2024-01-01",
        certificate_status="Valid",
        error=None,
    )

    lines: list[tuple[str, str | None]] = []

    def mock_append(text: str, tag: str | None = None) -> None:
        lines.append((text, tag))

    format_server_result(mock_append, result)
    all_text = "".join(t for t, _ in lines)
    assert "VALID" in all_text
    assert "Test User" in all_text


def test_format_server_result_error():
    """format_server_result handles an error result."""
    from revenant.network.soap import ServerVerifyResult
    from revenant.ui.gui.verify_dialog import format_server_result

    result = ServerVerifyResult(
        valid=False,
        signer_name=None,
        sign_time=None,
        certificate_status=None,
        error="Connection timeout",
    )

    lines: list[tuple[str, str | None]] = []

    def mock_append(text: str, tag: str | None = None) -> None:
        lines.append((text, tag))

    format_server_result(mock_append, result)
    all_text = "".join(t for t, _ in lines)
    assert "Unavailable" in all_text
    assert "Connection timeout" in all_text


def test_format_detached_result_valid():
    """format_detached_result handles a valid result."""
    from revenant.ui.gui.verify_dialog import format_detached_result

    result: VerificationResult = {
        "valid": True,
        "structure_ok": True,
        "hash_ok": True,
        "signer": {"name": "Test User", "email": None, "organization": None, "dn": None},
        "details": ["Signer: Test User\nAlgorithm: SHA-256"],
    }

    lines: list[tuple[str, str | None]] = []

    def mock_append(text: str, tag: str | None = None) -> None:
        lines.append((text, tag))

    format_detached_result(mock_append, result)
    all_text = "".join(t for t, _ in lines)
    assert "Detached" in all_text
    assert "VALID" in all_text


def test_format_inspection():
    """format_inspection outputs certificate inspection info."""
    from revenant.ui.gui.verify_dialog import format_inspection

    result: CmsInspection = {
        "signer": {"name": "Test User", "email": None, "organization": None, "dn": None},
        "digest_algorithm": "SHA-256",
        "cms_size": 1024,
        "details": ["Subject: CN=Test User", "Issuer: CN=CA"],
    }

    lines: list[tuple[str, str | None]] = []

    def mock_append(text: str, tag: str | None = None) -> None:
        lines.append((text, tag))

    format_inspection(mock_append, result)
    all_text = "".join(t for t, _ in lines)
    assert "Certificate inspection" in all_text
    assert "CN=Test User" in all_text


# ── try_server_verify ────────────────────────────────────────────────────


def test_try_server_verify_no_server_returns_none():
    """try_server_verify returns None when no server is configured."""
    from revenant.ui.gui.verify_dialog import try_server_verify

    with patch(
        "revenant.config.get_server_config",
        return_value=(None, None, None),
    ):
        result = try_server_verify(b"fake pdf")
        assert result is None


# ── run_in_thread ────────────────────────────────────────────────────────


def test_run_in_thread_success():
    """run_in_thread calls on_success for successful tasks."""
    import threading

    from revenant.ui.gui.utils import run_in_thread

    root = MagicMock()
    captured_callback = []

    def mock_after(delay, fn):
        captured_callback.append(fn)

    root.after = mock_after

    started_threads: list[threading.Thread] = []
    _original_start = threading.Thread.start

    def _capturing_start(self: threading.Thread) -> None:
        started_threads.append(self)
        _original_start(self)

    with patch.object(threading.Thread, "start", _capturing_start):
        run_in_thread(root, lambda: 42, lambda r: None, lambda e: None)

    assert len(started_threads) == 1
    started_threads[0].join(timeout=5)

    assert len(captured_callback) == 1


def test_run_in_thread_error():
    """run_in_thread calls on_error for failed tasks."""
    import threading

    from revenant.ui.gui.utils import run_in_thread

    root = MagicMock()
    captured_callback = []

    def mock_after(delay, fn):
        captured_callback.append(fn)

    root.after = mock_after

    def failing_task():
        raise ValueError("test error")

    started_threads: list[threading.Thread] = []
    _original_start = threading.Thread.start

    def _capturing_start(self: threading.Thread) -> None:
        started_threads.append(self)
        _original_start(self)

    with patch.object(threading.Thread, "start", _capturing_start):
        run_in_thread(root, failing_task, lambda r: None, lambda e: None)

    assert len(started_threads) == 1
    started_threads[0].join(timeout=5)

    assert len(captured_callback) == 1
