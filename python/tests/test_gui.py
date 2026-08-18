"""Smoke tests for revenant.ui.gui -- verify imports and non-UI logic."""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

import pytest

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


@pytest.fixture(autouse=True, scope="module")
def _init_i18n():
    """Initialize i18n to English so translated keys resolve to real text."""
    from revenant.ui.gui.i18n import init_locale

    init_locale("en")


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


# ── Verdict presentation (GHSA-m267 / GHSA-f928 / GHSA-2cxp) ────────────


def _render(result: VerificationResult) -> tuple[str, list[tuple[str, str | None]]]:
    """Run format_results and return the flat text plus the tagged segments."""
    from revenant.ui.gui.verify_dialog import format_results

    lines: list[tuple[str, str | None]] = []

    def mock_append(text: str, tag: str | None = None) -> None:
        lines.append((text, tag))

    format_results(mock_append, [result])
    return "".join(text for text, _ in lines), lines


def _tampered() -> VerificationResult:
    """A PDF whose covered bytes changed while its CMS stayed intact.

    The signature over the signed attributes still verifies, so the chain
    validates and names a trusted anchor; only the ByteRange digest disagrees.
    """
    return {
        "valid": False,
        "structure_ok": True,
        "hash_ok": False,
        "signer": {
            "name": "Victim Signer",
            "email": None,
            "organization": "Victim Org",
            "dn": None,
        },
        "chain_valid": True,
        "trust_anchor": "Example Trusted CA",
        "details": ["Integrity: FAILED"],
    }


def test_tampered_pdf_is_not_credited_to_a_trusted_signer():
    """A failed signature must not print a green trust line for its certificate."""
    all_text, lines = _render(_tampered())

    assert "Example Trusted CA" not in all_text
    assert not any(tag == "trust_ok" for _, tag in lines)


def test_tampered_pdf_does_not_name_its_signer_or_organization():
    all_text, _lines = _render(_tampered())

    assert "Victim Signer" not in all_text
    assert "Victim Org" not in all_text
    assert "FAILED" in all_text


def test_a_valid_signature_still_shows_signer_and_trust():
    """The fix must not strip identity from signatures that did verify."""
    result: VerificationResult = dict(_tampered())
    result["valid"] = True
    result["hash_ok"] = True

    all_text, lines = _render(result)

    assert "Victim Signer" in all_text
    assert "Victim Org" in all_text
    assert "Example Trusted CA" in all_text
    assert any(tag == "trust_ok" for _, tag in lines)


def test_certificate_that_has_not_started_is_not_shown_as_normal():
    """A notBefore in the future must not render with the plain styling."""
    import datetime

    from revenant.ui.gui.sign_panels import format_cert_validity

    now = datetime.datetime.now(datetime.timezone.utc)
    start = (now + datetime.timedelta(days=90)).isoformat()
    end = (now + datetime.timedelta(days=365)).isoformat()

    text, color = format_cert_validity(start, end)

    assert color == "red"
    assert "days remaining" not in text


def test_a_currently_valid_certificate_is_still_normal():
    import datetime

    from revenant.ui.gui.sign_panels import format_cert_validity

    now = datetime.datetime.now(datetime.timezone.utc)
    start = (now - datetime.timedelta(days=10)).isoformat()
    end = (now + datetime.timedelta(days=365)).isoformat()

    text, color = format_cert_validity(start, end)

    assert color == "gray"
    assert "days remaining" in text


# ── ConnectDialog ping-token guard (GHSA-285g) ──────────────────────────


class _StubWindow:
    """Stands in for the dialog's Toplevel so the guard runs without a display."""

    def __init__(self) -> None:
        self.destroyed = False

    def destroy(self) -> None:
        self.destroyed = True


def _dialog_without_tk():
    """A ConnectDialog with __init__ (and its Tk window) skipped."""
    from revenant.ui.gui.connect_dialog import ConnectDialog

    dialog = object.__new__(ConnectDialog)
    dialog._ping_token = None
    dialog._win = _StubWindow()
    return dialog


def test_connect_dialog_awaits_its_own_ping():
    dialog = _dialog_without_tk()
    token = object()
    dialog._ping_token = token
    assert dialog._awaiting(token) is True


def test_connect_dialog_awaits_a_ping_only_once():
    dialog = _dialog_without_tk()
    token = object()
    dialog._ping_token = token
    assert dialog._awaiting(token) is True
    assert dialog._awaiting(token) is False


def test_connect_dialog_ignores_a_superseded_ping():
    dialog = _dialog_without_tk()
    first = object()
    dialog._ping_token = first
    second = object()
    dialog._ping_token = second

    assert dialog._awaiting(first) is False
    assert dialog._awaiting(second) is True


def test_connect_dialog_does_not_save_a_cancelled_server():
    """GHSA-285g: a delayed success must not persist a declined server.

    Destroying the window does not cancel a callback already scheduled with
    after(), so the callback still runs -- the token guard is what stops it
    reaching save_server_config.
    """
    from revenant.config import make_custom_profile

    dialog = _dialog_without_tk()
    token = object()
    dialog._ping_token = token
    profile = make_custom_profile("https://attacker-controlled.example/SAPIWS/DSS.asmx")

    dialog._cancel()

    with patch("revenant.ui.gui.connect_dialog.save_server_config") as save:
        dialog._on_ping_ok(token, profile, (True, "200 OK"))

    assert dialog._win.destroyed
    save.assert_not_called()


# ── LoginDialog credential character class (issue #76) ──────────────────


class _StubVar:
    """Stands in for a tk.StringVar so the validation runs without a display."""

    def __init__(self, value: str) -> None:
        self._value = value

    def get(self) -> str:
        return self._value


def _login_without_tk(profile, user: str, pwd: str):
    """A LoginDialog on the credentials step with __init__ (and Tk) skipped."""
    from revenant.ui.gui.setup import _LOGIN_STEP_CREDENTIALS, LoginDialog

    dialog = object.__new__(LoginDialog)
    dialog._step = _LOGIN_STEP_CREDENTIALS
    dialog._profile = profile
    dialog._user_var = _StubVar(user)
    dialog._pass_var = _StubVar(pwd)
    dialog._win = _StubWindow()
    # Advancing renders the next page, which needs a real Tk window.
    dialog._show_step = lambda: None
    return dialog


def test_login_rejects_non_ascii_credentials_on_an_ascii_only_profile():
    """EKENG issues Latin-only logins, so non-ASCII is a keyboard-layout slip.

    Stopping it here spends none of the profile's five-attempt lockout budget.
    """
    from revenant.config import get_profile
    from revenant.ui.gui.setup import _LOGIN_STEP_CREDENTIALS

    dialog = _login_without_tk(get_profile("ekeng"), "пользователь", "пароль")

    with patch("tkinter.messagebox.showwarning") as warn:
        dialog._go_next()

    warn.assert_called_once()
    assert dialog._step == _LOGIN_STEP_CREDENTIALS


def test_login_accepts_non_ascii_credentials_on_a_custom_profile():
    """Issue #76: the restriction describes EKENG, not CoSign.

    A custom deployment may issue Unicode logins and the SOAP envelope carries
    them, so the wizard must not be what blocks them.
    """
    from revenant.config import make_custom_profile
    from revenant.ui.gui.setup import _LOGIN_STEP_CREDENTIALS

    profile = make_custom_profile("https://cosign.example/DSS.asmx")
    dialog = _login_without_tk(profile, "álïçé", "pässwörd")

    with patch("tkinter.messagebox.showwarning") as warn:
        dialog._go_next()

    warn.assert_not_called()
    assert dialog._step == _LOGIN_STEP_CREDENTIALS + 1
    assert dialog._username == "álïçé"
    assert dialog._password == "pässwörd"
