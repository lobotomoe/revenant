"""Tests for revenant.ui.helpers -- CLI input/output helpers."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from revenant.errors import AuthError
from revenant.ui.helpers import (
    atomic_write,
    confirm_choice,
    default_detached_output_path,
    default_output_path,
    format_server_verify_result,
    format_size_kb,
    offer_save_credentials,
    print_auth_failure,
    prompt_credentials,
    safe_input,
    safe_read_file,
)

# ── safe_input ────────────────────────────────────────────────────


def test_safe_input_returns_stripped():
    with patch("builtins.input", return_value="  hello  "):
        assert safe_input("prompt: ") == "hello"


def test_safe_input_returns_none_on_eof():
    with patch("builtins.input", side_effect=EOFError):
        assert safe_input("prompt: ") is None


def test_safe_input_returns_none_on_keyboard_interrupt():
    with patch("builtins.input", side_effect=KeyboardInterrupt):
        assert safe_input("prompt: ") is None


# ── confirm_choice ────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("answer", "default_yes", "expected"),
    [
        ("", True, True),  # default yes, empty input
        ("y", True, True),
        ("yes", True, True),
        ("n", True, False),
        ("no", True, False),
        ("", False, False),  # default no, empty input
        ("y", False, True),
        ("yes", False, True),
        ("n", False, False),
    ],
)
def test_confirm_choice_answers(answer: str, default_yes: bool, expected: bool):
    with patch("builtins.input", return_value=answer):
        assert confirm_choice("Continue?", default_yes=default_yes) is expected


def test_confirm_choice_returns_false_on_eof():
    with patch("builtins.input", side_effect=EOFError):
        assert confirm_choice("Continue?") is False


def test_confirm_choice_returns_false_on_keyboard_interrupt():
    with patch("builtins.input", side_effect=KeyboardInterrupt):
        assert confirm_choice("Continue?") is False


# ── safe_read_file ────────────────────────────────────────────────


def test_safe_read_file_success(tmp_path: Path):
    f = tmp_path / "test.pdf"
    f.write_bytes(b"PDF content")
    result = safe_read_file(f, "PDF")
    assert result == b"PDF content"


def test_safe_read_file_not_found(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    f = tmp_path / "missing.pdf"
    result = safe_read_file(f, "PDF")
    assert result is None
    assert "not found" in capsys.readouterr().err


def test_safe_read_file_read_error(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    f = tmp_path / "test.pdf"
    f.write_bytes(b"data")
    with patch.object(Path, "read_bytes", side_effect=OSError("permission denied")):
        result = safe_read_file(f, "PDF")
    assert result is None
    assert "permission denied" in capsys.readouterr().err


# ── print_auth_failure ────────────────────────────────────────────


def test_print_auth_failure_basic(capsys: pytest.CaptureFixture[str]):
    error = AuthError("Invalid credentials")
    print_auth_failure(error)
    stderr = capsys.readouterr().err
    assert "AUTH FAILED" in stderr
    assert "Invalid credentials" in stderr


def test_print_auth_failure_with_lockout_warning(capsys: pytest.CaptureFixture[str]):
    error = AuthError("Bad password")
    profile = MagicMock()
    profile.max_auth_attempts = 5
    print_auth_failure(error, profile=profile)
    stderr = capsys.readouterr().err
    assert "AUTH FAILED" in stderr
    assert "5 failed attempts" in stderr


def test_print_auth_failure_no_lockout_warning(capsys: pytest.CaptureFixture[str]):
    error = AuthError("Bad password")
    profile = MagicMock()
    profile.max_auth_attempts = None
    print_auth_failure(error, profile=profile)
    stderr = capsys.readouterr().err
    assert "AUTH FAILED" in stderr
    assert "failed attempts" not in stderr


# ── default_output_path / default_detached_output_path ────────────


def test_default_output_path():
    assert default_output_path(Path("/tmp/doc.pdf")) == Path("/tmp/doc_signed.pdf")


def test_default_detached_output_path():
    assert default_detached_output_path(Path("/tmp/doc.pdf")) == Path("/tmp/doc.pdf.p7s")


def test_default_detached_output_path_preserves_directory():
    p = Path("/home/user/documents/report.pdf")
    assert default_detached_output_path(p) == Path("/home/user/documents/report.pdf.p7s")


# ── format_size_kb ────────────────────────────────────────────────


def test_format_size_kb():
    assert format_size_kb(1024) == "1.0 KB"
    assert format_size_kb(0) == "0.0 KB"
    assert format_size_kb(512) == "0.5 KB"
    assert format_size_kb(2560) == "2.5 KB"


# ── prompt_credentials ────────────────────────────────────────────


def test_prompt_credentials_both_provided():
    user, pwd = prompt_credentials(username="alice", password="secret")
    assert user == "alice"
    assert pwd == "secret"


def test_prompt_credentials_prompts_username():
    with (
        patch("builtins.input", return_value="bob"),
        patch("getpass.getpass", return_value="pass123"),
    ):
        user, pwd = prompt_credentials()
    assert user == "bob"
    assert pwd == "pass123"


def test_prompt_credentials_prompts_password_only():
    with patch("getpass.getpass", return_value="pass123"):
        user, pwd = prompt_credentials(username="alice")
    assert user == "alice"
    assert pwd == "pass123"


def test_prompt_credentials_exits_on_eof_username():
    with patch("builtins.input", side_effect=EOFError), pytest.raises(SystemExit):
        prompt_credentials()


def test_prompt_credentials_exits_on_interrupt_password():
    with (
        patch("builtins.input", return_value="alice"),
        patch("getpass.getpass", side_effect=KeyboardInterrupt),
        pytest.raises(SystemExit),
    ):
        prompt_credentials()


def test_prompt_credentials_exits_on_empty():
    with (
        patch("builtins.input", return_value=""),
        patch("getpass.getpass", return_value=""),
        pytest.raises(SystemExit),
    ):
        prompt_credentials()


# ── offer_save_credentials ────────────────────────────────────────


def test_offer_save_credentials_yes(capsys: pytest.CaptureFixture[str]):
    with (
        patch("builtins.input", return_value="y"),
        patch("revenant.config.save_credentials") as mock_save,
        patch("revenant.config.get_credential_storage_info", return_value="keyring"),
        patch("revenant.config.is_keyring_available", return_value=True),
    ):
        offer_save_credentials("alice", "secret")
    mock_save.assert_called_once_with("alice", "secret")
    out = capsys.readouterr().out
    assert "keyring" in out


def test_offer_save_credentials_no(capsys: pytest.CaptureFixture[str]):
    with patch("builtins.input", return_value="n"):
        offer_save_credentials("alice", "secret")
    out = capsys.readouterr().out
    assert "not saved" in out


def test_offer_save_credentials_shows_keyring_hint(capsys: pytest.CaptureFixture[str]):
    with (
        patch("builtins.input", return_value="y"),
        patch("revenant.config.save_credentials"),
        patch("revenant.config.get_credential_storage_info", return_value="config file"),
        patch("revenant.config.is_keyring_available", return_value=False),
    ):
        offer_save_credentials("alice", "secret")
    out = capsys.readouterr().out
    assert "pip install keyring" in out


# ── atomic_write ──────────────────────────────────────────────────


def test_atomic_write_success(tmp_path: Path):
    target = tmp_path / "output.pdf"
    atomic_write(target, b"signed PDF content")
    assert target.read_bytes() == b"signed PDF content"


def test_atomic_write_no_partial_on_error(tmp_path: Path):
    target = tmp_path / "output.pdf"
    with (
        patch("os.write", side_effect=OSError("disk full")),
        pytest.raises(OSError, match="disk full"),
    ):
        atomic_write(target, b"data")
    assert not target.exists()


# ── format_server_verify_result ───────────────────────────────────


def test_format_server_verify_result_valid(capsys: pytest.CaptureFixture[str]):
    from revenant.network.soap import ServerVerifyResult

    result = ServerVerifyResult(
        valid=True,
        error=None,
        signer_name="Alice",
        sign_time="2024-01-01",
        certificate_status="Valid",
    )
    format_server_verify_result(result)
    out = capsys.readouterr().out
    assert "Alice" in out
    assert "VALID" in out


def test_format_server_verify_result_invalid(capsys: pytest.CaptureFixture[str]):
    from revenant.network.soap import ServerVerifyResult

    result = ServerVerifyResult(
        valid=False,
        error=None,
        signer_name=None,
        sign_time=None,
        certificate_status=None,
    )
    format_server_verify_result(result)
    out = capsys.readouterr().out
    assert "FAILED" in out


def test_format_server_verify_result_error(capsys: pytest.CaptureFixture[str]):
    from revenant.network.soap import ServerVerifyResult

    result = ServerVerifyResult(
        valid=False,
        error="Connection refused",
        signer_name=None,
        sign_time=None,
        certificate_status=None,
    )
    format_server_verify_result(result)
    out = capsys.readouterr().out
    assert "unavailable" in out
    assert "Connection refused" in out


def test_format_server_verify_result_wrong_type(capsys: pytest.CaptureFixture[str]):
    format_server_verify_result("not a result")
    err = capsys.readouterr().err
    assert "unexpected result type" in err
