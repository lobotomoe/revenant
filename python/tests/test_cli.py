"""Tests for revenant.ui.cli and revenant.ui.cli.sign -- CLI interface functions."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# ── _get_credentials / _resolve_cred_source ────────────────────────────


def test_get_credentials_from_env():
    from revenant.ui.cli.sign import _get_credentials

    with (
        patch.dict("os.environ", {"REVENANT_USER": "envuser", "REVENANT_PASS": "envpass"}),
        patch("revenant.ui.cli.sign.get_credentials", return_value=(None, None)),
    ):
        user, pwd = _get_credentials()
        assert user == "envuser"
        assert pwd == "envpass"


def test_get_credentials_from_config():
    from revenant.ui.cli.sign import _get_credentials

    with (
        patch.dict("os.environ", {"REVENANT_USER": "", "REVENANT_PASS": ""}),
        patch("revenant.ui.cli.sign.get_credentials", return_value=("cfguser", "cfgpass")),
    ):
        user, pwd = _get_credentials()
        assert user == "cfguser"
        assert pwd == "cfgpass"


def test_get_credentials_env_overrides_config():
    from revenant.ui.cli.sign import _get_credentials

    with (
        patch.dict("os.environ", {"REVENANT_USER": "envuser", "REVENANT_PASS": "envpass"}),
        patch("revenant.ui.cli.sign.get_credentials", return_value=("cfguser", "cfgpass")),
    ):
        user, pwd = _get_credentials()
        assert user == "envuser"
        assert pwd == "envpass"


def test_resolve_cred_source_env():
    from revenant.ui.cli.sign import _CRED_SOURCE_ENV, _resolve_cred_source

    with (
        patch.dict("os.environ", {"REVENANT_USER": "u", "REVENANT_PASS": "p"}),
        patch("revenant.ui.cli.sign.get_credentials", return_value=(None, None)),
    ):
        assert _resolve_cred_source() == _CRED_SOURCE_ENV


def test_resolve_cred_source_config():
    from revenant.ui.cli.sign import _CRED_SOURCE_CONFIG, _resolve_cred_source

    with (
        patch.dict("os.environ", {"REVENANT_USER": "", "REVENANT_PASS": ""}),
        patch("revenant.ui.cli.sign.get_credentials", return_value=("u", "p")),
    ):
        assert _resolve_cred_source() == _CRED_SOURCE_CONFIG


def test_resolve_cred_source_prompt():
    from revenant.ui.cli.sign import _CRED_SOURCE_PROMPT, _resolve_cred_source

    with (
        patch.dict("os.environ", {"REVENANT_USER": "", "REVENANT_PASS": ""}),
        patch("revenant.ui.cli.sign.get_credentials", return_value=(None, None)),
    ):
        assert _resolve_cred_source() == _CRED_SOURCE_PROMPT


# ── _require_server_config ─────────────────────────────────────────────


def test_require_server_config_success():
    from revenant.ui.cli.sign import _require_server_config

    with patch(
        "revenant.ui.cli.sign.get_server_config",
        return_value=("https://example.com", 120, "test"),
    ):
        url, timeout, profile = _require_server_config()
        assert url == "https://example.com"
        assert timeout == 120
        assert profile == "test"


def test_require_server_config_no_url_offers_setup_and_exits_on_decline():
    from revenant.ui.cli.sign import _require_server_config

    with (
        patch("revenant.ui.cli.sign.get_server_config", return_value=(None, None, None)),
        patch("builtins.input", return_value="n"),
        pytest.raises(SystemExit),
    ):
        _require_server_config()


def test_require_server_config_no_url_runs_setup_on_accept():
    from revenant.ui.cli.sign import _require_server_config

    # After setup, get_server_config returns a valid URL
    with (
        patch(
            "revenant.ui.cli.sign.get_server_config",
            side_effect=[(None, None, None), ("https://example.com", 120, "test")],
        ),
        patch("builtins.input", return_value="y"),
        patch("revenant.ui.cli.sign.cmd_setup") as mock_setup,
    ):
        url, timeout, _profile = _require_server_config()
        mock_setup.assert_called_once()
        assert url == "https://example.com"
        assert timeout == 120


def test_require_server_config_default_timeout():
    from revenant.ui.cli.sign import _require_server_config

    with patch(
        "revenant.ui.cli.sign.get_server_config",
        return_value=("https://example.com", None, None),
    ):
        _url, timeout, _profile = _require_server_config()
        assert timeout == 120  # default timeout


# ── _cmd_logout ───────────────────────────────────────────────────────


def test_cmd_logout_calls_logout(capsys):
    from revenant.ui.cli import _cmd_logout

    with patch("revenant.config.logout") as mock_logout:
        _cmd_logout()
        mock_logout.assert_called_once()
    out = capsys.readouterr().out
    assert "Logged out" in out
    assert "revenant setup" in out


# ── _cmd_reset ────────────────────────────────────────────────────────


def test_cmd_reset_calls_reset_all(capsys):
    from revenant.ui.cli import _cmd_reset

    with patch("revenant.config.reset_all") as mock_reset:
        _cmd_reset()
        mock_reset.assert_called_once()
    out = capsys.readouterr().out
    assert "cleared" in out.lower()
    assert "revenant setup" in out


# ── _cmd_check ────────────────────────────────────────────────────────


def test_cmd_check_file_not_found_exits_1():
    from revenant.ui.cli import _cmd_check

    args = argparse.Namespace(pdf="/nonexistent/file.pdf", server=False)
    with pytest.raises(SystemExit) as exc_info:
        _cmd_check(args)
    assert exc_info.value.code == 1


def test_cmd_check_valid_pdf(tmp_path, capsys):
    from revenant.ui.cli import _cmd_check

    pdf = tmp_path / "test.pdf"
    pdf.write_bytes(b"fake pdf content")

    mock_result = {
        "valid": True,
        "structure_ok": True,
        "hash_ok": True,
        "signer": {"name": "Test User", "email": None, "organization": None, "dn": None},
        "details": ["Signer: Test User", "Algorithm: SHA-256"],
    }

    args = argparse.Namespace(pdf=str(pdf), server=False)

    with patch(
        "revenant.ui.cli.verify_all_embedded_signatures",
        return_value=[mock_result],
    ):
        _cmd_check(args)

    out = capsys.readouterr().out
    assert "VALID" in out


def test_cmd_check_unreadable_file_exits_1(tmp_path):
    from revenant.ui.cli import _cmd_check

    pdf = tmp_path / "test.pdf"
    pdf.write_bytes(b"data")

    args = argparse.Namespace(pdf=str(pdf), server=False)

    with (
        patch("pathlib.Path.read_bytes", side_effect=OSError("Permission denied")),
        pytest.raises(SystemExit) as exc_info,
    ):
        _cmd_check(args)
    assert exc_info.value.code == 1


def test_cmd_check_revenant_error_exits_1(tmp_path):
    from revenant.errors import RevenantError
    from revenant.ui.cli import _cmd_check

    pdf = tmp_path / "test.pdf"
    pdf.write_bytes(b"fake pdf")

    args = argparse.Namespace(pdf=str(pdf), server=False)

    with (
        patch(
            "revenant.ui.cli.verify_all_embedded_signatures",
            side_effect=RevenantError("No signatures found"),
        ),
        pytest.raises(SystemExit) as exc_info,
    ):
        _cmd_check(args)
    assert exc_info.value.code == 1


# ── cmd_sign ──────────────────────────────────────────────────────────


def test_cmd_sign_no_files_exits_1():
    from revenant.ui.cli.sign import cmd_sign

    args = argparse.Namespace(
        files=[],
        output=None,
        detached=False,
        dry_run=False,
        position="right-bottom",
        page="last",
        image=None,
        invisible=False,
        font=None,
        reason=None,
    )
    with pytest.raises(SystemExit) as exc_info:
        cmd_sign(args)
    assert exc_info.value.code == 1


def test_cmd_sign_output_with_multiple_files_exits_1():
    from revenant.ui.cli.sign import cmd_sign

    args = argparse.Namespace(
        files=["a.pdf", "b.pdf"],
        output="/tmp/out.pdf",
        detached=False,
        dry_run=False,
        position="right-bottom",
        page="last",
        image=None,
        invisible=False,
        font=None,
        reason=None,
    )
    with pytest.raises(SystemExit) as exc_info:
        cmd_sign(args)
    assert exc_info.value.code == 1


def test_cmd_sign_dry_run(tmp_path, capsys):
    from revenant.ui.cli.sign import cmd_sign

    pdf = tmp_path / "doc.pdf"
    pdf.write_bytes(b"%PDF-1.4 fake content")

    args = argparse.Namespace(
        files=[str(pdf)],
        output=None,
        detached=False,
        dry_run=True,
        position="right-bottom",
        page="last",
        image=None,
        invisible=False,
        font=None,
        reason=None,
    )

    with (
        patch(
            "revenant.ui.cli.sign.get_server_config",
            return_value=("https://example.com", 120, "test"),
        ),
        patch("revenant.ui.cli.sign.get_signer_name", return_value="Test User"),
        patch("revenant.ui.cli.sign.get_active_profile", return_value=MagicMock(font=None)),
    ):
        cmd_sign(args)

    out = capsys.readouterr().out
    assert "DRY RUN" in out
    assert "Would sign" in out


def test_cmd_sign_file_not_found(tmp_path, capsys):
    from revenant.ui.cli.sign import cmd_sign

    args = argparse.Namespace(
        files=[str(tmp_path / "nonexistent.pdf")],
        output=None,
        detached=False,
        dry_run=False,
        position="right-bottom",
        page="last",
        image=None,
        invisible=False,
        font=None,
        reason=None,
    )

    with (
        patch.dict("os.environ", {"REVENANT_USER": "u", "REVENANT_PASS": "p"}),
        patch("revenant.ui.cli.sign.get_credentials", return_value=(None, None)),
        patch(
            "revenant.ui.cli.sign.get_server_config",
            return_value=("https://example.com", 120, "test"),
        ),
        patch("revenant.ui.cli.sign.get_signer_name", return_value="Test User"),
        patch("revenant.ui.cli.sign.get_active_profile", return_value=MagicMock(font=None)),
        patch("revenant.ui.cli.sign.resolve_sig_fields", return_value=None),
        pytest.raises(SystemExit),
    ):
        cmd_sign(args)


# ── main() dispatch ───────────────────────────────────────────────────


def test_main_dispatches_logout():
    result = subprocess.run(
        [sys.executable, "-c", "from revenant.ui.cli import main; main()", "logout"],
        capture_output=True,
        text=True,
        timeout=10,
        env={**__import__("os").environ, "PYTHONPATH": str(Path(__file__).parent.parent / "src")},
    )
    # logout clears config -- will succeed even without config
    assert "Logged out" in result.stdout or result.returncode == 0


def test_main_dispatches_reset():
    result = subprocess.run(
        [sys.executable, "-c", "from revenant.ui.cli import main; main()", "reset"],
        capture_output=True,
        text=True,
        timeout=10,
        env={**__import__("os").environ, "PYTHONPATH": str(Path(__file__).parent.parent / "src")},
    )
    assert "cleared" in result.stdout.lower() or result.returncode == 0


# ── __main__.py entry point ──────────────────────────────────────────


def test_main_module_invokes_cli():
    """python -m revenant --help should exit 0 and print usage."""
    result = subprocess.run(
        [sys.executable, "-m", "revenant", "--help"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0
    assert "usage:" in result.stdout.lower()


def test_main_module_no_args_exits_nonzero():
    """python -m revenant with no subcommand should exit non-zero."""
    result = subprocess.run(
        [sys.executable, "-m", "revenant"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode != 0


def test_main_module_version():
    """python -m revenant --version should print version."""
    result = subprocess.run(
        [sys.executable, "-m", "revenant", "--version"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0
    assert "revenant" in result.stdout.lower()


def test_main_module_sign_help():
    """python -m revenant sign --help should print sign usage."""
    result = subprocess.run(
        [sys.executable, "-m", "revenant", "sign", "--help"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0
    assert "sign" in result.stdout.lower()


def test_main_module_check_help():
    """python -m revenant check --help should print check usage."""
    result = subprocess.run(
        [sys.executable, "-m", "revenant", "check", "--help"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0
    assert "check" in result.stdout.lower()
