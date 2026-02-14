"""Tests for revenant.ui.cli.verify -- signature verification and info commands."""

from __future__ import annotations

import argparse
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

import pytest

from revenant.ui.cli.verify import cmd_info, cmd_verify

if TYPE_CHECKING:
    from pathlib import Path

# ── cmd_verify ────────────────────────────────────────────────────


def test_cmd_verify_pdf_not_found(tmp_path: Path):
    args = argparse.Namespace(pdf=str(tmp_path / "missing.pdf"), signature=None)
    with pytest.raises(SystemExit):
        cmd_verify(args)


def test_cmd_verify_sig_not_found(tmp_path: Path):
    pdf = tmp_path / "test.pdf"
    pdf.write_bytes(b"PDF")
    sig = tmp_path / "test.pdf.p7s"
    # sig doesn't exist
    args = argparse.Namespace(pdf=str(pdf), signature=str(sig))
    with pytest.raises(SystemExit):
        cmd_verify(args)


def test_cmd_verify_success(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    pdf = tmp_path / "test.pdf"
    sig = tmp_path / "test.pdf.p7s"
    pdf.write_bytes(b"PDF")
    sig.write_bytes(b"SIG")

    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stderr = b"Verification successful"

    args = argparse.Namespace(pdf=str(pdf), signature=str(sig))
    with patch("subprocess.run", return_value=mock_result):
        cmd_verify(args)

    out = capsys.readouterr().out
    assert "VALID" in out


def test_cmd_verify_failure(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    pdf = tmp_path / "test.pdf"
    sig = tmp_path / "test.pdf.p7s"
    pdf.write_bytes(b"PDF")
    sig.write_bytes(b"SIG")

    mock_result = MagicMock()
    mock_result.returncode = 1
    mock_result.stderr = b"signature verification failed"

    args = argparse.Namespace(pdf=str(pdf), signature=str(sig))
    with patch("subprocess.run", return_value=mock_result), pytest.raises(SystemExit):
        cmd_verify(args)

    out = capsys.readouterr().out
    assert "INVALID" in out


def test_cmd_verify_openssl_not_found(tmp_path: Path):
    pdf = tmp_path / "test.pdf"
    sig = tmp_path / "test.pdf.p7s"
    pdf.write_bytes(b"PDF")
    sig.write_bytes(b"SIG")

    args = argparse.Namespace(pdf=str(pdf), signature=str(sig))
    with patch("subprocess.run", side_effect=FileNotFoundError), pytest.raises(SystemExit):
        cmd_verify(args)


# ── cmd_info ──────────────────────────────────────────────────────


def test_cmd_info_file_not_found(tmp_path: Path):
    args = argparse.Namespace(signature=str(tmp_path / "missing.p7s"))
    with pytest.raises(SystemExit):
        cmd_info(args)


def test_cmd_info_parse_error(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    sig = tmp_path / "bad.p7s"
    sig.write_bytes(b"not a CMS signature")
    args = argparse.Namespace(signature=str(sig))
    # Should not raise, just print error
    cmd_info(args)
    stderr = capsys.readouterr().err
    assert "Error parsing" in stderr


def test_cmd_info_no_certs(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    sig = tmp_path / "test.p7s"
    sig.write_bytes(b"dummy")
    args = argparse.Namespace(signature=str(sig))

    mock_content_info = MagicMock()
    mock_signed_data = MagicMock()
    mock_content_info.__getitem__ = MagicMock(return_value=mock_signed_data)
    mock_signed_data.__getitem__ = MagicMock(return_value=[])

    with patch("revenant.ui.cli.verify.asn1_cms.ContentInfo.load", return_value=mock_content_info):
        cmd_info(args)

    out = capsys.readouterr().out
    assert "No certificates" in out
