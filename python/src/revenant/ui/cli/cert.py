# SPDX-License-Identifier: Apache-2.0
"""Certificate information and expiration CLI command."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING

from ...core.cert_expiry import format_expiry_summary, format_validity_period
from ...errors import AuthError, RevenantError, TLSError

if TYPE_CHECKING:
    import argparse


def _print_cert_info(info: dict[str, str | None], indent: str = "  ") -> None:
    """Print certificate info fields."""
    if info.get("name"):
        print(f"{indent}Subject:      {info['name']}")
    if info.get("organization"):
        print(f"{indent}Organization: {info['organization']}")
    if info.get("email"):
        print(f"{indent}Email:        {info['email']}")
    if info.get("dn"):
        print(f"{indent}DN:           {info['dn']}")

    not_before = info.get("not_before")
    not_after = info.get("not_after")
    validity = format_validity_period(not_before, not_after)
    print(f"{indent}Valid:        {validity}")

    summary = format_expiry_summary(not_after)
    print(f"{indent}Status:       {summary}")


def _cert_from_server() -> None:
    """Fetch certificate info from the server via enum-certificates."""
    from ...config import (
        get_server_config,
        register_active_profile_tls,
        resolve_credentials,
    )
    from ...core.cert_info import discover_identity_from_server
    from ...network import SoapSigningTransport

    url, timeout, _ = get_server_config()
    if not url or not timeout:
        print("Error: no server configured. Run 'revenant setup' first.", file=sys.stderr)
        sys.exit(1)

    username, password = resolve_credentials()
    if not username or not password:
        from ..helpers import prompt_credentials

        username, password = prompt_credentials()

    register_active_profile_tls()
    transport = SoapSigningTransport(url)

    print(f"Fetching certificate from {url}...")
    try:
        info = discover_identity_from_server(transport, username, password, timeout)
    except AuthError as e:
        print(f"Error: authentication failed: {e}", file=sys.stderr)
        sys.exit(1)
    except TLSError as e:
        print(f"Error: connection failed: {e}", file=sys.stderr)
        sys.exit(1)
    except RevenantError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    print("\nCertificate:")
    _print_cert_info(info)


def _cert_from_pdf(pdf_path: Path) -> None:
    """Extract certificate info from a signed PDF."""
    from ..helpers import format_size_kb

    if not pdf_path.exists():
        print(f"Error: {pdf_path} not found", file=sys.stderr)
        sys.exit(1)

    try:
        pdf_bytes = pdf_path.read_bytes()
    except OSError as e:
        print(f"Error: cannot read {pdf_path}: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Reading {pdf_path.name} ({format_size_kb(len(pdf_bytes))})...")

    try:
        from ...core.cert_info import extract_all_cert_info_from_pdf

        certs = extract_all_cert_info_from_pdf(pdf_bytes)
    except RevenantError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    for i, info in enumerate(certs):
        if len(certs) > 1:
            print(f"\nCertificate [{i + 1}/{len(certs)}]:")
        else:
            print("\nCertificate:")
        _print_cert_info(info)


def cmd_cert(args: argparse.Namespace) -> None:
    """Show certificate details and expiration."""
    pdf_path = getattr(args, "pdf", None)
    if pdf_path:
        _cert_from_pdf(Path(pdf_path))
    else:
        _cert_from_server()
