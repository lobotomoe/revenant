# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false
"""
Signature verification and inspection.

cmd_verify uses openssl CLI (graceful degradation if not installed).
cmd_info uses asn1crypto (cross-platform, no external tools).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from asn1crypto import cms as asn1_cms

if TYPE_CHECKING:
    import argparse


def cmd_verify(args: argparse.Namespace) -> None:
    """Verify a detached CMS signature using openssl."""
    pdf_path = Path(args.pdf)
    sig_path = Path(args.signature) if args.signature else pdf_path.with_suffix(".pdf.p7s")

    if not pdf_path.exists():
        print(f"Error: {pdf_path} not found", file=sys.stderr)
        sys.exit(1)
    if not sig_path.exists():
        print(f"Error: {sig_path} not found", file=sys.stderr)
        sys.exit(1)

    print(f"Verifying {pdf_path.name} against {sig_path.name}...")

    cmd = [
        "openssl",
        "cms",
        "-verify",
        "-inform",
        "DER",
        "-in",
        str(sig_path),
        "-content",
        str(pdf_path),
        "-binary",
        "-purpose",
        "any",
    ]

    print("  Using system trust store for chain verification")

    try:
        result = subprocess.run(cmd, capture_output=True, timeout=15)
        stderr = result.stderr.decode("utf-8", errors="replace").strip()

        if result.returncode == 0:
            print("  VALID: Signature verification succeeded.")
            if "Verification successful" in stderr:
                print(f"  {stderr}")
        else:
            print(f"  INVALID: {stderr}")
            sys.exit(1)
    except FileNotFoundError:
        print("Error: openssl not found. Install OpenSSL to verify signatures.", file=sys.stderr)
        sys.exit(1)
    except subprocess.TimeoutExpired:
        print("Error: openssl timed out after 15 seconds.", file=sys.stderr)
        sys.exit(1)


def cmd_info(args: argparse.Namespace) -> None:
    """Show info about a CMS signature file."""
    sig_path = Path(args.signature)
    if not sig_path.exists():
        print(f"Error: {sig_path} not found", file=sys.stderr)
        sys.exit(1)

    try:
        file_size = sig_path.stat().st_size
    except OSError as e:
        print(f"Error: cannot access {sig_path}: {e}", file=sys.stderr)
        sys.exit(1)
    print(f"Signature: {sig_path.name} ({file_size} bytes)")

    try:
        sig_bytes = sig_path.read_bytes()
    except OSError as e:
        print(f"Error reading {sig_path}: {e}", file=sys.stderr)
        sys.exit(1)
    try:
        content_info = asn1_cms.ContentInfo.load(sig_bytes)
        signed_data = content_info["content"]
        certs = signed_data["certificates"]
    except (ValueError, TypeError, KeyError, OSError) as e:
        print(f"  Error parsing signature: {e}", file=sys.stderr)
        return

    if not certs:
        print("  No certificates found in signature.")
        return

    cert_count = len(certs)
    print(f"\nCertificates ({cert_count}):")
    for i in range(cert_count):
        cert = certs[i].chosen
        if cert_count > 1:
            print(f"\n  [{i + 1}]")
        print(f"  Subject: {cert.subject.human_friendly}")
        print(f"  Issuer:  {cert.issuer.human_friendly}")
        print(f"  Serial:  {cert.serial_number}")
        print(
            f"  Valid:   {cert['tbs_certificate']['validity']['not_before'].native}"
            f" - {cert['tbs_certificate']['validity']['not_after'].native}"
        )
