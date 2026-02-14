"""
Command-line interface for Revenant.

Argument parsing, dispatch, and non-signing subcommands.
Signing logic lives in ``cli_sign``.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from ...config import BUILTIN_PROFILES, get_server_config
from ...constants import __version__
from ...core.pdf import verify_all_embedded_signatures
from ...errors import RevenantError
from .setup import cmd_setup
from .sign import cmd_sign
from .verify import cmd_info, cmd_verify


def _cmd_logout() -> None:
    """Clear credentials and identity, keeping server configuration."""
    from ...config import logout

    logout()
    print("Logged out. Server configuration preserved.")
    print("Run 'revenant setup' to log in again.")


def _cmd_reset() -> None:
    """Clear all configuration: credentials, identity, and server profile."""
    from ...config import reset_all

    reset_all()
    print("All configuration cleared.")
    print("Run 'revenant setup' to reconfigure.")


def _cmd_check(args: argparse.Namespace) -> None:
    """Check all embedded PDF signatures."""
    from ..helpers import format_size_kb
    from ..workflows import format_verify_results

    pdf_path = Path(args.pdf)

    if not pdf_path.exists():
        print(f"Error: {pdf_path} not found", file=sys.stderr)
        sys.exit(1)

    try:
        pdf_bytes = pdf_path.read_bytes()
    except OSError as e:
        print(f"Error: cannot read {pdf_path}: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Checking {pdf_path.name} ({format_size_kb(len(pdf_bytes))})...")

    try:
        results = verify_all_embedded_signatures(pdf_bytes)
    except RevenantError as e:
        print(f"  ERROR: {e}", file=sys.stderr)
        sys.exit(1)

    vr = format_verify_results(results)

    for entry in vr.entries:
        if vr.total_count > 1:
            print(f"\n  Signature {entry.index + 1}/{entry.total} ({entry.signer_name}):")
            indent = "    "
        else:
            indent = "  "

        for line in entry.detail_lines:
            print(f"{indent}{line}")

    # Server-side verification (optional)
    if getattr(args, "server", False):
        url, timeout, _ = get_server_config()
        if url and timeout:
            print("\n  Server verification...")
            from ...config import register_active_profile_tls
            from ...network.soap_transport import verify_pdf_server
            from ..helpers import format_server_verify_result

            register_active_profile_tls()
            server_result = verify_pdf_server(url, pdf_bytes, timeout)
            format_server_verify_result(server_result)
        else:
            print("\n  Server verification skipped: no server configured.")

    print()
    if vr.all_valid:
        sig_word = "signature" if vr.total_count == 1 else f"all {vr.total_count} signatures"
        print(f"  RESULT: {sig_word.capitalize()} VALID")
    else:
        print(f"  RESULT: {vr.failed_count} of {vr.total_count} signature(s) FAILED")
        sys.exit(1)


def main() -> None:
    from ...config import migrate_plaintext_password

    migrate_plaintext_password()

    url, _, _ = get_server_config()
    url_hint = f" (current: {url})" if url else " (run `revenant setup` first)"

    parser = argparse.ArgumentParser(
        prog="revenant",
        description="Cross-platform CLI for ARX CoSign electronic signatures.",
        epilog=(
            "Environment variables:\n"
            "  REVENANT_USER     Revenant username\n"
            "  REVENANT_PASS     Revenant password\n"
            f"  REVENANT_URL      SOAP endpoint{url_hint}\n"
            "  REVENANT_TIMEOUT  Timeout in seconds (default: 120)\n"
            "  REVENANT_NAME     Signer display name (overrides config from setup)\n"
            "\n"
            "Project:\n"
            "  https://github.com/lobotomoe/revenant\n"
            "  Bug reports: https://github.com/lobotomoe/revenant/issues\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-V", "--version", action="version", version=f"revenant {__version__}")

    sub = parser.add_subparsers(dest="command", help="Available commands")

    # sign
    p_sign = sub.add_parser("sign", help="Sign PDF document(s)")
    p_sign.add_argument("files", nargs="+", help="PDF file(s) to sign")
    p_sign.add_argument("-o", "--output", help="Output file path (single file only)")
    p_sign.add_argument(
        "-d",
        "--detached",
        action="store_true",
        default=False,
        help="Save detached .p7s signature instead of embedded PDF",
    )
    p_sign.add_argument(
        "-p",
        "--position",
        default="right-bottom",
        help=(
            "Signature position preset (default: right-bottom). "
            "Presets: right-bottom (rb), right-top (rt), left-bottom (lb), "
            "left-top (lt), center-bottom (cb)"
        ),
    )
    p_sign.add_argument(
        "--page",
        default="last",
        help=(
            "Page for the signature field (default: last). "
            "Use 'first', 'last', or a 1-based page number (e.g., 1 = first page)"
        ),
    )
    p_sign.add_argument(
        "--image",
        default=None,
        help="Signature image file (PNG or JPEG) shown in the signature field",
    )
    p_sign.add_argument(
        "--invisible",
        action="store_true",
        default=False,
        help="Create an invisible signature (no visual appearance on the page)",
    )
    p_sign.add_argument(
        "--font",
        choices=["noto-sans", "ghea-mariam", "ghea-grapalat"],
        default=None,
        help="Font for signature appearance (default: from profile)",
    )
    p_sign.add_argument(
        "--reason",
        default=None,
        help="Signature reason string (default: 'Signed with Revenant')",
    )
    p_sign.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="Show what would be done without actually signing",
    )

    # verify
    p_verify = sub.add_parser("verify", help="Verify a detached CMS signature")
    p_verify.add_argument("pdf", help="PDF file")
    p_verify.add_argument("-s", "--signature", help="Signature file (default: <pdf>.p7s)")

    # check
    p_check = sub.add_parser("check", help="Check an embedded PDF signature")
    p_check.add_argument("pdf", help="Signed PDF file")
    p_check.add_argument(
        "--server",
        action="store_true",
        default=False,
        help="Also run server-side verification (DssVerify) if a server is configured",
    )

    # info
    p_info = sub.add_parser("info", help="Show signature file details")
    p_info.add_argument("signature", help="CMS signature file (.p7s)")

    # setup
    p_setup = sub.add_parser(
        "setup",
        help="Configure server, credentials, and signer identity",
    )
    p_setup.add_argument(
        "--profile",
        default=None,
        help=f"Use a built-in server profile ({', '.join(sorted(BUILTIN_PROFILES))})",
    )

    # logout
    sub.add_parser("logout", help="Log out (clear credentials and identity, keep server)")

    # reset
    sub.add_parser("reset", help="Clear all configuration (server, credentials, identity)")

    # gui
    sub.add_parser("gui", help="Launch graphical interface")

    args = parser.parse_args()

    if args.command == "sign":
        cmd_sign(args)
    elif args.command == "verify":
        cmd_verify(args)
    elif args.command == "check":
        _cmd_check(args)
    elif args.command == "info":
        cmd_info(args)
    elif args.command == "logout":
        _cmd_logout()
    elif args.command == "reset":
        _cmd_reset()
    elif args.command == "setup":
        cmd_setup(args)
    elif args.command == "gui":
        from ..gui import main as gui_main

        gui_main()
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
