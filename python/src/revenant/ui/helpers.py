"""
Common CLI helper functions for Revenant.

Extracted patterns from cli_setup.py and cli_sign.py to eliminate duplication.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..config import ServerProfile
    from ..errors import AuthError

__all__ = [
    "atomic_write",
    "confirm_choice",
    "default_detached_output_path",
    "default_output_path",
    "format_server_verify_result",
    "format_size_kb",
    "offer_save_credentials",
    "print_auth_failure",
    "prompt_credentials",
    "safe_input",
    "safe_read_file",
]

_BYTES_PER_KB = 1024  # Local constant avoids importing BYTES_PER_MB for a KB conversion


def format_size_kb(size_bytes: int) -> str:
    """Format a byte count as a human-readable KB string (e.g. '123.4 KB')."""
    return f"{size_bytes / _BYTES_PER_KB:.1f} KB"


def default_output_path(pdf_path: Path) -> Path:
    """Compute default output path for a signed PDF: '<stem>_signed.pdf'."""
    return pdf_path.with_name(f"{pdf_path.stem}_signed.pdf")


def default_detached_output_path(pdf_path: Path) -> Path:
    """Compute default output path for a detached signature: '<name>.pdf.p7s'."""
    return pdf_path.with_suffix(".pdf.p7s")


def safe_input(prompt: str) -> str | None:
    """Prompt user for input, returning None on EOF/KeyboardInterrupt.

    Prints a newline on interrupt to keep the terminal tidy.

    Args:
        prompt: The prompt string to display.

    Returns:
        Stripped user input, or None if cancelled (Ctrl-C, Ctrl-D).
    """
    try:
        return input(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return None


def confirm_choice(message: str, default_yes: bool = True) -> bool:
    """
    Prompt user for yes/no confirmation.

    Args:
        message: Question to ask the user (without the [Y/n] suffix).
        default_yes: If True, empty input defaults to yes. If False, defaults to no.

    Returns:
        True if the user confirmed, False otherwise.

    Examples:
        >>> if confirm_choice("Is this you?"):
        ...     # User said yes
        >>> if confirm_choice("Run setup?", default_yes=False):
        ...     # User explicitly said yes
    """
    suffix = "[Y/n]" if default_yes else "[y/N]"
    try:
        answer = input(f"{message} {suffix} ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return False

    if default_yes:
        return answer in ("", "y", "yes")
    else:
        return answer in ("y", "yes")


def safe_read_file(path: Path, kind: str = "file") -> bytes | None:
    """
    Read a file with uniform error handling.

    Checks existence first, then reads, catching OSError.

    Args:
        path: Path to the file to read.
        kind: Descriptive name for error messages (e.g., "PDF", "signature").

    Returns:
        File contents as bytes, or None if the file doesn't exist or can't be read.

    Example:
        >>> pdf_bytes = safe_read_file(Path("input.pdf"), "PDF")
        >>> if pdf_bytes is None:
        ...     sys.exit(1)
    """
    if not path.exists():
        print(f"Error: {kind} not found: {path}", file=sys.stderr)
        return None

    try:
        return path.read_bytes()
    except OSError as e:
        print(f"Error reading {kind}: {e}", file=sys.stderr)
        return None


def print_auth_failure(error: AuthError, profile: ServerProfile | None = None) -> None:
    """
    Print authentication failure message with account lockout warning.

    Args:
        error: The authentication error that occurred.
        profile: Server profile (used to show max_auth_attempts warning if set).

    Example:
        >>> try:
        ...     sign_pdf(...)
        ... except AuthError as e:
        ...     print_auth_failure(e, profile)
        ...     sys.exit(1)
    """
    print("AUTH FAILED", file=sys.stderr)
    print(f"  {error}", file=sys.stderr)
    if profile and profile.max_auth_attempts:
        print(
            f"  WARNING: account locks after {profile.max_auth_attempts} failed attempts!",
            file=sys.stderr,
        )


def prompt_credentials(username: str | None = None, password: str | None = None) -> tuple[str, str]:
    """
    Prompt for username and/or password interactively.

    Pre-fills with provided values if available. Handles EOFError/KeyboardInterrupt
    by exiting with a newline (prevents broken terminal state).

    Args:
        username: Pre-filled username (will skip prompt if provided).
        password: Pre-filled password (will skip prompt if provided).

    Returns:
        (username, password) tuple.

    Raises:
        SystemExit: If the user cancels (Ctrl-C, Ctrl-D) or provides empty input.

    Example:
        >>> user, pwd = prompt_credentials()
        >>> user, pwd = prompt_credentials(username="alice")  # Only prompt for password
    """
    if not username:
        try:
            username = input("Revenant username: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            sys.exit(1)

    if not password:
        try:
            import getpass

            password = getpass.getpass("Revenant password: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            sys.exit(1)

    if not username or not password:
        print("Error: username and password are required.", file=sys.stderr)
        sys.exit(1)

    return username, password


def offer_save_credentials(username: str, password: str) -> None:
    """Ask the user if they want to save credentials for future use.

    On confirmation, saves via config module and prints storage info.
    """
    from ..config import (
        get_credential_storage_info,
        is_keyring_available,
        save_credentials,
    )

    if confirm_choice("\nSave credentials for future use?"):
        save_credentials(username, password)
        storage = get_credential_storage_info()
        print(f"Credentials saved to: {storage}")
        if not is_keyring_available():
            print("  For secure storage, install: pip install keyring")
        print("  (env vars REVENANT_USER/REVENANT_PASS always take priority)")
    else:
        print("Credentials not saved.")


def atomic_write(path: Path, data: bytes) -> None:
    """Write data to a file atomically using temp file + rename.

    Prevents partial writes from leaving corrupt output files if
    the process is interrupted mid-write (e.g., disk full, Ctrl-C).

    Args:
        path: Target file path.
        data: Bytes to write.
    """
    fd, tmp_path = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    tmp = Path(tmp_path)
    try:
        os.write(fd, data)
        os.fsync(fd)
        os.close(fd)
        fd = -1
        tmp.replace(path)
    except Exception:
        if fd >= 0:
            os.close(fd)
        tmp.unlink(missing_ok=True)
        raise


def format_server_verify_result(result: object) -> None:
    """Print server-side verification result to stdout.

    Args:
        result: ServerVerifyResult from soap_transport.verify_pdf_server().
    """
    from ..network.soap import ServerVerifyResult

    if not isinstance(result, ServerVerifyResult):
        print("  Server verification: unexpected result type", file=sys.stderr)
        return

    if result.error:
        print(f"  Server: unavailable ({result.error})")
        return

    if result.signer_name:
        print(f"  Server signer: {result.signer_name}")
    if result.sign_time:
        print(f"  Server sign time: {result.sign_time}")
    if result.certificate_status:
        print(f"  Server certificate: {result.certificate_status}")

    if result.valid:
        print("  Server: VALID")
    else:
        print("  Server: FAILED")
