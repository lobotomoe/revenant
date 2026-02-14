"""Signing command handlers for Revenant CLI."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from ...config import (
    get_active_profile,
    get_credentials,
    get_server_config,
    get_signer_name,
    resolve_credentials,
)
from ...constants import (
    BYTES_PER_MB,
    DEFAULT_POSITION,
    DEFAULT_TIMEOUT_SOAP,
    ENV_NAME,
    ENV_PASS,
    ENV_USER,
    PDF_WARN_SIZE,
    __version__,
)
from ...errors import AuthError, RevenantError
from ..helpers import (
    default_detached_output_path,
    default_output_path,
    format_size_kb,
    offer_save_credentials,
    print_auth_failure,
    prompt_credentials,
    safe_read_file,
)
from ..workflows import SigningResult, resolve_sig_fields, sign_one_detached, sign_one_embedded
from .setup import cmd_setup

# Credential source tracking -- used to decide whether to offer saving
_CRED_SOURCE_ENV = "env"
_CRED_SOURCE_CONFIG = "config"
_CRED_SOURCE_PROMPT = "prompt"


def _resolve_cred_source() -> str:
    """Determine where credentials will come from (no secrets touched).

    Returns:
        One of _CRED_SOURCE_ENV, _CRED_SOURCE_CONFIG, _CRED_SOURCE_PROMPT.
    """
    env_user = os.environ.get(ENV_USER, "").strip()
    env_pass = os.environ.get(ENV_PASS, "").strip()
    if env_user and env_pass:
        return _CRED_SOURCE_ENV

    saved_user, saved_pass = get_credentials()
    if saved_user and saved_pass:
        return _CRED_SOURCE_CONFIG

    return _CRED_SOURCE_PROMPT


def _get_credentials() -> tuple[str, str]:
    """Get credentials from environment, config, or interactive prompt.

    Priority: env vars > config file > interactive prompt.

    Returns:
        (username, password).
    """
    # 1. Environment variables (highest priority)
    env_user = os.environ.get(ENV_USER, "").strip()
    env_pass = os.environ.get(ENV_PASS, "").strip()
    if env_user and env_pass:
        return env_user, env_pass

    # 2. Saved credentials in config
    saved_user, saved_pass = get_credentials()
    if saved_user and saved_pass:
        return saved_user, saved_pass

    # 3. Interactive prompt (pre-fill from partial env/config)
    username, password = resolve_credentials()
    username, password = prompt_credentials(username, password)
    return username, password


def _sign_one_embedded_cli(
    pdf_path_str: str,
    output_path: str | None,
    username: str,
    password: str,
    url: str,
    timeout: int,
    name: str | None = None,
    position: str = DEFAULT_POSITION,
    page: str | int = "last",
    image_path: str | None = None,
    dry_run: bool = False,
    visible: bool = True,
    font: str | None = None,
    reason: str = "Signed with Revenant",
) -> SigningResult:
    """Sign a single PDF with an embedded signature and print progress."""
    pdf_path = Path(pdf_path_str)

    pdf_bytes = safe_read_file(pdf_path, "PDF")
    if pdf_bytes is None:
        return SigningResult(ok=False, error_message="File not found or unreadable")

    if len(pdf_bytes) > PDF_WARN_SIZE:
        size_mb = len(pdf_bytes) / BYTES_PER_MB
        warn_mb = PDF_WARN_SIZE // BYTES_PER_MB
        print(
            f"  Warning: {pdf_path.name} is {size_mb:.0f} MB. "
            f"Files over {warn_mb} MB may be slow or fail.",
            file=sys.stderr,
        )

    out = Path(output_path) if output_path else default_output_path(pdf_path)

    if dry_run:
        page_display = page if isinstance(page, str) else page + 1  # Show 1-based
        print(f"  Would sign: {pdf_path.name} ({format_size_kb(len(pdf_bytes))})")
        print(f"    -> Output: {out.name}")
        print(f"    -> Position: {position}, Page: {page_display}")
        if image_path:
            print(f"    -> Image: {image_path}")
        return SigningResult(ok=True)

    fields = resolve_sig_fields()
    print(f"  Signing {pdf_path.name} ({format_size_kb(len(pdf_bytes))})...", end=" ", flush=True)

    result = sign_one_embedded(
        pdf_bytes,
        out,
        url,
        username,
        password,
        timeout,
        name=name,
        position=position,
        page=page,
        image_path=image_path,
        visible=visible,
        font=font,
        reason=reason,
        fields=fields,
    )

    if result.ok:
        print(f"OK -> {out.name} ({format_size_kb(result.output_size)})")
    elif result.auth_failed:
        print_auth_failure(AuthError(result.error_message or ""), get_active_profile())
    elif result.tls_error:
        print("TLS ERROR", file=sys.stderr)
        print(f"  {result.error_message}", file=sys.stderr)
    else:
        print("FAILED", file=sys.stderr)
        print(f"  {result.error_message}", file=sys.stderr)

    return result


def _sign_one_detached_cli(
    pdf_path_str: str, output_path: str | None, username: str, password: str, url: str, timeout: int
) -> SigningResult:
    """Sign a single PDF with a detached .p7s signature and print progress."""
    pdf_path = Path(pdf_path_str)

    pdf_bytes = safe_read_file(pdf_path, "PDF")
    if pdf_bytes is None:
        return SigningResult(ok=False, error_message="File not found or unreadable")

    if len(pdf_bytes) > PDF_WARN_SIZE:
        size_mb = len(pdf_bytes) / BYTES_PER_MB
        warn_mb = PDF_WARN_SIZE // BYTES_PER_MB
        print(
            f"  Warning: {pdf_path.name} is {size_mb:.0f} MB. "
            f"Files over {warn_mb} MB may be slow or fail.",
            file=sys.stderr,
        )

    sig_path = Path(output_path) if output_path else default_detached_output_path(pdf_path)

    print(f"  Signing {pdf_path.name} ({format_size_kb(len(pdf_bytes))})...", end=" ", flush=True)

    result = sign_one_detached(pdf_bytes, sig_path, url, username, password, timeout)

    if result.ok:
        print(f"OK -> {sig_path.name} ({result.output_size} bytes)")
    elif result.auth_failed:
        print_auth_failure(AuthError(result.error_message or ""), get_active_profile())
    elif result.tls_error:
        print("TLS ERROR", file=sys.stderr)
        print(f"  {result.error_message}", file=sys.stderr)
    else:
        print("FAILED", file=sys.stderr)
        print(f"  {result.error_message}", file=sys.stderr)

    return result


def _require_server_config() -> tuple[str, int, str | None]:
    """Get server config, offering setup wizard if not configured."""
    url, timeout, profile_name = get_server_config()
    if url:
        return url, timeout or DEFAULT_TIMEOUT_SOAP, profile_name

    # No config — offer interactive setup
    print("No saved configuration found.")
    try:
        answer = input("Run setup wizard? [Y/n] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(1)

    if answer in ("", "y", "yes"):
        # Run setup, then re-read config
        cmd_setup(argparse.Namespace(profile=None))
        url, timeout, profile_name = get_server_config()
        if url:
            print()
            return url, timeout or DEFAULT_TIMEOUT_SOAP, profile_name

    # User declined or setup didn't produce a config
    print("No server configured.", file=sys.stderr)
    print("Set REVENANT_URL env var or run `revenant setup`.", file=sys.stderr)
    sys.exit(1)


def cmd_sign(args: argparse.Namespace) -> None:
    """Handle the 'sign' subcommand."""
    from ...core.pdf import parse_page_spec

    files = args.files
    if not files:
        print("Error: no input files specified.", file=sys.stderr)
        sys.exit(1)

    detached = args.detached
    output = args.output
    dry_run = getattr(args, "dry_run", False)

    if output and len(files) > 1:
        print("Error: -o/--output can only be used with a single input file.", file=sys.stderr)
        sys.exit(1)

    # In dry run mode, we don't need credentials
    if dry_run:
        username, password = "", ""
        cred_source = "dry_run"
        url, timeout, _ = get_server_config()
        url = url or "(not configured)"
        timeout = timeout or DEFAULT_TIMEOUT_SOAP
    else:
        cred_source = _resolve_cred_source()
        username, password = _get_credentials()
        url, timeout, _ = _require_server_config()

    # Resolve signer name: REVENANT_NAME env > config file (from `revenant setup`)
    name = None
    if not detached:
        name = os.environ.get(ENV_NAME, "").strip() or None
    if not name and not detached:
        name = get_signer_name()
        if name:
            print(f"Using signer name from config: {name}")
            print("  (override with REVENANT_NAME env, reconfigure with: revenant setup)")

    # Signature position, page, and image (embedded mode only)
    position = getattr(args, "position", DEFAULT_POSITION) or DEFAULT_POSITION
    page_raw = getattr(args, "page", "last") or "last"
    try:
        page = parse_page_spec(page_raw)
    except RevenantError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    image_path = getattr(args, "image", None)
    visible = not getattr(args, "invisible", False)
    reason = getattr(args, "reason", None) or "Signed with Revenant"

    # Font: CLI --font overrides profile default
    font = getattr(args, "font", None)
    if font is None:
        profile = get_active_profile()
        if profile:
            font = profile.font

    mode_label = "detached .p7s" if detached else "embedded PDF"
    cred_label = {
        _CRED_SOURCE_ENV: "environment",
        _CRED_SOURCE_CONFIG: "saved config",
        _CRED_SOURCE_PROMPT: "interactive",
    }
    print(f"Revenant CLI v{__version__}")
    print(f"Endpoint: {url}")
    if dry_run:
        print("Mode: DRY RUN (no actual signing)")
    else:
        print(f"Credentials: {cred_label.get(cred_source, cred_source)}")
        print(f"Mode: {mode_label}")
    if not detached:
        print(f"Position: {position}, Page: {page_raw}")
    print()

    success = 0
    failed = 0

    for pdf_file in files:
        if detached:
            if dry_run:
                pdf_path = Path(pdf_file)
                print(f"  Would sign: {pdf_path.name} (detached .p7s)")
                result = SigningResult(ok=True)
            else:
                result = _sign_one_detached_cli(pdf_file, output, username, password, url, timeout)
        else:
            result = _sign_one_embedded_cli(
                pdf_file,
                output,
                username,
                password,
                url,
                timeout,
                name=name,
                position=position,
                page=page,
                image_path=image_path,
                dry_run=dry_run,
                visible=visible,
                font=font,
                reason=reason,
            )
        if result.ok:
            success += 1
        else:
            failed += 1
            # Stop batch on auth failure to prevent account lockout.
            # EKENG locks accounts after 5 failed attempts — continuing
            # would burn remaining attempts with the same bad credentials.
            if result.auth_failed:
                remaining = len(files) - success - failed
                if remaining > 0:
                    print(
                        f"\n  Stopping: {remaining} file(s) skipped to prevent account lockout.",
                        file=sys.stderr,
                    )
                break

    print()
    if dry_run:
        print(f"Dry run complete: {success} file(s) would be signed.")
    elif failed:
        print(f"Done: {success} signed, {failed} failed.")
        sys.exit(1)
    else:
        print(f"Done: {success} signed.")

    # Offer to save credentials if they came from interactive prompt
    if success > 0 and cred_source == _CRED_SOURCE_PROMPT:
        offer_save_credentials(username, password)
