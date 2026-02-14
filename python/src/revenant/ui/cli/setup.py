"""
Interactive setup wizard for Revenant CLI.

Configures server profile, credentials, and signer identity.
"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from ...config import (
    BUILTIN_PROFILES,
    CONFIG_FILE,
    ServerProfile,
    get_active_profile,
    get_profile,
    get_saved_username,
    get_signer_info,
    make_custom_profile,
    register_profile_tls_mode,
    save_server_config,
    save_signer_info,
)
from ...constants import DEFAULT_TIMEOUT_HTTP_GET, ENV_NAME, ENV_URL
from ...core.cert_info import discover_identity_from_server
from ...errors import AuthError, RevenantError, TLSError
from ...network.discovery import ping_server
from ...network.transport import get_host_tls_info
from ..helpers import (
    confirm_choice,
    offer_save_credentials,
    print_auth_failure,
    prompt_credentials,
    safe_input,
)

if TYPE_CHECKING:
    import argparse

# ── Setup steps ──────────────────────────────────────────────────────


def _choose_profile(preset_profile: str | None = None) -> ServerProfile:
    """
    Step 1: Choose a server profile.

    Returns a ServerProfile.
    """
    if preset_profile:
        try:
            profile = get_profile(preset_profile)
        except KeyError as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
        else:
            print(f"Using profile: {profile.display_name}")
            print(f"  URL: {profile.url}")
            return profile

    print("Choose a CoSign server:\n")

    # List built-in profiles
    profiles_list = sorted(BUILTIN_PROFILES.values(), key=lambda p: p.name)
    for i, p in enumerate(profiles_list, 1):
        print(f"  {i}. {p.display_name}")
    print(f"  {len(profiles_list) + 1}. Custom server (enter URL)")
    print()

    choice = safe_input(f"Your choice [1-{len(profiles_list) + 1}]: ")
    if choice is None:
        sys.exit(1)

    try:
        idx = int(choice) - 1
    except ValueError:
        print("Invalid choice.", file=sys.stderr)
        sys.exit(1)

    if idx < 0 or idx > len(profiles_list):
        print("Invalid choice.", file=sys.stderr)
        sys.exit(1)

    if idx < len(profiles_list):
        profile = profiles_list[idx]
        print(f"\nSelected: {profile.display_name}")
        print(f"  URL: {profile.url}")
        return profile

    # Custom server
    url = safe_input("\nServer SOAP URL (e.g. https://host:port/SAPIWS/DSS.asmx): ")
    if not url:
        print("Error: URL is required.", file=sys.stderr)
        sys.exit(1)

    return make_custom_profile(url)


def _ping(profile: ServerProfile) -> bool:
    """
    Step 2: Ping the server via WSDL fetch.

    Returns True on success, exits on failure.
    """
    print(f"\nContacting {profile.url}...", end=" ", flush=True)
    ok, info = ping_server(profile.url, timeout=DEFAULT_TIMEOUT_HTTP_GET)

    if ok:
        print(f"OK ({info})")
        host = urlparse(profile.url).hostname
        tls_info = get_host_tls_info(host) if host else None
        if tls_info:
            print(f"  TLS: {tls_info}")
        return True
    else:
        print("FAILED")
        print(f"  {info}", file=sys.stderr)
        print("\nCheck the URL and try again.", file=sys.stderr)
        sys.exit(1)


def _get_credentials(profile: ServerProfile) -> tuple[str, str]:
    """
    Step 3: Get credentials from the user.

    Returns (username, password).
    """
    print()
    if profile.max_auth_attempts:
        print(f"WARNING: account locks after {profile.max_auth_attempts} failed attempts!")
        print()

    return prompt_credentials()


def _discover_identity(
    profile: ServerProfile, url: str, username: str, password: str, timeout: int
) -> dict[str, str | None] | None:
    """
    Step 4: Discover signer identity using available methods.

    Tries methods in order from the profile.  Returns a dict with
    name/email/organization/dn, or None if the user skips.
    """
    for method in profile.identity_methods:
        if method == "server":
            info = _try_identity_from_server(url, username, password, timeout)
            if info:
                return info

        elif method == "manual":
            info = _try_identity_manual()
            if info:
                return info

    return None


# ── Identity discovery helpers ───────────────────────────────────────


def _try_identity_from_server(
    url: str, username: str, password: str, timeout: int
) -> dict[str, str | None] | None:
    """Attempt to discover identity by signing a dummy hash."""
    from ...network.soap_transport import SoapSigningTransport

    print("\nDiscovering signer identity from server...", end=" ", flush=True)

    try:
        transport = SoapSigningTransport(url)
        info = discover_identity_from_server(transport, username, password, timeout)
    except AuthError as e:
        print("FAILED")
        print_auth_failure(e)
        return None
    except (RevenantError, TLSError) as e:
        print("FAILED")
        print(f"  {e}", file=sys.stderr)
        print("  (will try other methods)")
        return None

    if not info.get("name"):
        print("no signer name found")
        return None

    print("OK")
    _print_signer_info(info)

    if confirm_choice("\nIs this you?"):
        return info

    return None


def _try_identity_manual() -> dict[str, str | None] | None:
    """Prompt the user to enter identity manually."""
    print("\nEnter signer identity manually:")

    name = safe_input("  Name (CN): ")
    if not name:
        print("  Name is required.", file=sys.stderr)
        return None

    email = safe_input("  Email (optional): ")
    if email is None:
        return None
    org = safe_input("  Organization (optional): ")
    if org is None:
        return None

    return {
        "name": name,
        "email": email or None,
        "organization": org or None,
        "dn": None,
    }


# ── UI helpers ───────────────────────────────────────────────────────


def _print_signer_info(info: dict[str, str | None]) -> None:
    """Display signer certificate info."""
    print(f"\n  Name (CN):    {info['name']}")
    if info.get("email"):
        print(f"  Email:        {info['email']}")
    if info.get("organization"):
        print(f"  Organization: {info['organization']}")
    if info.get("dn"):
        print(f"  Full DN:      {info['dn']}")


# ── Main setup command ───────────────────────────────────────────────


def cmd_setup(args: argparse.Namespace) -> None:
    """Interactive setup wizard -- configure server, credentials, and signer identity."""
    print("Revenant Setup Wizard")
    print("=" * 40)
    print()

    # Show current config if exists
    current = get_signer_info()
    saved_user = get_saved_username()
    current_profile = get_active_profile()
    if current_profile and (current["name"] or saved_user):
        print("Current configuration:")
        print(f"  Profile:      {current_profile.display_name}")
        print(f"  URL:          {current_profile.url}")
        if current["name"]:
            print(f"  Name:         {current['name']}")
        if current.get("email"):
            print(f"  Email:        {current['email']}")
        if current.get("organization"):
            print(f"  Organization: {current['organization']}")
        if saved_user:
            print(f"  Credentials:  saved (user: {saved_user})")
        print(f"  Config file:  {CONFIG_FILE}")
        print()

    # Step 1: Choose server profile
    preset_profile = getattr(args, "profile", None)
    profile = _choose_profile(preset_profile)

    # Pre-register TLS mode so transport uses correct strategy from the start
    register_profile_tls_mode(profile)

    # Step 2: Ping server
    _ping(profile)

    # Step 3: Credentials
    username, password = _get_credentials(profile)

    # Step 4: Discover signer identity
    info = _discover_identity(profile, profile.url, username, password, profile.timeout)

    if not info:
        print("\nSetup cancelled (no signer identity configured).")
        sys.exit(1)

    # Step 5: Save everything
    save_server_config(profile)
    name = info.get("name") or ""
    save_signer_info(
        name=name,
        email=info.get("email"),
        organization=info.get("organization"),
        dn=info.get("dn"),
    )

    print(f"\nSaved to {CONFIG_FILE}")
    print(f"  Server:  {profile.display_name}")
    print(f"  Signer:  {info['name']}")
    print(f"Override anytime with {ENV_URL} / {ENV_NAME} env variables.")

    # Offer to save credentials
    offer_save_credentials(username, password)
