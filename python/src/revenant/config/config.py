"""
Configuration management for Revenant.

Stores signer identity, server profile, and preferences in
~/.revenant/config.json.  Certificate extraction logic lives in
``discovery.py``; this module handles only config I/O.

Credential management lives in ``credentials.py``.
"""

from __future__ import annotations

__all__ = [
    "CONFIG_DIR",
    "CONFIG_FILE",
    "get_active_profile",
    "get_config_layer",
    "get_server_config",
    "get_signer_info",
    "get_signer_name",
    "logout",
    "reset_all",
    "save_server_config",
    "save_signer_info",
]

import logging
import os

from ..constants import DEFAULT_TIMEOUT_SOAP, ENV_TIMEOUT, ENV_URL, MAX_TIMEOUT, MIN_TIMEOUT
from ._storage import CONFIG_DIR, CONFIG_FILE, load_config, load_raw_config, save_config
from .profiles import BUILTIN_PROFILES, ServerProfile, make_custom_profile

_logger = logging.getLogger(__name__)


# ── Server config ────────────────────────────────────────────────────


def get_server_config() -> tuple[str | None, int | None, str | None]:
    """
    Resolve the active server URL and timeout.

    Priority: env vars > config file > built-in profile.

    Returns:
        (url, timeout, profile_name) or (None, None, None) if no
        profile is configured and no env vars are set.
    """
    config = load_config()

    # Env vars take top priority
    url = os.environ.get(ENV_URL, "").strip()
    timeout_str = os.environ.get(ENV_TIMEOUT, "").strip()

    profile_name = config.get("profile")

    if not url:
        url = config.get("url", "")

    if not url and profile_name:
        profile = BUILTIN_PROFILES.get(profile_name)
        if profile:
            url = profile.url

    # No URL from any source — setup not done
    if not url:
        return None, None, None

    config_timeout = config.get("timeout")
    if timeout_str:
        try:
            timeout = int(timeout_str)
            if timeout < MIN_TIMEOUT or timeout > MAX_TIMEOUT:
                _logger.warning(
                    "%s=%d out of range [%d, %d], using default",
                    ENV_TIMEOUT,
                    timeout,
                    MIN_TIMEOUT,
                    MAX_TIMEOUT,
                )
                timeout = DEFAULT_TIMEOUT_SOAP
        except ValueError:
            _logger.warning("Invalid %s value %r, using default", ENV_TIMEOUT, timeout_str)
            timeout = DEFAULT_TIMEOUT_SOAP
    elif config_timeout is not None:
        timeout = config_timeout
    elif profile_name and profile_name in BUILTIN_PROFILES:
        timeout = BUILTIN_PROFILES[profile_name].timeout
    else:
        timeout = DEFAULT_TIMEOUT_SOAP

    return url, timeout, profile_name


def get_active_profile() -> ServerProfile | None:
    """
    Get the ServerProfile for the currently configured server.

    Returns:
        ServerProfile (built-in or custom), or None if not configured.
    """
    config = load_config()
    profile_name = config.get("profile")

    if profile_name and profile_name in BUILTIN_PROFILES:
        return BUILTIN_PROFILES[profile_name]

    url = config.get("url", "")
    timeout = config.get("timeout", DEFAULT_TIMEOUT_SOAP)

    if url:
        return make_custom_profile(url, timeout)

    return None


def save_server_config(profile: ServerProfile) -> None:
    """
    Save server profile to config.

    Args:
        profile: A ServerProfile instance.
    """
    config = load_raw_config()
    config["profile"] = profile.name
    config["url"] = profile.url
    config["timeout"] = profile.timeout
    save_config(config)


# ── Signer identity ─────────────────────────────────────────────────


def get_signer_name() -> str | None:
    """
    Get the signer display name from config.

    Returns:
        str or None -- the saved signer CN, or None if not configured.
    """
    config = load_config()
    return config.get("name")


def get_signer_info() -> dict[str, str | None]:
    """
    Get all saved signer info from config.

    Returns:
        dict with keys: name, email, organization, dn (any may be None).
    """
    config = load_config()
    return {
        "name": config.get("name"),
        "email": config.get("email"),
        "organization": config.get("organization"),
        "dn": config.get("dn"),
    }


def save_signer_info(
    name: str,
    email: str | None = None,
    organization: str | None = None,
    dn: str | None = None,
) -> None:
    """Save signer identity to config file.

    Clears any previously saved identity fields that are not provided,
    ensuring stale data from a prior identity doesn't persist.
    """
    config = load_raw_config()
    config["name"] = name
    for key, value in (("email", email), ("organization", organization), ("dn", dn)):
        if value:
            config[key] = value
        else:
            config.pop(key, None)
    save_config(config)


def reset_all() -> None:
    """Clear all config: credentials, signer identity, and server profile.

    Returns the app to the unconfigured state (Layer 0), allowing the
    user to set up a different server via the setup wizard.
    """
    from .credentials import clear_credentials, clear_session_credentials

    clear_credentials()
    clear_session_credentials()
    save_config({})


# Identity keys cleared on logout (credentials handled by clear_credentials)
_IDENTITY_KEYS = ("name", "email", "organization", "dn")


def logout() -> None:
    """Clear credentials and signer identity, preserving server config.

    Returns the app to the server-configured state (Layer 1), allowing
    the user to log in with different credentials via the setup wizard.
    Server profile, URL, and timeout are preserved.
    """
    from .credentials import clear_credentials, clear_session_credentials

    clear_credentials()
    clear_session_credentials()

    # Remove identity keys (separate load/save since clear_credentials
    # already saved once -- we need a fresh read of the post-clear state)
    config = load_raw_config()
    changed = False
    for key in _IDENTITY_KEYS:
        if config.pop(key, None) is not None:
            changed = True
    if changed:
        save_config(config)


# ── Layer detection ──────────────────────────────────────────────────


def get_config_layer() -> int:
    """Determine the current configuration layer.

    Returns:
        0: Nothing configured (offline verify only).
        1: Server configured (offline + server verify).
        2: Server + identity configured (all features).
    """
    url, _, _ = get_server_config()
    if not url:
        return 0
    if not get_signer_name():
        return 1
    return 2
