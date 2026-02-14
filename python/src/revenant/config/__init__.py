"""
Configuration and server profile management.

Unified API for all config-related functionality. Instead of importing
from individual submodules (config, credentials, profiles), import from
this package directly.
"""

from __future__ import annotations

import logging

# Server configuration
from .config import (
    CONFIG_FILE,
    get_active_profile,
    get_config_layer,
    get_server_config,
    get_signer_info,
    get_signer_name,
    logout,
    reset_all,
    save_server_config,
    save_signer_info,
)

# Credentials management
from .credentials import (
    clear_credentials,
    clear_session_credentials,
    get_credential_storage_info,
    get_credentials,
    get_saved_username,
    is_keyring_available,
    migrate_plaintext_password,
    resolve_credentials,
    save_credentials,
    set_session_credentials,
)

# Server profiles
from .profiles import (
    BUILTIN_PROFILES,
    CertField,
    ServerProfile,
    SigField,
    get_profile,
    make_custom_profile,
)

_logger = logging.getLogger(__name__)


def register_profile_tls_mode(profile: ServerProfile) -> None:
    """
    Register a specific profile's TLS mode with the transport layer.

    Use this in setup wizards when working with a profile that hasn't been
    saved to config yet. For normal operation, use register_active_profile_tls().

    Args:
        profile: ServerProfile with url and legacy_tls attributes.
    """
    from urllib.parse import urlparse

    from ..network.transport import register_host_tls

    host = urlparse(profile.url).hostname
    if host:
        register_host_tls(host, profile.legacy_tls)
        _logger.debug(
            "Registered TLS mode for %s: %s", host, "legacy" if profile.legacy_tls else "standard"
        )


def register_active_profile_tls() -> None:
    """
    Register the active profile's TLS mode with the transport layer.

    This function bridges config and transport layers: it reads the active
    server profile and registers its TLS requirements (standard HTTPS or
    legacy TLS) with the transport module.

    Should be called by UI code before making any network requests.
    """
    profile = get_active_profile()
    if profile is not None:
        register_profile_tls_mode(profile)


__all__ = [
    "BUILTIN_PROFILES",
    "CONFIG_FILE",
    "CertField",
    "ServerProfile",
    "SigField",
    "clear_credentials",
    "clear_session_credentials",
    "get_active_profile",
    "get_config_layer",
    "get_credential_storage_info",
    "get_credentials",
    "get_profile",
    "get_saved_username",
    "get_server_config",
    "get_signer_info",
    "get_signer_name",
    "is_keyring_available",
    "logout",
    "make_custom_profile",
    "migrate_plaintext_password",
    "register_active_profile_tls",
    "register_profile_tls_mode",
    "reset_all",
    "resolve_credentials",
    "save_credentials",
    "save_server_config",
    "save_signer_info",
    "set_session_credentials",
]
