"""
Credential management for Revenant.

Credentials are stored securely via the system keychain (keyring)
when available, falling back to config file storage otherwise.
"""

from __future__ import annotations

__all__ = [
    "clear_credentials",
    "clear_session_credentials",
    "get_credential_storage_info",
    "get_credentials",
    "is_keyring_available",
    "migrate_plaintext_password",
    "resolve_credentials",
    "save_credentials",
    "set_session_credentials",
]

import logging
import os
import threading
from typing import TYPE_CHECKING

from ..constants import ENV_PASS, ENV_USER
from ._storage import CONFIG_FILE, load_config, load_raw_config, save_config

if TYPE_CHECKING:
    import types

# Keyring service name for credential storage
_KEYRING_SERVICE = "revenant"

# Try to import keyring for secure credential storage
_keyring_available = False
_KeyringError: type[Exception] | None = None
_keyring_mod: types.ModuleType | None = None
try:
    import keyring as _kr
    from keyring.errors import KeyringError as _KRError

    _keyring_available = True
    _KeyringError = _KRError
    _keyring_mod = _kr
except ImportError:
    pass

_logger = logging.getLogger(__name__)

# Session-level credential cache (not persisted to disk).
# Set during setup wizard so the user can sign in the current session
# even if they chose not to save credentials to disk.
# Protected by _session_lock for thread safety (GUI uses background threads).
_session_lock = threading.Lock()
_session_username: str | None = None
_session_password: str | None = None


def set_session_credentials(username: str, password: str) -> None:
    """Cache credentials in memory for the current app session."""
    global _session_username, _session_password
    with _session_lock:
        _session_username = username
        _session_password = password


def clear_session_credentials() -> None:
    """Clear the in-memory session credential cache."""
    global _session_username, _session_password
    with _session_lock:
        _session_username = None
        _session_password = None


def _keyring_ready() -> bool:
    """Return True when keyring module AND its error type are importable."""
    return _keyring_available and _keyring_mod is not None and _KeyringError is not None


def _keyring_delete(username: str) -> None:
    """Delete a single keyring entry for the given username (best-effort)."""
    if not _keyring_ready() or not username:
        return
    if _keyring_mod is None or _KeyringError is None:
        raise RuntimeError("Keyring module/error is None despite passing readiness check")
    try:
        _keyring_mod.delete_password(_KEYRING_SERVICE, username)
        _logger.debug("Deleted keyring entry")
    except _KeyringError:
        pass  # entry doesn't exist — fine
    except (OSError, RuntimeError) as e:
        _logger.debug("Keyring delete failed: %s", e)


def is_keyring_available() -> bool:
    """Check if secure keyring storage is available."""
    return _keyring_available


def get_credential_storage_info() -> str:
    """Return human-readable description of where credentials are stored.

    Shows the storage backend name so the user knows where passwords go.
    """
    if _keyring_ready():
        if _keyring_mod is None:
            raise RuntimeError("Keyring module is None despite passing readiness check")
        backend = _keyring_mod.get_keyring()
        module = type(backend).__module__ or ""
        if "macOS" in module:
            return "macOS Keychain"
        if "Windows" in module or "WinVault" in module:
            return "Windows Credential Manager"
        if "SecretService" in module:
            return "Linux Secret Service"
        if "KWallet" in module:
            return "KDE Wallet"
        return f"System keychain ({type(backend).__name__})"

    return f"{CONFIG_FILE} (plaintext)"


def resolve_credentials() -> tuple[str, str]:
    """Resolve credentials from env vars or saved config.

    Priority: env vars > saved credentials (partial merge allowed --
    e.g. username from env, password from config).

    Returns:
        (username, password) -- may be empty strings if not configured.
    """
    source = "none"

    user = os.environ.get(ENV_USER, "").strip()
    pwd = os.environ.get(ENV_PASS, "").strip()
    if user or pwd:
        source = "env"

    # Session cache (set during setup wizard)
    with _session_lock:
        session_user = _session_username
        session_pass = _session_password
    if not user and session_user:
        user = session_user
        source = "session"
    if not pwd and session_pass:
        pwd = session_pass
        if source != "session":
            source = "session+other"

    # Saved credentials (config file / keyring)
    if not user or not pwd:
        saved_user, saved_pass = get_credentials()
        if saved_user and not user:
            user = saved_user
            source = "saved"
        if saved_pass and not pwd:
            pwd = saved_pass

    _logger.debug(
        "resolve_credentials: has_user=%s, has_pwd=%s, source=%s", bool(user), bool(pwd), source
    )
    return user, pwd


def migrate_plaintext_password() -> None:
    """Remove plaintext password from config file if keyring has it.

    Called lazily from get_credentials() on first use, so the macOS Keychain
    prompt (if triggered) appears in context rather than at app startup.
    Idempotent -- safe to call multiple times.
    """
    if not _keyring_ready():
        return
    if _keyring_mod is None or _KeyringError is None:
        raise RuntimeError("Keyring module/error is None despite passing readiness check")

    config = load_config()
    username = config.get("username")
    if not isinstance(username, str) or not username:
        return
    if not config.get("password"):
        return  # no plaintext password to migrate

    try:
        keyring_password = _keyring_mod.get_password(_KEYRING_SERVICE, username)
    except (_KeyringError, OSError, RuntimeError):
        return  # can't verify keyring has it — don't remove plaintext

    if keyring_password:
        raw = load_raw_config()
        if raw.pop("password", None):
            save_config(raw)
            _logger.info("Migrated: removed plaintext password from config file")


def get_saved_username() -> str | None:
    """Return the saved username without touching secrets.

    This is safe to use in display/logging contexts because it never
    accesses the password from keyring or config.

    Returns:
        The saved username, or None if no credentials are configured.
    """
    config = load_config()
    username = config.get("username")
    if isinstance(username, str) and username:
        return username
    return None


def get_credentials() -> tuple[str | None, str | None]:
    """
    Get saved Revenant credentials.

    Retrieves password from system keychain if keyring is available,
    otherwise falls back to config file.  Also runs one-time plaintext
    migration on first call.

    Returns:
        (username, password) where:
        - (None, None) if no credentials are saved at all.
        - (username, None) if username exists but password is inaccessible
          (e.g. keychain access was denied).
        - (username, password) if both are available.
    """
    migrate_plaintext_password()
    config = load_config()
    username = config.get("username")
    if not isinstance(username, str) or not username:
        _logger.debug("get_credentials: no username in config -> (None, None)")
        return None, None

    _logger.debug("get_credentials: found username in config")

    # Try keyring first
    if _keyring_ready():
        if _keyring_mod is None or _KeyringError is None:
            raise RuntimeError("Keyring module/error is None despite passing readiness check")
        try:
            password = _keyring_mod.get_password(_KEYRING_SERVICE, username)
        except _KeyringError as e:
            # Expected keyring failure (locked, access denied, etc.)
            _logger.debug("Keyring read failed, trying config file: %s", e)
        except (OSError, RuntimeError) as e:
            # OS-level failures from certain keyring backends
            _logger.debug("Keyring backend error, trying config file: %s", e)
        else:
            if password:
                _logger.debug("get_credentials: found password in keyring")
                return username, password
            _logger.debug("get_credentials: keyring returned None")

    # Fallback to config file (legacy or keyring unavailable)
    password = config.get("password")
    if isinstance(password, str) and password:
        _logger.debug("get_credentials: found password in config file (plaintext)")
        return username, password

    _logger.debug("get_credentials: username found but no password anywhere")
    return username, None


def save_credentials(username: str, password: str) -> bool:
    """
    Save Revenant credentials securely.

    Stores password in system keychain if keyring is available,
    otherwise falls back to config file (chmod 600).

    If the username changed since last save, the old keyring entry
    is removed to prevent stale entries from accumulating.

    Args:
        username: Revenant username.
        password: Revenant password.

    Returns:
        True if password was stored in the system keychain (secure).
        False if it fell back to the config file (plaintext).
    """
    config = load_raw_config()
    old_username = config.get("username")

    # Clean up old keyring entry if username changed
    if isinstance(old_username, str) and old_username != username:
        _keyring_delete(old_username)

    config["username"] = username

    # Try to store password in keyring
    if _keyring_ready():
        if _keyring_mod is None or _KeyringError is None:
            raise RuntimeError("Keyring module/error is None despite passing readiness check")
        try:
            _keyring_mod.set_password(_KEYRING_SERVICE, username, password)
        except _KeyringError as e:
            # Expected keyring failure (locked, access denied, etc.)
            _logger.warning("Keyring save failed, using config file: %s", e)
        except (OSError, RuntimeError) as e:
            # OS-level failures from certain keyring backends
            _logger.warning("Keyring backend error, using config file: %s", e)
        else:
            # Success - remove password from config file if it was there
            config.pop("password", None)
            save_config(config)
            return True

    # Fallback to config file
    if not _keyring_available:
        _logger.warning(
            "Keyring unavailable. Password will be saved in plaintext (%s). "
            "Install keyring for secure storage: pip install keyring",
            CONFIG_FILE,
        )
    config["password"] = password
    save_config(config)
    return False


def clear_credentials() -> None:
    """Remove saved credentials from all storage backends."""
    config = load_raw_config()
    username = config.get("username")

    _logger.info(
        "Clearing credentials: has_username=%s, password_in_config=%s, keyring=%s",
        bool(username),
        "password" in config,
        _keyring_ready(),
    )

    # Clear from keyring
    if isinstance(username, str):
        _keyring_delete(username)

    # Clear from config file
    config.pop("username", None)
    config.pop("password", None)
    save_config(config)
    _logger.info("Config saved without credentials. Keys remaining: %s", list(config.keys()))
