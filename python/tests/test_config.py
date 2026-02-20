"""Tests for revenant.config — config management and cert extraction."""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from revenant.config._storage import load_config, load_raw_config, save_config
from revenant.config.config import (
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
from revenant.config.credentials import (
    clear_credentials,
    get_credentials,
    resolve_credentials,
    save_credentials,
)
from revenant.config.profiles import (
    ServerProfile,
    get_profile,
    make_custom_profile,
)


@pytest.fixture
def config_dir(tmp_path):
    """Redirect config to a temp directory and disable real keyring.

    Keyring is disabled by default to prevent tests from polluting
    the real system keychain. Use the ``keyring_enabled`` fixture
    to test with a fake in-memory keyring backend.
    """
    config_file = tmp_path / "config.json"
    with (
        patch("revenant.config._storage.CONFIG_DIR", tmp_path),
        patch("revenant.config._storage.CONFIG_FILE", config_file),
        patch("revenant.config.credentials._keyring_available", False),
        patch("revenant.config.credentials._keyring_mod", None),
        patch("revenant.config.credentials._KeyringError", None),
    ):
        yield tmp_path, config_file


# ── load_config / save_config ─────────────────────────────────────


def test_load_empty(config_dir):
    """Loading when no config file exists should return empty dict."""
    assert load_config() == {}


def test_save_and_load(config_dir):
    _, config_file = config_dir
    save_config({"name": "Alice", "email": "alice@example.com"})
    assert config_file.exists()

    loaded = load_config()
    assert loaded.get("name") == "Alice"
    assert loaded.get("email") == "alice@example.com"


def test_load_corrupt_json(config_dir):
    _, config_file = config_dir
    config_file.write_text("{broken json", encoding="utf-8")
    assert load_config() == {}


def test_load_raw_config_os_error(config_dir):
    """OSError when reading config file should return empty dict."""
    _, config_file = config_dir
    config_file.write_text('{"name": "Alice"}', encoding="utf-8")
    with patch.object(type(config_file), "read_text", side_effect=OSError("permission denied")):
        assert load_raw_config() == {}


def test_load_config_timeout_out_of_range(config_dir):
    """Timeout outside [MIN_TIMEOUT, MAX_TIMEOUT] should be ignored."""
    save_config({"timeout": 99999})
    loaded = load_config()
    assert "timeout" not in loaded


def test_save_config_chmod_dir_oserror(config_dir):
    """If chmod on CONFIG_DIR fails, save should still succeed."""
    import os

    if os.name == "nt":
        pytest.skip("chmod test not applicable on Windows")

    tmp_path, config_file = config_dir
    with patch.object(type(tmp_path), "chmod", side_effect=OSError("permission denied")):
        save_config({"name": "test"})
    assert config_file.exists()
    loaded = load_config()
    assert loaded.get("name") == "test"


def test_save_config_chmod_tmpfile_oserror(config_dir):
    """If chmod on temp file fails, save should still complete with warning."""
    import os

    if os.name == "nt":
        pytest.skip("chmod test not applicable on Windows")

    tmp_path, config_file = config_dir

    original_chmod = type(tmp_path).chmod

    def selective_chmod(self, mode):
        # Fail on temp files (.tmp suffix), succeed on config dir
        if str(self).endswith(".tmp"):
            raise OSError("permission denied")
        return original_chmod(self, mode)

    with patch.object(type(tmp_path), "chmod", selective_chmod):
        save_config({"name": "test"})
    assert config_file.exists()
    loaded = load_config()
    assert loaded.get("name") == "test"


def test_save_config_write_failure_cleans_up(config_dir):
    """BaseException during write should clean up temp file and re-raise."""
    tmp_path, _config_file = config_dir

    def failing_fdopen(fd, *args, **kwargs):
        # Don't close fd — let the cleanup block handle it
        raise OSError("disk full")

    with patch("os.fdopen", failing_fdopen), pytest.raises(OSError, match="disk full"):
        save_config({"name": "test"})

    # Temp file should be cleaned up
    tmp_files = list(tmp_path.glob("*.tmp"))
    assert tmp_files == []


# ── get_signer_name ─────────────────────────────────────────────────


def test_get_signer_name_empty(config_dir):
    assert get_signer_name() is None


def test_get_signer_name_set(config_dir):
    _, _config_file = config_dir
    save_config({"name": "Bob"})
    assert get_signer_name() == "Bob"


# ── get_signer_info ─────────────────────────────────────────────────


def test_get_signer_info_empty(config_dir):
    info = get_signer_info()
    assert info["name"] is None
    assert info["email"] is None
    assert info["organization"] is None
    assert info["dn"] is None


def test_get_signer_info_partial(config_dir):
    save_config({"name": "Charlie", "email": "charlie@test.com"})
    info = get_signer_info()
    assert info["name"] == "Charlie"
    assert info["email"] == "charlie@test.com"
    assert info["organization"] is None


# ── save_signer_info ────────────────────────────────────────────────


def test_save_signer_info_basic(config_dir):
    save_signer_info("Dave")
    assert get_signer_name() == "Dave"


def test_save_signer_info_full(config_dir):
    save_signer_info(
        name="Eve",
        email="eve@example.com",
        organization="Acme Corp",
        dn="CN=Eve, O=Acme Corp",
    )
    info = get_signer_info()
    assert info["name"] == "Eve"
    assert info["email"] == "eve@example.com"
    assert info["organization"] == "Acme Corp"
    assert info["dn"] == "CN=Eve, O=Acme Corp"


def test_save_preserves_existing(config_dir):
    """Saving should merge with existing config, not overwrite."""
    save_config({"name": "Old", "custom_key": "keep_me"})
    save_signer_info("New", email="new@test.com")

    loaded = load_config()
    assert loaded.get("name") == "New"
    assert loaded.get("email") == "new@test.com"
    # Unknown keys are preserved on disk (forward-compat) but not in typed view
    raw = load_raw_config()
    assert raw["custom_key"] == "keep_me"


def test_config_is_valid_json(config_dir):
    _, config_file = config_dir
    save_signer_info("Frank")
    data = json.loads(config_file.read_text(encoding="utf-8"))
    assert data["name"] == "Frank"


# ── Credential management ──────────────────────────────────────────


def test_get_credentials_empty(config_dir):
    user, pwd = get_credentials()
    assert user is None
    assert pwd is None


def test_save_and_get_credentials(config_dir):
    save_credentials("myuser", "mypass")
    user, pwd = get_credentials()
    assert user == "myuser"
    assert pwd == "mypass"


def test_clear_credentials(config_dir):
    save_credentials("myuser", "mypass")
    clear_credentials()
    user, pwd = get_credentials()
    assert user is None
    assert pwd is None


def test_credentials_preserve_signer_info(config_dir):
    """Saving credentials should not overwrite signer info."""
    save_signer_info("Alice", email="alice@test.com")
    save_credentials("myuser", "mypass")

    assert get_signer_name() == "Alice"
    info = get_signer_info()
    assert info["email"] == "alice@test.com"

    user, pwd = get_credentials()
    assert user == "myuser"
    assert pwd == "mypass"


def test_signer_info_preserves_credentials(config_dir):
    """Saving signer info should not overwrite credentials."""
    save_credentials("myuser", "mypass")
    save_signer_info("Bob")

    user, pwd = get_credentials()
    assert user == "myuser"
    assert pwd == "mypass"


def test_config_file_permissions(config_dir):
    """Config file should have restricted permissions (0600)."""
    import os
    import stat

    _, config_file = config_dir
    save_credentials("user", "pass")

    if os.name != "nt":  # skip on Windows
        mode = stat.S_IMODE(config_file.stat().st_mode)
        assert mode == 0o600, f"Expected 0600, got {oct(mode)}"


def test_get_credentials_partial(config_dir):
    """Only username saved (no password) should return (username, None)."""
    save_config({"username": "onlyuser"})
    user, pwd = get_credentials()
    assert user == "onlyuser"
    assert pwd is None


# ── resolve_credentials ───────────────────────────────────────────


def test_resolve_credentials_from_env(config_dir):
    """Env vars should take priority over saved config."""
    save_credentials("saved_user", "saved_pass")
    with patch.dict("os.environ", {"REVENANT_USER": "env_user", "REVENANT_PASS": "env_pass"}):
        user, pwd = resolve_credentials()
        assert user == "env_user"
        assert pwd == "env_pass"


def test_resolve_credentials_from_config(config_dir):
    """Should fall back to saved config when no env vars."""
    save_credentials("cfg_user", "cfg_pass")
    with patch.dict("os.environ", {"REVENANT_USER": "", "REVENANT_PASS": ""}, clear=False):
        user, pwd = resolve_credentials()
        assert user == "cfg_user"
        assert pwd == "cfg_pass"


def test_resolve_credentials_partial_merge(config_dir):
    """Should merge: user from env, password from config."""
    save_credentials("cfg_user", "cfg_pass")
    with patch.dict("os.environ", {"REVENANT_USER": "env_user", "REVENANT_PASS": ""}, clear=False):
        user, pwd = resolve_credentials()
        assert user == "env_user"
        assert pwd == "cfg_pass"


def test_resolve_credentials_empty(config_dir):
    """Should return empty strings when nothing is configured."""
    with patch.dict("os.environ", {"REVENANT_USER": "", "REVENANT_PASS": ""}, clear=False):
        user, pwd = resolve_credentials()
        assert user == ""
        assert pwd == ""


# ── Keyring integration tests ─────────────────────────────────────


class FakeKeyringError(Exception):
    """Fake keyring error for testing."""


class FakeKeyring:
    """In-memory keyring mock for testing."""

    def __init__(self):
        self._store: dict[tuple[str, str], str] = {}

    def get_password(self, service: str, username: str) -> str | None:
        return self._store.get((service, username))

    def set_password(self, service: str, username: str, password: str) -> None:
        self._store[(service, username)] = password

    def delete_password(self, service: str, username: str) -> None:
        self._store.pop((service, username), None)


@pytest.fixture
def keyring_enabled(config_dir):
    """Enable keyring with a fake in-memory backend."""
    fake = FakeKeyring()
    with (
        patch("revenant.config.credentials._keyring_available", True),
        patch("revenant.config.credentials._keyring_mod", fake),
        patch("revenant.config.credentials._KeyringError", FakeKeyringError),
    ):
        yield fake


@pytest.fixture
def keyring_disabled(config_dir):
    """Disable keyring completely."""
    with (
        patch("revenant.config.credentials._keyring_available", False),
        patch("revenant.config.credentials._keyring_mod", None),
        patch("revenant.config.credentials._KeyringError", None),
    ):
        yield


def test_save_credentials_uses_keyring(keyring_enabled):
    """When keyring is available, password should go to keyring, not config file."""
    fake = keyring_enabled
    save_credentials("alice", "secret123")

    # Password should be in keyring
    assert fake.get_password("revenant", "alice") == "secret123"

    # Password should NOT be in config file
    config = load_config()
    assert config.get("username") == "alice"
    assert "password" not in config


def test_get_credentials_from_keyring(keyring_enabled):
    """Should retrieve password from keyring when available."""
    fake = keyring_enabled
    fake.set_password("revenant", "bob", "keyring_pass")
    save_config({"username": "bob"})

    user, pwd = get_credentials()
    assert user == "bob"
    assert pwd == "keyring_pass"


def test_get_credentials_fallback_to_config(keyring_enabled):
    """If keyring has no password, should fallback to config file."""
    save_config({"username": "charlie", "password": "config_pass"})

    user, pwd = get_credentials()
    assert user == "charlie"
    assert pwd == "config_pass"


def test_save_credentials_without_keyring(keyring_disabled):
    """When keyring is disabled, password should go to config file."""
    save_credentials("dave", "fallback_pass")

    config = load_config()
    assert config.get("username") == "dave"
    assert config.get("password") == "fallback_pass"


def test_clear_credentials_clears_keyring(keyring_enabled):
    """clear_credentials should remove from both keyring and config."""
    fake = keyring_enabled
    fake.set_password("revenant", "eve", "to_delete")
    save_config({"username": "eve", "password": "also_delete"})

    clear_credentials()

    # Keyring should be cleared
    assert fake.get_password("revenant", "eve") is None

    # Config should be cleared
    config = load_config()
    assert "username" not in config
    assert "password" not in config


def test_keyring_error_fallback_on_save(keyring_enabled, config_dir):
    """If keyring.set_password fails, should fallback to config file."""

    class FailingKeyring(FakeKeyring):
        def set_password(self, service: str, username: str, password: str) -> None:
            raise RuntimeError("Keyring locked")

    failing = FailingKeyring()
    with patch("revenant.config.credentials._keyring_mod", failing):
        save_credentials("frank", "fallback_on_error")

    config = load_config()
    assert config.get("username") == "frank"
    assert config.get("password") == "fallback_on_error"


def test_keyring_error_fallback_on_read(keyring_enabled, config_dir):
    """If keyring.get_password fails, should fallback to config file."""

    class FailingKeyring(FakeKeyring):
        def get_password(self, service: str, username: str) -> str | None:
            raise RuntimeError("Keyring locked")

    failing = FailingKeyring()
    save_config({"username": "grace", "password": "config_fallback"})

    with patch("revenant.config.credentials._keyring_mod", failing):
        user, pwd = get_credentials()

    assert user == "grace"
    assert pwd == "config_fallback"


def test_save_removes_password_from_config_when_keyring_works(keyring_enabled):
    """If config had password and keyring works, password should be removed from config."""
    # Start with password in config (legacy state)
    save_config({"username": "henry", "password": "old_config_pass"})

    # Save new credentials — should go to keyring and remove from config
    save_credentials("henry", "new_keyring_pass")

    config = load_config()
    assert "password" not in config

    # Verify keyring has the new password
    fake = keyring_enabled
    assert fake.get_password("revenant", "henry") == "new_keyring_pass"


def test_save_credentials_cleans_old_keyring_entry(keyring_enabled):
    """Changing username should delete old keyring entry to prevent stale entries."""
    fake = keyring_enabled
    save_credentials("old_user", "old_pass")
    assert fake.get_password("revenant", "old_user") == "old_pass"

    # Save with a different username
    save_credentials("new_user", "new_pass")

    # Old entry should be cleaned up
    assert fake.get_password("revenant", "old_user") is None
    # New entry should exist
    assert fake.get_password("revenant", "new_user") == "new_pass"

    config = load_config()
    assert config.get("username") == "new_user"


# ── logout ──────────────────────────────────────────────────────────


def test_logout_clears_credentials_and_signer(config_dir):
    """reset_all() should clear both credentials and signer identity."""
    save_credentials("myuser", "mypass")
    save_signer_info("Alice", email="alice@test.com", organization="Acme", dn="CN=Alice")

    reset_all()

    user, pwd = get_credentials()
    assert user is None
    assert pwd is None

    info = get_signer_info()
    assert info["name"] is None
    assert info["email"] is None
    assert info["organization"] is None
    assert info["dn"] is None


def test_logout_clears_server_config(config_dir):
    """reset_all() should clear everything including server config."""
    save_config(
        {
            "profile": "ekeng",
            "url": "https://example.com/DSS.asmx",
            "timeout": 90,
            "username": "myuser",
            "password": "mypass",
            "name": "Alice",
            "email": "alice@test.com",
        }
    )

    reset_all()

    raw = load_raw_config()
    assert raw == {}


def test_reset_all_when_empty(config_dir):
    """reset_all() on empty config should not error."""
    reset_all()
    assert load_config() == {}


# ── Session credentials ──────────────────────────────────────────


def test_set_and_clear_session_credentials(config_dir):
    """set_session_credentials caches in memory; clear removes it."""
    from revenant.config.credentials import (
        clear_session_credentials,
        set_session_credentials,
    )

    set_session_credentials("sess_user", "sess_pass")
    # Session creds should be resolved (env empty, no saved)
    with patch.dict("os.environ", {"REVENANT_USER": "", "REVENANT_PASS": ""}, clear=False):
        user, pwd = resolve_credentials()
        assert user == "sess_user"
        assert pwd == "sess_pass"

    clear_session_credentials()
    with patch.dict("os.environ", {"REVENANT_USER": "", "REVENANT_PASS": ""}, clear=False):
        user, pwd = resolve_credentials()
        assert user == ""
        assert pwd == ""


def test_resolve_session_partial_with_env(config_dir):
    """Session password fills in when env provides only user."""
    from revenant.config.credentials import (
        clear_session_credentials,
        set_session_credentials,
    )

    set_session_credentials("sess_user", "sess_pass")
    with patch.dict("os.environ", {"REVENANT_USER": "env_user", "REVENANT_PASS": ""}, clear=False):
        user, pwd = resolve_credentials()
        assert user == "env_user"
        assert pwd == "sess_pass"
    clear_session_credentials()


# ── _keyring_delete edge cases ───────────────────────────────────


def test_keyring_delete_empty_username(keyring_enabled):
    """_keyring_delete with empty username should be a no-op."""
    from revenant.config.credentials import _keyring_delete

    fake = keyring_enabled
    fake.set_password("revenant", "", "should_survive")
    _keyring_delete("")
    # Empty username short-circuits — entry is untouched
    assert fake.get_password("revenant", "") == "should_survive"


def test_keyring_delete_keyring_error(keyring_enabled):
    """_keyring_delete should swallow KeyringError silently."""
    from revenant.config.credentials import _keyring_delete

    class FailingDeleteKeyring(FakeKeyring):
        def delete_password(self, service: str, username: str) -> None:
            raise FakeKeyringError("no such entry")

    with patch("revenant.config.credentials._keyring_mod", FailingDeleteKeyring()):
        _keyring_delete("nonexistent")  # should not raise


def test_keyring_delete_os_error(keyring_enabled):
    """_keyring_delete should swallow OSError silently."""
    from revenant.config.credentials import _keyring_delete

    class OSErrorKeyring(FakeKeyring):
        def delete_password(self, service: str, username: str) -> None:
            raise OSError("disk error")

    with patch("revenant.config.credentials._keyring_mod", OSErrorKeyring()):
        _keyring_delete("some_user")  # should not raise


# ── get_credential_storage_info ──────────────────────────────────


def test_storage_info_plaintext_fallback(config_dir):
    """Without keyring, storage info should mention config file when credentials exist."""
    from revenant.config.credentials import get_credential_storage_info

    save_config({"username": "alice", "password": "secret"})
    info = get_credential_storage_info()
    assert "plaintext" in info


def test_storage_info_no_credentials(config_dir):
    """Without saved credentials, storage info should show storage backend."""
    from revenant.config.credentials import get_credential_storage_info

    info = get_credential_storage_info()
    # Without keyring, falls back to config file path
    assert "config.json" in info or "Keychain" in info or "Credential Manager" in info


@pytest.mark.parametrize(
    ("module_name", "expected_label"),
    [
        ("keyring.backends.macOS", "macOS Keychain"),
        ("keyring.backends.Windows.WinVaultKeyring", "Windows Credential Manager"),
        ("keyring.backends.SecretService", "Linux Secret Service"),
        ("keyring.backends.kwallet.KWallet", "KDE Wallet"),
        ("keyring.backends.chainer", "FakeBackend"),
    ],
    ids=["macos", "windows", "secret_service", "kwallet", "generic"],
)
def test_storage_info_platforms(keyring_enabled, module_name, expected_label):
    """get_credential_storage_info should detect platform from backend module."""
    from revenant.config.credentials import get_credential_storage_info

    class FakeBackend:
        __module__ = module_name

    fake = keyring_enabled
    fake.get_keyring = lambda: FakeBackend()

    # Credentials must exist for backend name to be shown
    save_config({"username": "alice"})
    fake.set_password("revenant", "alice", "secret")

    info = get_credential_storage_info()
    assert expected_label in info


# ── get_credentials edge cases ───────────────────────────────────


def test_get_credentials_non_string_username(config_dir):
    """Non-string username in config should return (None, None)."""
    save_config({"username": 12345, "password": "some_pass"})
    user, pwd = get_credentials()
    assert user is None
    assert pwd is None


def test_migrate_plaintext_password(keyring_enabled):
    """migrate_plaintext_password() removes config password when keyring has it."""
    from revenant.config.credentials import migrate_plaintext_password

    fake = keyring_enabled
    # Simulate legacy state: password in both keyring and config
    fake.set_password("revenant", "migrated_user", "keyring_pass")
    save_config({"username": "migrated_user", "password": "legacy_plain_pass"})

    migrate_plaintext_password()

    # Legacy password should have been removed from config
    config = load_config()
    assert "password" not in config

    # Credentials should still be retrievable via keyring
    user, pwd = get_credentials()
    assert user == "migrated_user"
    assert pwd == "keyring_pass"


def test_get_credentials_keyring_error_then_config(keyring_enabled, config_dir):
    """KeyringError on read should fall back to config password."""

    class KeyringErrorOnRead(FakeKeyring):
        def get_password(self, service: str, username: str) -> str | None:
            raise FakeKeyringError("access denied")

    save_config({"username": "fallback_user", "password": "config_pass"})
    with patch("revenant.config.credentials._keyring_mod", KeyringErrorOnRead()):
        user, pwd = get_credentials()

    assert user == "fallback_user"
    assert pwd == "config_pass"


# ── is_keyring_available ─────────────────────────────────────────


def test_is_keyring_available_false(config_dir):
    """is_keyring_available returns False when keyring is disabled."""
    from revenant.config.credentials import is_keyring_available

    assert is_keyring_available() is False


def test_is_keyring_available_true(keyring_enabled):
    """is_keyring_available returns True when keyring is enabled."""
    from revenant.config.credentials import is_keyring_available

    assert is_keyring_available() is True


# ── get_server_config ──────────────────────────────────────────


def test_get_server_config_empty(config_dir):
    """No config and no env vars returns (None, None, None)."""
    url, timeout, profile = get_server_config()
    assert url is None
    assert timeout is None
    assert profile is None


def test_get_server_config_from_profile(config_dir):
    """Built-in profile provides URL and timeout."""
    save_config({"profile": "ekeng"})
    url, timeout, profile = get_server_config()
    assert url == "https://ca.gov.am:8080/SAPIWS/DSS.asmx"
    assert timeout == 120
    assert profile == "ekeng"


def test_get_server_config_custom_url(config_dir):
    """Custom URL in config takes priority over profile URL."""
    save_config({"profile": "ekeng", "url": "https://custom.example.com/DSS.asmx"})
    url, timeout, _ = get_server_config()
    assert url == "https://custom.example.com/DSS.asmx"
    assert timeout == 120  # still from profile


def test_get_server_config_custom_timeout(config_dir):
    """Config timeout overrides profile timeout."""
    save_config({"profile": "ekeng", "timeout": 60})
    url, timeout, _ = get_server_config()
    assert url == "https://ca.gov.am:8080/SAPIWS/DSS.asmx"
    assert timeout == 60


def test_get_server_config_env_url(config_dir):
    """REVENANT_URL env var takes top priority."""
    save_config({"profile": "ekeng"})
    with patch.dict("os.environ", {"REVENANT_URL": "https://env.example.com/DSS.asmx"}):
        url, _timeout, _ = get_server_config()
    assert url == "https://env.example.com/DSS.asmx"


def test_get_server_config_env_timeout(config_dir):
    """REVENANT_TIMEOUT env var takes top priority."""
    save_config({"profile": "ekeng"})
    with patch.dict("os.environ", {"REVENANT_TIMEOUT": "30"}):
        _url, timeout, _ = get_server_config()
    assert timeout == 30


def test_get_server_config_env_timeout_invalid(config_dir):
    """Invalid REVENANT_TIMEOUT falls back to default."""
    save_config({"url": "https://example.com"})
    with patch.dict("os.environ", {"REVENANT_TIMEOUT": "not-a-number"}):
        _, timeout, _ = get_server_config()
    assert timeout == 120  # DEFAULT_TIMEOUT_SOAP


def test_get_server_config_env_timeout_out_of_range(config_dir):
    """Out-of-range REVENANT_TIMEOUT falls back to default."""
    save_config({"url": "https://example.com"})
    with patch.dict("os.environ", {"REVENANT_TIMEOUT": "99999"}):
        _, timeout, _ = get_server_config()
    assert timeout == 120  # DEFAULT_TIMEOUT_SOAP


def test_get_server_config_url_only(config_dir):
    """URL without profile uses default timeout."""
    save_config({"url": "https://standalone.example.com"})
    url, timeout, profile = get_server_config()
    assert url == "https://standalone.example.com"
    assert timeout == 120  # DEFAULT_TIMEOUT_SOAP
    assert profile is None


def test_get_server_config_unknown_profile(config_dir):
    """Unknown profile name does not provide URL."""
    save_config({"profile": "nonexistent"})
    url, _timeout, _profile = get_server_config()
    assert url is None


# ── get_active_profile ──────────────────────────────────────────


def test_get_active_profile_none(config_dir):
    """No config returns None."""
    assert get_active_profile() is None


def test_get_active_profile_builtin(config_dir):
    """Returns built-in profile when configured."""
    save_config({"profile": "ekeng"})
    profile = get_active_profile()
    assert profile is not None
    assert profile.name == "ekeng"
    assert profile.legacy_tls is True


def test_get_active_profile_custom_url(config_dir):
    """Returns custom profile when only URL is configured."""
    save_config({"url": "https://custom.example.com/DSS.asmx", "timeout": 60})
    profile = get_active_profile()
    assert profile is not None
    assert profile.name == "custom"
    assert profile.url == "https://custom.example.com/DSS.asmx"
    assert profile.timeout == 60


def test_get_active_profile_builtin_over_custom(config_dir):
    """Built-in profile takes priority over custom URL."""
    save_config({"profile": "ekeng", "url": "https://ignored.com"})
    profile = get_active_profile()
    assert profile is not None
    assert profile.name == "ekeng"


# ── save_server_config ────────────────────────────────────────


def test_save_server_config(config_dir):
    """save_server_config persists profile, url, and timeout."""
    profile = ServerProfile(
        name="test", display_name="Test", url="https://test.example.com", timeout=90
    )
    save_server_config(profile)
    raw = load_raw_config()
    assert raw["profile"] == "test"
    assert raw["url"] == "https://test.example.com"
    assert raw["timeout"] == 90


def test_save_server_config_preserves_signer(config_dir):
    """Saving server config should not overwrite signer info."""
    save_signer_info("Alice", email="alice@test.com")
    profile = ServerProfile(name="test", display_name="Test", url="https://test.com")
    save_server_config(profile)
    assert get_signer_name() == "Alice"


# ── get_profile ──────────────────────────────────────────────


def test_get_profile_ekeng():
    """get_profile returns the ekeng built-in profile."""
    profile = get_profile("ekeng")
    assert profile.name == "ekeng"
    assert profile.legacy_tls is True


def test_get_profile_case_insensitive():
    """get_profile is case-insensitive."""
    profile = get_profile("EKENG")
    assert profile.name == "ekeng"


def test_get_profile_unknown():
    """get_profile raises KeyError for unknown profiles."""
    with pytest.raises(KeyError, match="Unknown profile"):
        get_profile("nonexistent")


# ── make_custom_profile ──────────────────────────────────────


def test_make_custom_profile_https():
    """make_custom_profile creates a valid profile for HTTPS URL."""
    profile = make_custom_profile("https://example.com/DSS.asmx", timeout=60)
    assert profile.name == "custom"
    assert profile.url == "https://example.com/DSS.asmx"
    assert profile.timeout == 60
    assert profile.legacy_tls is False


def test_make_custom_profile_http_rejected():
    """make_custom_profile rejects HTTP URLs to prevent plaintext credentials."""
    with pytest.raises(ValueError, match="HTTP URLs are not supported"):
        make_custom_profile("http://example.com/DSS.asmx")


def test_make_custom_profile_invalid_scheme():
    """make_custom_profile rejects invalid URL schemes."""
    with pytest.raises(ValueError, match="Invalid URL scheme"):
        make_custom_profile("ftp://example.com/DSS.asmx")


def test_make_custom_profile_no_hostname():
    """make_custom_profile rejects URLs without hostname."""
    with pytest.raises(ValueError, match="no hostname"):
        make_custom_profile("https://")


# ── ServerProfile.has_identity_method ────────────────────────


def test_server_profile_has_identity_method():
    """has_identity_method checks identity_methods tuple."""
    profile = ServerProfile(
        name="test",
        display_name="Test",
        url="https://test.com",
        identity_methods=("server", "manual"),
    )
    assert profile.has_identity_method("server") is True
    assert profile.has_identity_method("manual") is True
    assert profile.has_identity_method("ldap") is False


# ── register_profile_tls_mode / register_active_profile_tls ──


def test_register_profile_tls_mode(config_dir):
    """register_profile_tls_mode calls register_host_tls with correct args."""
    from revenant.config import register_profile_tls_mode

    profile = ServerProfile(
        name="test",
        display_name="Test",
        url="https://test.example.com:8080/DSS.asmx",
        legacy_tls=True,
    )
    with patch("revenant.network.transport.register_host_tls") as mock_reg:
        register_profile_tls_mode(profile)
    mock_reg.assert_called_once_with("test.example.com", True)


def test_register_profile_tls_mode_standard(config_dir):
    """register_profile_tls_mode passes legacy=False for standard TLS."""
    from revenant.config import register_profile_tls_mode

    profile = ServerProfile(name="test", display_name="Test", url="https://standard.com/api")
    with patch("revenant.network.transport.register_host_tls") as mock_reg:
        register_profile_tls_mode(profile)
    mock_reg.assert_called_once_with("standard.com", False)


def test_register_active_profile_tls(config_dir):
    """register_active_profile_tls registers the active profile's TLS mode."""
    from revenant.config import register_active_profile_tls

    save_config({"profile": "ekeng"})
    with patch("revenant.network.transport.register_host_tls") as mock_reg:
        register_active_profile_tls()
    mock_reg.assert_called_once_with("ca.gov.am", True)


def test_register_active_profile_tls_no_profile(config_dir):
    """register_active_profile_tls is a no-op when no profile is configured."""
    from revenant.config import register_active_profile_tls

    with patch("revenant.network.transport.register_host_tls") as mock_reg:
        register_active_profile_tls()
    mock_reg.assert_not_called()


# ── logout (credentials + identity, preserve server) ──────────────


def test_logout_preserves_server_config(config_dir):
    """logout() should clear credentials and identity but keep server config."""
    save_config(
        {
            "profile": "ekeng",
            "url": "https://ca.gov.am:8080/SAPIWS/DSS.asmx",
            "timeout": 120,
            "username": "myuser",
            "password": "mypass",
            "name": "Alice",
            "email": "alice@test.com",
            "organization": "Acme",
            "dn": "CN=Alice, O=Acme",
        }
    )

    logout()

    raw = load_raw_config()
    # Server config preserved
    assert raw["profile"] == "ekeng"
    assert raw["url"] == "https://ca.gov.am:8080/SAPIWS/DSS.asmx"
    assert raw["timeout"] == 120
    # Credentials cleared
    assert "username" not in raw
    assert "password" not in raw
    # Identity cleared
    assert "name" not in raw
    assert "email" not in raw
    assert "organization" not in raw
    assert "dn" not in raw


def test_logout_clears_session_credentials(config_dir):
    """logout() should clear in-memory session credential cache."""
    from revenant.config.credentials import set_session_credentials

    set_session_credentials("sess_user", "sess_pass")
    save_config({"profile": "ekeng", "name": "Alice"})

    logout()

    with patch.dict("os.environ", {"REVENANT_USER": "", "REVENANT_PASS": ""}, clear=False):
        user, pwd = resolve_credentials()
        assert user == ""
        assert pwd == ""


def test_logout_with_keyring(keyring_enabled):
    """logout() should clear keyring credentials and identity, keep server."""
    fake = keyring_enabled
    save_credentials("alice", "secret")
    save_signer_info("Alice", email="alice@test.com")
    save_server_config(
        ServerProfile(name="test", display_name="Test", url="https://test.com", timeout=60)
    )

    logout()

    # Keyring cleared
    assert fake.get_password("revenant", "alice") is None
    # Config has server but not credentials/identity
    raw = load_raw_config()
    assert raw["profile"] == "test"
    assert raw["url"] == "https://test.com"
    assert "username" not in raw
    assert "name" not in raw


def test_logout_when_only_server_configured(config_dir):
    """logout() on Layer 1 state (server only) should not error."""
    save_config({"profile": "ekeng", "url": "https://ca.gov.am:8080/SAPIWS/DSS.asmx"})
    logout()
    raw = load_raw_config()
    assert raw["profile"] == "ekeng"


def test_logout_when_empty(config_dir):
    """logout() on empty config (Layer 0) should not error."""
    logout()
    assert load_config() == {}


# ── get_config_layer ──────────────────────────────────────────────


def test_config_layer_0_empty(config_dir):
    """Empty config should be Layer 0."""
    assert get_config_layer() == 0


def test_config_layer_0_unknown_profile(config_dir):
    """Unknown profile name (no URL resolved) should be Layer 0."""
    save_config({"profile": "nonexistent"})
    assert get_config_layer() == 0


def test_config_layer_1_server_only(config_dir):
    """Server configured without identity should be Layer 1."""
    save_config({"profile": "ekeng", "url": "https://ca.gov.am:8080/SAPIWS/DSS.asmx"})
    assert get_config_layer() == 1


def test_config_layer_1_server_with_credentials_no_identity(config_dir):
    """Server + credentials but no identity should be Layer 1."""
    save_config(
        {
            "profile": "ekeng",
            "url": "https://ca.gov.am:8080/SAPIWS/DSS.asmx",
            "username": "myuser",
            "password": "mypass",
        }
    )
    assert get_config_layer() == 1


def test_config_layer_2_full(config_dir):
    """Server + identity should be Layer 2."""
    save_config(
        {
            "profile": "ekeng",
            "url": "https://ca.gov.am:8080/SAPIWS/DSS.asmx",
            "name": "Alice",
        }
    )
    assert get_config_layer() == 2


def test_config_layer_after_logout(config_dir):
    """After logout(), layer should drop from 2 to 1."""
    save_config(
        {
            "profile": "ekeng",
            "url": "https://ca.gov.am:8080/SAPIWS/DSS.asmx",
            "username": "myuser",
            "password": "mypass",
            "name": "Alice",
        }
    )
    assert get_config_layer() == 2
    logout()
    assert get_config_layer() == 1


def test_config_layer_after_reset(config_dir):
    """After reset_all(), layer should drop to 0."""
    save_config(
        {
            "profile": "ekeng",
            "url": "https://ca.gov.am:8080/SAPIWS/DSS.asmx",
            "name": "Alice",
        }
    )
    assert get_config_layer() == 2
    reset_all()
    assert get_config_layer() == 0


# ── constants version fallback ────────────────────────────────────


def test_version_fallback_on_missing_package():
    """__version__ falls back to hardcoded version when package metadata is unavailable."""
    import importlib
    import importlib.metadata

    with patch.object(
        importlib.metadata,
        "version",
        side_effect=importlib.metadata.PackageNotFoundError("revenant"),
    ):
        # importlib.reload re-executes module-level code
        import revenant.constants

        importlib.reload(revenant.constants)
        assert revenant.constants.__version__ == "0.2.2"

    # Reload again to restore real version
    importlib.reload(revenant.constants)
