//! Credential management: the secret backend, session cache, and resolution.
//!
//! Passwords are stored in the OS keychain via a [`SecretStore`]; the username
//! lives in the config file so it can be shown without unlocking the keychain.
//! When the keychain is unusable (e.g. a headless box with no Secret Service),
//! storage falls back to a plaintext password in the config file, and a one-time
//! migration removes the plaintext once the keychain holds it.

use std::error::Error;
use std::fmt;

use serde_json::Value;

use crate::constants::{ENV_PASS, ENV_USER};
use crate::error::RevenantError;

use super::secret::Secret;
use super::storage::{KEY_PASSWORD, KEY_USERNAME};
use super::{ConfigStore, SessionCredentials};

/// Keyring service name under which every credential is stored, keyed by
/// username. Matches the Python client and the TS port so an entry saved by any
/// of them is found by the others.
pub(super) const KEYRING_SERVICE: &str = "revenant";

/// A failure from the secret backend (keychain locked, access denied, no
/// backend running, etc.). Distinct from [`RevenantError`]: credential code
/// treats these as recoverable and degrades to the plaintext fallback.
#[derive(Debug)]
pub(super) struct SecretStoreError {
    message: String,
}

impl SecretStoreError {
    fn new(message: impl Into<String>) -> Self {
        SecretStoreError {
            message: message.into(),
        }
    }
}

impl fmt::Display for SecretStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl Error for SecretStoreError {}

/// A backend for storing and retrieving a single secret per account.
///
/// The abstraction is the seam that keeps credential logic testable: production
/// uses [`KeyringStore`]; tests inject an in-memory store so the OS keychain is
/// never touched (no interactive unlock prompts, no pollution of the real
/// keychain). The service name is fixed at construction, so methods take only
/// the account (username).
///
/// Kept crate-internal for now: there is no public constructor that injects a
/// custom backend, so exposing the trait would be a speculative API. Widening
/// visibility later is non-breaking.
pub(super) trait SecretStore: fmt::Debug + Send + Sync {
    /// Retrieve the secret for `account`. `Ok(None)` means "no such entry";
    /// `Err` means the backend itself failed.
    fn get(&self, account: &str) -> Result<Option<String>, SecretStoreError>;

    /// Store (or replace) the secret for `account`.
    fn set(&self, account: &str, secret: &str) -> Result<(), SecretStoreError>;

    /// Remove the entry for `account`. Removing a non-existent entry succeeds.
    fn delete(&self, account: &str) -> Result<(), SecretStoreError>;

    /// Human-readable backend name for display (e.g. "macOS Keychain").
    fn backend_name(&self) -> String;

    /// Whether this backend is real secure storage (vs. a fallback).
    fn is_secure(&self) -> bool;
}

/// The OS keychain backend, via the `keyring` crate.
#[derive(Debug)]
pub(super) struct KeyringStore {
    service: String,
}

impl KeyringStore {
    pub(super) fn new(service: impl Into<String>) -> Self {
        KeyringStore {
            service: service.into(),
        }
    }

    fn entry(&self, account: &str) -> Result<keyring::Entry, SecretStoreError> {
        keyring::Entry::new(&self.service, account)
            .map_err(|e| SecretStoreError::new(e.to_string()))
    }
}

impl SecretStore for KeyringStore {
    fn get(&self, account: &str) -> Result<Option<String>, SecretStoreError> {
        match self.entry(account)?.get_password() {
            Ok(password) => Ok(Some(password)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(SecretStoreError::new(e.to_string())),
        }
    }

    fn set(&self, account: &str, secret: &str) -> Result<(), SecretStoreError> {
        self.entry(account)?
            .set_password(secret)
            .map_err(|e| SecretStoreError::new(e.to_string()))
    }

    fn delete(&self, account: &str) -> Result<(), SecretStoreError> {
        match self.entry(account)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(SecretStoreError::new(e.to_string())),
        }
    }

    fn backend_name(&self) -> String {
        if cfg!(target_os = "macos") {
            "macOS Keychain".to_owned()
        } else if cfg!(target_os = "windows") {
            "Windows Credential Manager".to_owned()
        } else if cfg!(target_os = "linux") {
            "Linux Secret Service".to_owned()
        } else {
            "system keychain".to_owned()
        }
    }

    fn is_secure(&self) -> bool {
        true
    }
}

/// Credentials resolved from all sources, with precedence already applied.
///
/// Either field may be absent: a username can be known while its password is
/// inaccessible (keychain locked). `password` is a [`Secret`], so `Debug` stays
/// redacted.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResolvedCredentials {
    pub username: Option<String>,
    pub password: Option<Secret>,
}

impl ResolvedCredentials {
    /// Whether both a non-empty username and password are present.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        let has_user = self.username.as_deref().is_some_and(|u| !u.is_empty());
        let has_pass = self.password.as_ref().is_some_and(|p| !p.is_empty());
        has_user && has_pass
    }
}

/// Read a non-empty string value for `key` from a raw config object.
fn raw_nonempty(map: &serde_json::Map<String, Value>, key: &str) -> Option<String> {
    map.get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

impl ConfigStore {
    /// Whether secure keychain storage is available.
    #[must_use]
    pub fn is_keyring_available(&self) -> bool {
        self.secrets.is_secure()
    }

    /// Human-readable description of where credentials are stored.
    #[must_use]
    pub fn credential_storage_info(&self) -> String {
        if self.secrets.is_secure() {
            self.secrets.backend_name()
        } else {
            format!("{} (plaintext)", self.storage.file().display())
        }
    }

    /// The saved username, without touching any secret. Safe for display.
    #[must_use]
    pub fn saved_username(&self) -> Option<String> {
        self.storage.load_typed().username.filter(|u| !u.is_empty())
    }

    /// Cache credentials in memory for the current process (not persisted).
    pub fn set_session_credentials(
        &self,
        username: impl Into<String>,
        password: impl Into<Secret>,
    ) {
        let mut guard = self
            .session
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *guard = Some(SessionCredentials {
            username: username.into(),
            password: password.into(),
        });
    }

    /// Clear the in-memory session credential cache.
    pub fn clear_session_credentials(&self) {
        let mut guard = self
            .session
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *guard = None;
    }

    /// Remove the plaintext password from the config file once the keychain
    /// holds it. Idempotent; a no-op unless the keychain is secure, a username
    /// and plaintext password are present, and the keychain confirms it stores a
    /// password for that user. Called lazily so any keychain unlock prompt
    /// appears in context rather than at startup.
    fn migrate_plaintext_password(&self) {
        if !self.secrets.is_secure() {
            return;
        }
        let raw = self.storage.load_raw();
        let Some(username) = raw_nonempty(&raw, KEY_USERNAME) else {
            return;
        };
        if raw_nonempty(&raw, KEY_PASSWORD).is_none() {
            return; // no plaintext password to migrate
        }
        match self.secrets.get(&username) {
            Ok(Some(keychain_password)) if !keychain_password.is_empty() => {
                let mut raw = self.storage.load_raw();
                if raw.remove(KEY_PASSWORD).is_some() {
                    match self.storage.save(&raw) {
                        Ok(()) => {
                            log::info!("Migrated: removed plaintext password from config file");
                        }
                        Err(e) => log::warn!("Failed to remove plaintext password: {e}"),
                    }
                }
            }
            // Keychain lacks it or the read failed: keep the plaintext copy.
            _ => {}
        }
    }

    /// Get saved credentials, preferring the keychain over the config file.
    ///
    /// The username is absent when none is saved; the password is absent when the
    /// username exists but no password is reachable. Both non-empty fields are
    /// present when credentials are fully available. Runs the one-time plaintext
    /// migration on first call.
    #[must_use]
    pub fn get_credentials(&self) -> ResolvedCredentials {
        self.migrate_plaintext_password();
        let config = self.storage.load_typed();
        let Some(username) = config.username.filter(|u| !u.is_empty()) else {
            return ResolvedCredentials::default();
        };

        if self.secrets.is_secure() {
            match self.secrets.get(&username) {
                Ok(Some(password)) if !password.is_empty() => {
                    return ResolvedCredentials {
                        username: Some(username),
                        password: Some(Secret::new(password)),
                    };
                }
                Ok(_) => {} // no keychain password -> try config file
                Err(e) => log::debug!("Keyring read failed, trying config file: {e}"),
            }
        }

        let password = config.password.filter(|p| !p.is_empty());
        ResolvedCredentials {
            username: Some(username),
            password,
        }
    }

    /// Save credentials, preferring the keychain.
    ///
    /// Returns `Ok(true)` if the password went to the keychain (secure), or
    /// `Ok(false)` if it fell back to the config file (plaintext). If the
    /// username changed, the stale keychain entry is removed.
    ///
    /// # Errors
    /// [`RevenantError::Config`] if the config file cannot be written.
    pub fn save_credentials(&self, username: &str, password: &str) -> Result<bool, RevenantError> {
        let mut raw = self.storage.load_raw();
        let old_username = raw
            .get(KEY_USERNAME)
            .and_then(Value::as_str)
            .map(str::to_owned);
        if let Some(old) = &old_username {
            if old != username {
                if let Err(e) = self.secrets.delete(old) {
                    log::debug!("Keyring delete of old entry failed: {e}");
                }
            }
        }
        raw.insert(KEY_USERNAME.to_owned(), Value::String(username.to_owned()));

        if self.secrets.is_secure() {
            match self.secrets.set(username, password) {
                Ok(()) => {
                    raw.remove(KEY_PASSWORD);
                    self.storage.save(&raw)?;
                    return Ok(true);
                }
                Err(e) => log::warn!("Keyring save failed, using config file: {e}"),
            }
        } else {
            log::warn!(
                "Keyring unavailable. Password will be saved in plaintext ({}).",
                self.storage.file().display()
            );
        }

        raw.insert(KEY_PASSWORD.to_owned(), Value::String(password.to_owned()));
        self.storage.save(&raw)?;
        Ok(false)
    }

    /// Remove saved credentials from every backend.
    ///
    /// # Errors
    /// [`RevenantError::Config`] if the config file cannot be written.
    pub fn clear_credentials(&self) -> Result<(), RevenantError> {
        let mut raw = self.storage.load_raw();
        let username = raw
            .get(KEY_USERNAME)
            .and_then(Value::as_str)
            .map(str::to_owned);
        log::info!(
            "Clearing credentials: has_username={}, password_in_config={}, secure={}",
            username.is_some(),
            raw.contains_key(KEY_PASSWORD),
            self.secrets.is_secure()
        );
        if let Some(username) = &username {
            if let Err(e) = self.secrets.delete(username) {
                log::debug!("Keyring delete failed: {e}");
            }
        }
        raw.remove(KEY_USERNAME);
        raw.remove(KEY_PASSWORD);
        self.storage.save(&raw)
    }

    /// Resolve credentials from all sources with precedence
    /// env > session > saved, merging partial results (e.g. username from env,
    /// password from the keychain).
    #[must_use]
    pub fn resolve_credentials(&self) -> ResolvedCredentials {
        let session = self.session_snapshot();
        let mut username = self.env_nonempty(ENV_USER).or_else(|| {
            session
                .as_ref()
                .map(|s| s.username.clone())
                .filter(|u| !u.is_empty())
        });
        let mut password = self.env_nonempty(ENV_PASS).map(Secret::new).or_else(|| {
            session
                .as_ref()
                .map(|s| s.password.clone())
                .filter(|p| !p.is_empty())
        });

        // Fall back to saved credentials only when something is still missing, so
        // the keychain is left untouched if env or session already answered.
        if username.is_none() || password.is_none() {
            let saved = self.get_credentials();
            username = username.or(saved.username);
            password = password.or(saved.password);
        }

        ResolvedCredentials { username, password }
    }
}

#[cfg(test)]
pub(super) use mock::MockSecretStore;

#[cfg(test)]
mod mock {
    use super::{SecretStore, SecretStoreError};
    use std::collections::HashMap;
    use std::fmt;
    use std::sync::Mutex;

    /// In-memory secret backend for tests. Never touches the OS keychain.
    pub(in crate::config) struct MockSecretStore {
        entries: Mutex<HashMap<String, String>>,
        secure: bool,
        fail_ops: bool,
    }

    impl MockSecretStore {
        /// A working secure store.
        pub(in crate::config) fn working() -> Self {
            MockSecretStore {
                entries: Mutex::new(HashMap::new()),
                secure: true,
                fail_ops: false,
            }
        }

        /// A secure store whose every operation fails (keychain unreachable),
        /// exercising the plaintext fallback path.
        pub(in crate::config) fn failing() -> Self {
            MockSecretStore {
                entries: Mutex::new(HashMap::new()),
                secure: true,
                fail_ops: true,
            }
        }

        fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, String>> {
            self.entries
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
        }
    }

    impl fmt::Debug for MockSecretStore {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            // Never render stored secrets.
            f.debug_struct("MockSecretStore")
                .field("secure", &self.secure)
                .field("fail_ops", &self.fail_ops)
                .field("entries", &self.lock().len())
                .finish()
        }
    }

    impl SecretStore for MockSecretStore {
        fn get(&self, account: &str) -> Result<Option<String>, SecretStoreError> {
            if self.fail_ops {
                return Err(SecretStoreError::new("mock get failure"));
            }
            Ok(self.lock().get(account).cloned())
        }

        fn set(&self, account: &str, secret: &str) -> Result<(), SecretStoreError> {
            if self.fail_ops {
                return Err(SecretStoreError::new("mock set failure"));
            }
            self.lock().insert(account.to_owned(), secret.to_owned());
            Ok(())
        }

        fn delete(&self, account: &str) -> Result<(), SecretStoreError> {
            if self.fail_ops {
                return Err(SecretStoreError::new("mock delete failure"));
            }
            self.lock().remove(account);
            Ok(())
        }

        fn backend_name(&self) -> String {
            "Mock Keychain".to_owned()
        }

        fn is_secure(&self) -> bool {
            self.secure
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{test_store, test_store_with_env};
    use std::collections::HashMap;
    use std::path::PathBuf;

    #[test]
    fn save_uses_keychain_and_hides_password_from_file() {
        let (dir, store) = test_store();
        let secure = store.save_credentials("alice", "pw-123").expect("save");
        assert!(secure, "working keychain should store securely");

        // Password must NOT be in the config file.
        let text = std::fs::read_to_string(dir.path().join("config.json")).unwrap();
        assert!(text.contains("alice"));
        assert!(!text.contains("pw-123"), "plaintext leaked: {text}");

        let ResolvedCredentials {
            username: user,
            password: pass,
        } = store.get_credentials();
        assert_eq!(user.as_deref(), Some("alice"));
        assert_eq!(
            pass.map(|p| p.expose().to_owned()),
            Some("pw-123".to_owned())
        );
    }

    #[test]
    fn save_falls_back_to_plaintext_when_keychain_fails() {
        let dir = tempfile::tempdir().unwrap();
        let store = ConfigStore::with_parts(
            dir.path().to_path_buf(),
            Box::new(super::mock::MockSecretStore::failing()),
            HashMap::new(),
        );
        let secure = store.save_credentials("bob", "pw-xyz").expect("save");
        assert!(!secure, "failing keychain must fall back to plaintext");
        let text = std::fs::read_to_string(dir.path().join("config.json")).unwrap();
        assert!(
            text.contains("pw-xyz"),
            "plaintext password expected in file"
        );

        // Reading back still works via the config-file fallback.
        let ResolvedCredentials {
            username: user,
            password: pass,
        } = store.get_credentials();
        assert_eq!(user.as_deref(), Some("bob"));
        assert_eq!(
            pass.map(|p| p.expose().to_owned()),
            Some("pw-xyz".to_owned())
        );
    }

    #[test]
    fn changing_username_removes_old_keychain_entry() {
        let (_dir, store) = test_store();
        store.save_credentials("old", "pw1").unwrap();
        store.save_credentials("new", "pw2").unwrap();
        // Old entry is gone; only the new one resolves.
        let ResolvedCredentials {
            username: user,
            password: pass,
        } = store.get_credentials();
        assert_eq!(user.as_deref(), Some("new"));
        assert_eq!(pass.map(|p| p.expose().to_owned()), Some("pw2".to_owned()));
    }

    #[test]
    fn clear_removes_username_and_password() {
        let (_dir, store) = test_store();
        store.save_credentials("alice", "pw").unwrap();
        store.clear_credentials().unwrap();
        assert_eq!(store.get_credentials(), ResolvedCredentials::default());
        assert_eq!(store.saved_username(), None);
    }

    #[test]
    fn migrate_removes_plaintext_once_keychain_has_it() {
        let (dir, store) = test_store();
        // Simulate a legacy config: username + plaintext password on disk, and
        // the same password already present in the keychain.
        let path = dir.path().join("config.json");
        std::fs::create_dir_all(dir.path()).unwrap();
        std::fs::write(&path, r#"{"username":"alice","password":"legacy-pw"}"#).unwrap();
        store.save_credentials("alice", "legacy-pw").unwrap(); // puts it in keychain, strips plaintext
                                                               // Re-add plaintext to disk to force the migration path on next read.
        let mut raw = store.storage.load_raw();
        raw.insert(
            KEY_PASSWORD.to_owned(),
            Value::String("legacy-pw".to_owned()),
        );
        store.storage.save(&raw).unwrap();

        let _ = store.get_credentials(); // triggers migration
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(
            !text.contains("legacy-pw"),
            "plaintext should be migrated away: {text}"
        );
    }

    #[test]
    fn resolve_precedence_env_over_session_over_saved() {
        let (_dir, store) =
            test_store_with_env(&[("REVENANT_USER", "env-user"), ("REVENANT_PASS", "env-pass")]);
        store.set_session_credentials("session-user", "session-pass");
        store.save_credentials("saved-user", "saved-pass").unwrap();

        let resolved = store.resolve_credentials();
        assert_eq!(resolved.username.as_deref(), Some("env-user"));
        assert_eq!(
            resolved.password.as_ref().map(Secret::expose),
            Some("env-pass")
        );
        assert!(resolved.is_complete());
    }

    #[test]
    fn resolve_merges_partial_sources() {
        // Username from env, password from the saved keychain.
        let (_dir, store) = test_store_with_env(&[("REVENANT_USER", "env-user")]);
        store.save_credentials("saved-user", "saved-pass").unwrap();
        let resolved = store.resolve_credentials();
        assert_eq!(resolved.username.as_deref(), Some("env-user"));
        assert_eq!(
            resolved.password.as_ref().map(Secret::expose),
            Some("saved-pass")
        );
    }

    #[test]
    fn resolve_session_fills_when_no_env() {
        let (_dir, store) = test_store();
        store.set_session_credentials("session-user", "session-pass");
        let resolved = store.resolve_credentials();
        assert_eq!(resolved.username.as_deref(), Some("session-user"));
        assert_eq!(
            resolved.password.as_ref().map(Secret::expose),
            Some("session-pass")
        );
    }

    #[test]
    fn storage_info_reflects_backend() {
        let (_dir, store) = test_store();
        assert_eq!(store.credential_storage_info(), "Mock Keychain");
        assert!(store.is_keyring_available());

        let dir = tempfile::tempdir().unwrap();
        let insecure = ConfigStore::with_parts(
            dir.path().to_path_buf(),
            Box::new(NonSecureStore),
            HashMap::new(),
        );
        assert!(insecure.credential_storage_info().contains("(plaintext)"));
        assert!(!insecure.is_keyring_available());
        let _ = PathBuf::new();
    }

    /// End-to-end proof that the configured keyring feature flags produce a
    /// real, working OS backend (not the no-features in-memory mock). Ignored by
    /// default because it touches the actual OS keychain; run explicitly with:
    ///
    /// ```text
    /// cargo test -p revenant-core --lib keyring_store_roundtrips -- --ignored --exact
    /// ```
    #[test]
    #[ignore = "touches the real OS keychain; run explicitly with --ignored"]
    fn keyring_store_roundtrips_against_real_backend() {
        let store = KeyringStore::new("revenant-test-phase3");
        let account = "phase3-throwaway";
        // Start clean, even if a prior aborted run left an entry.
        let _ = store.delete(account);
        assert_eq!(store.get(account).expect("get"), None);

        store.set(account, "secret-value-123").expect("set");
        assert_eq!(
            store.get(account).expect("get").as_deref(),
            Some("secret-value-123")
        );

        store.delete(account).expect("delete");
        assert_eq!(store.get(account).expect("get"), None);
        assert!(store.is_secure());
    }

    /// A store that reports itself as non-secure (never used for real storage).
    #[derive(Debug)]
    struct NonSecureStore;
    impl SecretStore for NonSecureStore {
        fn get(&self, _account: &str) -> Result<Option<String>, SecretStoreError> {
            Ok(None)
        }
        fn set(&self, _account: &str, _secret: &str) -> Result<(), SecretStoreError> {
            Ok(())
        }
        fn delete(&self, _account: &str) -> Result<(), SecretStoreError> {
            Ok(())
        }
        fn backend_name(&self) -> String {
            "none".to_owned()
        }
        fn is_secure(&self) -> bool {
            false
        }
    }
}
