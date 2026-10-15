//! Configuration, credentials, and server profiles.
//!
//! Signer identity, active server profile, credentials, and preferences
//! persisted under `~/.revenant`. State that would naturally be process-global
//! (the config path, the keyring handle, session variables) is centralized in an
//! injectable [`ConfigStore`], so the whole layer is testable against a temp
//! directory and an in-memory secret backend without touching the real OS
//! keychain.
//!
//! The submodules are private; the public surface is re-exported here.

mod credentials;
mod profiles;
mod secret;
mod settings;
mod storage;

use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;
use std::sync::{Mutex, PoisonError};

use crate::net::Transport;

use credentials::{KeyringStore, MemorySecretStore, SecretStore};
use storage::Storage;

pub use credentials::ResolvedCredentials;
pub use profiles::{
    CertField, CertFieldSource, IdentityMethod, ServerProfile, SigAuto, SigField, SigFieldValue,
    TrustAnchors, BUILTIN_PROFILES, EKENG,
};
pub use secret::Secret;
pub use settings::{ConfigLayer, ResolvedServerConfig, SignerInfo, SYSTEM_LANGUAGE};

/// Directory (under the user's home) holding the config file.
const CONFIG_DIR_NAME: &str = ".revenant";

/// In-memory, non-persisted credentials for the current process.
///
/// Set during interactive setup so an operation can proceed in the same run
/// even when the user declines to save credentials to disk. `password` is a
/// [`Secret`] so it is never printed by `Debug`.
#[derive(Debug, Clone)]
struct SessionCredentials {
    username: String,
    password: Secret,
}

/// Where environment-variable overrides are read from.
///
/// Production reads the real process environment; tests inject a fixed set so
/// env-precedence behavior is exercised deterministically without mutating the
/// shared process environment (which would race across parallel tests), and an
/// isolated store uses an empty set so the caller's environment cannot leak in.
enum EnvSource {
    Process,
    Fixed(HashMap<String, String>),
}

impl EnvSource {
    /// Raw value for `key`, or `None` if unset.
    fn get(&self, key: &str) -> Option<String> {
        match self {
            EnvSource::Process => std::env::var(key).ok(),
            EnvSource::Fixed(vars) => vars.get(key).cloned(),
        }
    }
}

impl fmt::Debug for EnvSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never render values: env may carry REVENANT_PASS.
        match self {
            EnvSource::Process => f.write_str("Process"),
            EnvSource::Fixed(vars) => write!(f, "Fixed({} vars)", vars.len()),
        }
    }
}

/// The configuration subsystem: persisted settings, credentials, and the
/// session credential cache, all rooted at one config directory.
///
/// A single instance is threaded through a run (the CLI builds one and shares
/// it). It is `Send + Sync`, so background work can read config concurrently.
#[derive(Debug)]
pub struct ConfigStore {
    storage: Storage,
    secrets: Box<dyn SecretStore>,
    env: EnvSource,
    session: Mutex<Option<SessionCredentials>>,
}

impl ConfigStore {
    /// Build the production store: `~/.revenant`, the OS keychain, and the real
    /// process environment.
    #[must_use]
    pub fn new() -> Self {
        ConfigStore {
            storage: Storage::new(default_config_dir()),
            secrets: Box::new(KeyringStore::new(credentials::KEYRING_SERVICE)),
            env: EnvSource::Process,
            session: Mutex::new(None),
        }
    }

    /// Build a store detached from the user's machine: the config file lives in
    /// `dir`, secrets are held in process memory, and environment overrides
    /// (`REVENANT_URL`, `REVENANT_USER`, ...) are ignored.
    ///
    /// For anything that must drive the real UI or API without reading or
    /// changing the user's setup -- rendering store screenshots, demos, embedding
    /// tests. `keychain_name` is what [`ConfigStore::credential_storage_info`]
    /// reports, standing in for the OS keychain the memory store replaces.
    #[must_use]
    pub fn isolated(dir: PathBuf, keychain_name: impl Into<String>) -> Self {
        ConfigStore {
            storage: Storage::new(dir),
            secrets: Box::new(MemorySecretStore::new(keychain_name.into())),
            env: EnvSource::Fixed(HashMap::new()),
            session: Mutex::new(None),
        }
    }

    /// The path to the config file (`~/.revenant/config.json`).
    #[must_use]
    pub fn config_file(&self) -> &std::path::Path {
        self.storage.file()
    }

    // -- Shared internals used by the settings and credentials impl blocks --

    /// Trimmed, non-empty value of an environment override, else `None`
    /// (a whitespace-only override is treated as unset).
    fn env_nonempty(&self, key: &str) -> Option<String> {
        self.env
            .get(key)
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
    }

    /// A snapshot of the session credential cache, recovering from a poisoned
    /// lock rather than propagating a panic (the cached credentials remain
    /// valid data even if another thread panicked while holding the lock).
    fn session_snapshot(&self) -> Option<SessionCredentials> {
        self.session
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl Default for ConfigStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Resolve the default config directory (`~/.revenant`).
///
/// If the home directory cannot be determined -- an extraordinary state, since
/// `std::env::home_dir` consults both `HOME`/`USERPROFILE` and the password
/// database -- fall back to a `.revenant` directory in the current working
/// directory and log loudly, rather than panicking the whole tool.
fn default_config_dir() -> PathBuf {
    if let Some(home) = std::env::home_dir() {
        home.join(CONFIG_DIR_NAME)
    } else {
        log::warn!("Could not determine home directory; using ./{CONFIG_DIR_NAME}");
        PathBuf::from(CONFIG_DIR_NAME)
    }
}

/// Register a specific profile's TLS mode with the transport.
///
/// Bridges the config and transport layers: the appliance's cipher requirement
/// (standard HTTPS vs. legacy TLS 1.0 + RC4) is a profile property, and the
/// transport needs it keyed by host before the first request. Use this in setup
/// flows working with a profile that is not yet the saved active one.
pub fn register_profile_tls_mode(transport: &Transport, profile: &ServerProfile) {
    let Ok(parsed) = url::Url::parse(&profile.url) else {
        return;
    };
    if let Some(host) = parsed.host_str() {
        transport.register_host_tls(host, profile.tls_mode.clone());
    }
}

/// Register the active profile's TLS mode with the transport.
///
/// Reads the currently configured profile and applies its TLS requirement.
/// Call before making network requests. A no-op when nothing is configured.
pub fn register_active_profile_tls(transport: &Transport, store: &ConfigStore) {
    if let Some(profile) = store.active_profile() {
        register_profile_tls_mode(transport, &profile);
    }
}

#[cfg(test)]
mod test_support {
    use super::*;
    use credentials::MockSecretStore;
    use std::collections::HashMap;
    use tempfile::TempDir;

    impl ConfigStore {
        /// Build a store over a temp directory with an injected secret backend
        /// and a fixed environment -- the DI seam every config test uses.
        pub(super) fn with_parts(
            dir: PathBuf,
            secrets: Box<dyn SecretStore>,
            env: HashMap<String, String>,
        ) -> Self {
            ConfigStore {
                storage: Storage::new(dir),
                secrets,
                env: EnvSource::Fixed(env),
                session: Mutex::new(None),
            }
        }
    }

    /// A store backed by a working in-memory keychain and empty environment.
    pub(crate) fn test_store() -> (TempDir, ConfigStore) {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = ConfigStore::with_parts(
            dir.path().to_path_buf(),
            Box::new(MockSecretStore::working()),
            HashMap::new(),
        );
        (dir, store)
    }

    /// A store with the given fixed environment overrides.
    pub(crate) fn test_store_with_env(env: &[(&str, &str)]) -> (TempDir, ConfigStore) {
        let dir = tempfile::tempdir().expect("temp dir");
        let vars = env
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        let store = ConfigStore::with_parts(
            dir.path().to_path_buf(),
            Box::new(MockSecretStore::working()),
            vars,
        );
        (dir, store)
    }
}

#[cfg(test)]
pub(crate) use test_support::{test_store, test_store_with_env};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_file_path_is_under_config_dir() {
        let (dir, store) = test_store();
        assert_eq!(store.config_file(), dir.path().join("config.json"));
    }

    #[test]
    fn debug_never_leaks_session_password() {
        let (_dir, store) = test_store();
        store.set_session_credentials("user", "s3cr3t-pw");
        let rendered = format!("{store:?}");
        assert!(!rendered.contains("s3cr3t-pw"), "leaked: {rendered}");
    }

    #[test]
    fn isolated_store_keeps_config_and_secrets_off_the_machine() {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = ConfigStore::isolated(dir.path().to_path_buf(), "Test Keychain");
        assert_eq!(store.config_file(), dir.path().join("config.json"));
        assert_eq!(store.credential_storage_info(), "Test Keychain");

        // Reported as secure, so the password goes to memory, not the file.
        assert!(store.save_credentials("user", "s3cr3t-pw").unwrap());
        let on_disk = std::fs::read_to_string(store.config_file()).unwrap();
        assert!(
            !on_disk.contains("s3cr3t-pw"),
            "plaintext on disk: {on_disk}"
        );
        let resolved = store.get_credentials();
        assert_eq!(resolved.username.as_deref(), Some("user"));
        assert_eq!(resolved.password.unwrap().expose(), "s3cr3t-pw");
    }

    #[test]
    fn default_config_dir_uses_home() {
        // Sanity: the production directory ends with the expected name.
        let dir = default_config_dir();
        assert!(dir.ends_with(CONFIG_DIR_NAME));
    }

    #[test]
    fn tls_bridge_registers_profile_mode() {
        let transport = Transport::new();
        let ekeng = ServerProfile::builtin(EKENG).unwrap();
        register_profile_tls_mode(&transport, &ekeng);
        assert_eq!(
            transport.host_tls_info("ca.gov.am"),
            "Legacy TLS (RC4, pinned key)"
        );
    }

    #[test]
    fn tls_bridge_registers_active_profile_from_config() {
        let (_dir, store) = test_store();
        store
            .save_server_config(&ServerProfile::builtin(EKENG).unwrap())
            .unwrap();
        let transport = Transport::new();
        register_active_profile_tls(&transport, &store);
        assert_eq!(
            transport.host_tls_info("ca.gov.am"),
            "Legacy TLS (RC4, pinned key)"
        );
    }

    #[test]
    fn tls_bridge_registers_standard_for_custom_https() {
        let (_dir, store) = test_store();
        let custom = ServerProfile::custom_default("https://example.com/DSS.asmx").unwrap();
        store.save_server_config(&custom).unwrap();
        let transport = Transport::new();
        register_active_profile_tls(&transport, &store);
        assert_eq!(transport.host_tls_info("example.com"), "Standard HTTPS");
    }
}
