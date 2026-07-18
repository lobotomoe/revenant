//! Server configuration, signer identity, language, and layer detection.
//!
//! The high-level settings operations layered on the storage primitives.
//! Resolution precedence for the server endpoint and timeout is
//! environment > config file > built-in profile.

use std::time::Duration;

use serde_json::{Map, Value};

use crate::constants::{
    DEFAULT_TIMEOUT_SOAP_SECS, ENV_TIMEOUT, ENV_URL, MAX_TIMEOUT_SECS, MIN_TIMEOUT_SECS,
};
use crate::error::RevenantError;

use super::profiles::{ServerProfile, BUILTIN_PROFILES};
use super::storage::{
    TypedConfig, IDENTITY_KEYS, KEY_LANGUAGE, KEY_NAME, KEY_PROFILE, KEY_TIMEOUT, KEY_URL,
};
use super::ConfigStore;

/// The language value meaning "follow the system locale".
pub const SYSTEM_LANGUAGE: &str = "system";

/// The active server endpoint and timeout, resolved from all sources.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedServerConfig {
    /// The SOAP endpoint URL.
    pub url: String,
    /// The request timeout in whole seconds.
    pub timeout: u32,
    /// The active profile name, if a named profile drives the config.
    pub profile_name: Option<String>,
}

impl ResolvedServerConfig {
    /// The timeout as a [`Duration`], for the transport layer.
    #[must_use]
    pub fn timeout_duration(&self) -> Duration {
        Duration::from_secs(u64::from(self.timeout))
    }
}

/// All saved signer-identity fields. Every field is optional; `name` is set
/// once identity is configured.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SignerInfo {
    pub name: Option<String>,
    pub email: Option<String>,
    pub organization: Option<String>,
    pub dn: Option<String>,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
}

/// The configuration completeness layer, gating which features are usable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ConfigLayer {
    /// Nothing configured -- offline verification only.
    Unconfigured = 0,
    /// Server configured -- offline plus server-side verification.
    ServerConfigured = 1,
    /// Server and identity configured -- all features.
    FullyConfigured = 2,
}

impl ConfigLayer {
    /// The numeric layer (0, 1, or 2) -- a stable external contract.
    #[must_use]
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

impl ConfigStore {
    /// Resolve the active server URL and timeout.
    ///
    /// Precedence: environment > config file > built-in profile. Returns `None`
    /// when no URL is configured from any source (the unconfigured state).
    #[must_use]
    pub fn server_config(&self) -> Option<ResolvedServerConfig> {
        let config = self.storage.load_typed();
        let profile_name = config.profile.clone();

        let url = self
            .env_nonempty(ENV_URL)
            .or_else(|| config.url.clone())
            .or_else(|| {
                profile_name
                    .as_deref()
                    .and_then(|name| BUILTIN_PROFILES.get(name))
                    .map(|profile| profile.url.clone())
            })?;

        let timeout = self.resolve_timeout(&config, profile_name.as_deref());
        Some(ResolvedServerConfig {
            url,
            timeout,
            profile_name,
        })
    }

    /// Resolve the timeout following env > config > profile > default, treating
    /// an invalid or out-of-range environment value as the default (with a
    /// warning), and an out-of-range config value as absent (already dropped by
    /// the typed load) so it falls through to the profile or default.
    fn resolve_timeout(&self, config: &TypedConfig, profile_name: Option<&str>) -> u32 {
        if let Some(raw) = self.env_nonempty(ENV_TIMEOUT) {
            return parse_env_timeout(&raw);
        }
        if let Some(timeout) = config.timeout {
            return timeout;
        }
        if let Some(name) = profile_name {
            if let Some(profile) = BUILTIN_PROFILES.get(name) {
                return profile.timeout;
            }
        }
        DEFAULT_TIMEOUT_SOAP_SECS
    }

    /// The [`ServerProfile`] for the currently configured server, if any.
    ///
    /// A saved built-in profile name resolves to that profile; otherwise a saved
    /// custom URL yields an ad-hoc profile. Unlike [`ConfigStore::server_config`]
    /// this consults only the config file, not the environment.
    #[must_use]
    pub fn active_profile(&self) -> Option<ServerProfile> {
        let config = self.storage.load_typed();
        if let Some(name) = &config.profile {
            if let Some(profile) = BUILTIN_PROFILES.get(name.as_str()) {
                return Some(profile.clone());
            }
        }
        let url = config.url?;
        let timeout = config.timeout.unwrap_or(DEFAULT_TIMEOUT_SOAP_SECS);
        match ServerProfile::custom(&url, timeout) {
            Ok(profile) => Some(profile),
            Err(e) => {
                log::warn!("Saved custom URL is invalid, ignoring active profile: {e}");
                None
            }
        }
    }

    /// Save a server profile (name, URL, timeout) to the config file.
    ///
    /// # Errors
    /// [`RevenantError::Config`] if the config file cannot be written.
    pub fn save_server_config(&self, profile: &ServerProfile) -> Result<(), RevenantError> {
        let mut raw = self.storage.load_raw_for_update()?;
        raw.insert(KEY_PROFILE.to_owned(), Value::String(profile.name.clone()));
        raw.insert(KEY_URL.to_owned(), Value::String(profile.url.clone()));
        raw.insert(KEY_TIMEOUT.to_owned(), Value::from(profile.timeout));
        self.storage.save(&raw)
    }

    /// The saved signer display name, if identity is configured.
    #[must_use]
    pub fn signer_name(&self) -> Option<String> {
        self.storage.load_typed().name.filter(|n| !n.is_empty())
    }

    /// All saved signer-identity fields.
    #[must_use]
    pub fn signer_info(&self) -> SignerInfo {
        let config = self.storage.load_typed();
        SignerInfo {
            name: config.name,
            email: config.email,
            organization: config.organization,
            dn: config.dn,
            not_before: config.not_before,
            not_after: config.not_after,
        }
    }

    /// Save signer identity, replacing any previously stored fields.
    ///
    /// The `name` must be set. Optional fields that are empty or absent are
    /// removed, so stale data from a prior identity never persists. Server
    /// config, credentials, and language are preserved.
    ///
    /// # Errors
    /// [`RevenantError::Config`] if `name` is missing or the file cannot be
    /// written.
    pub fn save_signer_info(&self, info: &SignerInfo) -> Result<(), RevenantError> {
        let Some(name) = info.name.as_deref().filter(|n| !n.is_empty()) else {
            return Err(RevenantError::Config(
                "Signer name is required to save identity".to_owned(),
            ));
        };

        let mut raw = self.storage.load_raw_for_update()?;
        raw.insert(KEY_NAME.to_owned(), Value::String(name.to_owned()));

        let optional = [
            (super::storage::KEY_EMAIL, &info.email),
            (super::storage::KEY_ORGANIZATION, &info.organization),
            (super::storage::KEY_DN, &info.dn),
            (super::storage::KEY_NOT_BEFORE, &info.not_before),
            (super::storage::KEY_NOT_AFTER, &info.not_after),
        ];
        for (key, value) in optional {
            match value.as_deref().filter(|v| !v.is_empty()) {
                Some(value) => {
                    raw.insert(key.to_owned(), Value::String(value.to_owned()));
                }
                None => {
                    raw.remove(key);
                }
            }
        }
        self.storage.save(&raw)
    }

    /// Clear everything -- credentials, identity, and server profile --
    /// returning to the unconfigured state. The language preference is kept.
    ///
    /// # Errors
    /// [`RevenantError::Config`] if the config file cannot be written.
    pub fn reset_all(&self) -> Result<(), RevenantError> {
        self.clear_credentials()?;
        self.clear_session_credentials();

        let raw = self.storage.load_raw_for_update()?;
        let mut preserved = Map::new();
        if let Some(language) = raw.get(KEY_LANGUAGE) {
            preserved.insert(KEY_LANGUAGE.to_owned(), language.clone());
        }
        self.storage.save(&preserved)
    }

    /// Clear credentials and signer identity, preserving the server config.
    ///
    /// # Errors
    /// [`RevenantError::Config`] if the config file cannot be written.
    pub fn logout(&self) -> Result<(), RevenantError> {
        self.clear_credentials()?;
        self.clear_session_credentials();

        let mut raw = self.storage.load_raw_for_update()?;
        let mut changed = false;
        for key in IDENTITY_KEYS {
            if raw.remove(key).is_some() {
                changed = true;
            }
        }
        if changed {
            self.storage.save(&raw)?;
        }
        Ok(())
    }

    /// The saved language preference, or `"system"` if unset.
    #[must_use]
    pub fn language(&self) -> String {
        self.storage
            .load_typed()
            .language
            .unwrap_or_else(|| SYSTEM_LANGUAGE.to_owned())
    }

    /// Save the language preference. `"system"` removes the stored override.
    ///
    /// # Errors
    /// [`RevenantError::Config`] if the config file cannot be written.
    pub fn save_language(&self, language: &str) -> Result<(), RevenantError> {
        let mut raw = self.storage.load_raw_for_update()?;
        if language == SYSTEM_LANGUAGE {
            raw.remove(KEY_LANGUAGE);
        } else {
            raw.insert(KEY_LANGUAGE.to_owned(), Value::String(language.to_owned()));
        }
        self.storage.save(&raw)
    }

    /// Determine the current configuration layer.
    #[must_use]
    pub fn config_layer(&self) -> ConfigLayer {
        if self.server_config().is_none() {
            return ConfigLayer::Unconfigured;
        }
        if self.signer_name().is_none() {
            return ConfigLayer::ServerConfigured;
        }
        ConfigLayer::FullyConfigured
    }
}

/// Parse an environment timeout string, falling back to the default (with a
/// warning) on non-integers or out-of-range values.
fn parse_env_timeout(raw: &str) -> u32 {
    let Ok(secs) = raw.parse::<i64>() else {
        log::warn!("Invalid {ENV_TIMEOUT} value {raw:?}, using default");
        return DEFAULT_TIMEOUT_SOAP_SECS;
    };
    match u64::try_from(secs) {
        Ok(secs) if (MIN_TIMEOUT_SECS..=MAX_TIMEOUT_SECS).contains(&secs) => {
            u32::try_from(secs).unwrap_or(DEFAULT_TIMEOUT_SOAP_SECS)
        }
        _ => {
            log::warn!(
                "{ENV_TIMEOUT}={secs} out of range [{MIN_TIMEOUT_SECS}, {MAX_TIMEOUT_SECS}], using default"
            );
            DEFAULT_TIMEOUT_SOAP_SECS
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{test_store, test_store_with_env, ResolvedCredentials};

    #[test]
    fn unconfigured_store_has_no_server_and_layer_zero() {
        let (_dir, store) = test_store();
        assert!(store.server_config().is_none());
        assert_eq!(store.config_layer(), ConfigLayer::Unconfigured);
    }

    #[test]
    fn saved_ekeng_profile_resolves() {
        let (_dir, store) = test_store();
        let ekeng = ServerProfile::builtin("ekeng").unwrap();
        store.save_server_config(&ekeng).unwrap();

        let resolved = store.server_config().expect("configured");
        assert_eq!(resolved.url, "https://ca.gov.am:8080/SAPIWS/DSS.asmx");
        assert_eq!(resolved.timeout, 120);
        assert_eq!(resolved.profile_name.as_deref(), Some("ekeng"));
        assert_eq!(resolved.timeout_duration(), Duration::from_secs(120));

        let active = store.active_profile().expect("active");
        assert_eq!(active.name, "ekeng");
        assert_eq!(active.tls_mode, crate::net::TlsMode::Legacy);
    }

    #[test]
    fn env_url_overrides_config() {
        let (_dir, store) =
            test_store_with_env(&[("REVENANT_URL", "https://override.example/DSS.asmx")]);
        let ekeng = ServerProfile::builtin("ekeng").unwrap();
        store.save_server_config(&ekeng).unwrap();
        let resolved = store.server_config().unwrap();
        assert_eq!(resolved.url, "https://override.example/DSS.asmx");
        // profile_name still reflects the saved profile.
        assert_eq!(resolved.profile_name.as_deref(), Some("ekeng"));
    }

    #[test]
    fn env_timeout_overrides_and_validates() {
        let (_dir, store) = test_store_with_env(&[
            ("REVENANT_URL", "https://x.example/DSS.asmx"),
            ("REVENANT_TIMEOUT", "45"),
        ]);
        assert_eq!(store.server_config().unwrap().timeout, 45);

        let (_dir2, bad) = test_store_with_env(&[
            ("REVENANT_URL", "https://x.example/DSS.asmx"),
            ("REVENANT_TIMEOUT", "99999"),
        ]);
        assert_eq!(
            bad.server_config().unwrap().timeout,
            DEFAULT_TIMEOUT_SOAP_SECS
        );

        let (_dir3, invalid) = test_store_with_env(&[
            ("REVENANT_URL", "https://x.example/DSS.asmx"),
            ("REVENANT_TIMEOUT", "notanumber"),
        ]);
        assert_eq!(
            invalid.server_config().unwrap().timeout,
            DEFAULT_TIMEOUT_SOAP_SECS
        );
    }

    #[test]
    fn signer_info_roundtrip_and_stale_clear() {
        let (_dir, store) = test_store();
        let info = SignerInfo {
            name: Some("Jane Doe 12345".to_owned()),
            email: Some("jane@example.am".to_owned()),
            organization: Some("Gov".to_owned()),
            ..SignerInfo::default()
        };
        store.save_signer_info(&info).unwrap();
        assert_eq!(store.signer_name().as_deref(), Some("Jane Doe 12345"));
        let loaded = store.signer_info();
        assert_eq!(loaded.email.as_deref(), Some("jane@example.am"));
        assert_eq!(loaded.organization.as_deref(), Some("Gov"));
        assert!(loaded.dn.is_none());

        // Saving a new identity without the optional fields clears the stale ones.
        let info2 = SignerInfo {
            name: Some("Bob 67890".to_owned()),
            ..SignerInfo::default()
        };
        store.save_signer_info(&info2).unwrap();
        let loaded2 = store.signer_info();
        assert_eq!(loaded2.name.as_deref(), Some("Bob 67890"));
        assert!(loaded2.email.is_none(), "stale email should be cleared");
        assert!(loaded2.organization.is_none());
    }

    #[test]
    fn save_signer_info_requires_name() {
        let (_dir, store) = test_store();
        let err = store.save_signer_info(&SignerInfo::default()).unwrap_err();
        assert!(err.to_string().contains("name is required"));
    }

    #[test]
    fn layers_progress_with_configuration() {
        let (_dir, store) = test_store();
        assert_eq!(store.config_layer(), ConfigLayer::Unconfigured);

        store
            .save_server_config(&ServerProfile::builtin("ekeng").unwrap())
            .unwrap();
        assert_eq!(store.config_layer(), ConfigLayer::ServerConfigured);

        store
            .save_signer_info(&SignerInfo {
                name: Some("Jane 12345".to_owned()),
                ..SignerInfo::default()
            })
            .unwrap();
        assert_eq!(store.config_layer(), ConfigLayer::FullyConfigured);
        assert_eq!(store.config_layer().as_u8(), 2);
    }

    #[test]
    fn logout_clears_identity_keeps_server() {
        let (_dir, store) = test_store();
        store
            .save_server_config(&ServerProfile::builtin("ekeng").unwrap())
            .unwrap();
        store
            .save_signer_info(&SignerInfo {
                name: Some("Jane 12345".to_owned()),
                ..SignerInfo::default()
            })
            .unwrap();
        store.save_credentials("jane", "pw").unwrap();

        store.logout().unwrap();
        assert!(store.signer_name().is_none());
        assert_eq!(store.get_credentials(), ResolvedCredentials::default());
        // Server config survives.
        assert!(store.server_config().is_some());
        assert_eq!(store.config_layer(), ConfigLayer::ServerConfigured);
    }

    #[test]
    fn reset_all_clears_everything_but_language() {
        let (_dir, store) = test_store();
        store.save_language("hy").unwrap();
        store
            .save_server_config(&ServerProfile::builtin("ekeng").unwrap())
            .unwrap();
        store.save_credentials("jane", "pw").unwrap();

        store.reset_all().unwrap();
        assert!(store.server_config().is_none());
        assert_eq!(store.get_credentials(), ResolvedCredentials::default());
        assert_eq!(store.config_layer(), ConfigLayer::Unconfigured);
        // Language preference is preserved.
        assert_eq!(store.language(), "hy");
    }

    #[test]
    fn save_on_corrupt_config_fails_loud_without_destroying_it() {
        let (dir, store) = test_store();
        let path = dir.path().join("config.json");
        std::fs::create_dir_all(dir.path()).unwrap();
        std::fs::write(&path, b"{ this is corrupt").unwrap();

        // A write must fail loud instead of silently replacing the file.
        let err = store.save_language("ru").unwrap_err();
        assert!(matches!(err, RevenantError::Config(_)));

        // The corrupt file is left intact, not overwritten with {"language":"ru"}.
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text, "{ this is corrupt");
    }

    #[test]
    fn language_default_and_system_removal() {
        let (_dir, store) = test_store();
        assert_eq!(store.language(), "system");
        store.save_language("ru").unwrap();
        assert_eq!(store.language(), "ru");
        store.save_language("system").unwrap();
        assert_eq!(store.language(), "system");
    }
}
