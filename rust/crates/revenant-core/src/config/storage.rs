//! Low-level `config.json` I/O.
//!
//! The shared storage layer that both settings and credentials build on. It
//! offers a two-tier view of the file:
//!
//! * [`Storage::load_raw`] returns the on-disk object verbatim, preserving
//!   unknown keys so a rewrite never drops fields a newer version wrote
//!   (forward-compatibility).
//! * [`Storage::load_typed`] returns only the known keys, each validated to the
//!   expected type and range -- the safe view settings/credentials read from.
//!
//! Writes go through [`Storage::save`], which is atomic (temp file + rename) and
//! restricts permissions to `0600` (file) / `0700` (directory) on Unix.

use std::fs;
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};

use serde_json::{Map, Value};
use tempfile::NamedTempFile;

use crate::constants::{MAX_TIMEOUT_SECS, MIN_TIMEOUT_SECS};
use crate::error::RevenantError;

use super::secret::Secret;

/// Config file name inside the config directory.
const CONFIG_FILE_NAME: &str = "config.json";

// Known config keys. Centralized so settings/credentials never spell them
// inline, and the on-disk schema has a single source of truth.
pub(crate) const KEY_PROFILE: &str = "profile";
pub(crate) const KEY_URL: &str = "url";
pub(crate) const KEY_TIMEOUT: &str = "timeout";
pub(crate) const KEY_USERNAME: &str = "username";
pub(crate) const KEY_PASSWORD: &str = "password";
pub(crate) const KEY_NAME: &str = "name";
pub(crate) const KEY_EMAIL: &str = "email";
pub(crate) const KEY_ORGANIZATION: &str = "organization";
pub(crate) const KEY_DN: &str = "dn";
pub(crate) const KEY_LANGUAGE: &str = "language";
pub(crate) const KEY_NOT_BEFORE: &str = "not_before";
pub(crate) const KEY_NOT_AFTER: &str = "not_after";

/// The known config keys that hold signer identity (cleared on logout).
pub(crate) const IDENTITY_KEYS: [&str; 6] = [
    KEY_NAME,
    KEY_EMAIL,
    KEY_ORGANIZATION,
    KEY_DN,
    KEY_NOT_BEFORE,
    KEY_NOT_AFTER,
];

/// The validated, known-key view of the config file.
///
/// Every field is optional, strings are taken only when the stored value is
/// actually a string, and `timeout` is present only when it is an integer within
/// `[MIN_TIMEOUT_SECS, MAX_TIMEOUT_SECS]`.
#[derive(Debug, Default)]
pub(crate) struct TypedConfig {
    pub profile: Option<String>,
    pub url: Option<String>,
    pub timeout: Option<u32>,
    pub username: Option<String>,
    pub password: Option<Secret>,
    pub name: Option<String>,
    pub email: Option<String>,
    pub organization: Option<String>,
    pub dn: Option<String>,
    pub language: Option<String>,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
}

/// The on-disk config store: owns the directory and file paths.
///
/// The paths are fields, not constants, so the whole config layer can be pointed
/// at a temp directory in tests without touching the real `~/.revenant`.
#[derive(Debug, Clone)]
pub(crate) struct Storage {
    dir: PathBuf,
    file: PathBuf,
}

impl Storage {
    /// Create a store rooted at `dir`, with `config.json` inside it.
    pub(crate) fn new(dir: PathBuf) -> Self {
        let file = dir.join(CONFIG_FILE_NAME);
        Storage { dir, file }
    }

    /// The config directory (`~/.revenant` in production). Test-only accessor;
    /// production code reaches the directory through the file path's parent.
    #[cfg(test)]
    pub(crate) fn dir(&self) -> &Path {
        &self.dir
    }

    /// The config file path (`~/.revenant/config.json`).
    pub(crate) fn file(&self) -> &Path {
        &self.file
    }

    /// Load the raw config object, preserving every key.
    ///
    /// Returns an empty map when the file is missing, unreadable, corrupt, or
    /// holds valid JSON that is not an object. Only genuinely unexpected states
    /// (unreadable-but-present, corrupt JSON) are logged; a missing file is the
    /// normal unconfigured state and stays silent.
    pub(crate) fn load_raw(&self) -> Map<String, Value> {
        let text = match fs::read_to_string(&self.file) {
            Ok(text) => text,
            Err(e) if e.kind() == ErrorKind::NotFound => return Map::new(),
            Err(e) => {
                log::warn!("Cannot read config file {}: {e}", self.file.display());
                return Map::new();
            }
        };
        match serde_json::from_str::<Value>(&text) {
            Ok(Value::Object(map)) => map,
            Ok(_) => Map::new(), // valid JSON but not an object -> treat as empty
            Err(e) => {
                log::warn!("Config file corrupted, ignoring: {e}");
                Map::new()
            }
        }
    }

    /// Load the validated, known-key view of the config.
    pub(crate) fn load_typed(&self) -> TypedConfig {
        let raw = self.load_raw();
        TypedConfig {
            profile: pick_str(&raw, KEY_PROFILE),
            url: pick_str(&raw, KEY_URL),
            timeout: pick_timeout(&raw),
            username: pick_str(&raw, KEY_USERNAME),
            password: pick_str(&raw, KEY_PASSWORD).map(Secret::new),
            name: pick_str(&raw, KEY_NAME),
            email: pick_str(&raw, KEY_EMAIL),
            organization: pick_str(&raw, KEY_ORGANIZATION),
            dn: pick_str(&raw, KEY_DN),
            language: pick_str(&raw, KEY_LANGUAGE),
            not_before: pick_str(&raw, KEY_NOT_BEFORE),
            not_after: pick_str(&raw, KEY_NOT_AFTER),
        }
    }

    /// Persist the raw config object atomically with restricted permissions.
    ///
    /// Writes to a temp file in the same directory (so the rename is atomic on
    /// the same filesystem), fsyncs it, then renames over the target. On Unix
    /// the directory is forced to `0700` and the file to `0600`.
    ///
    /// # Errors
    /// [`RevenantError::Config`] if the directory or file cannot be written.
    pub(crate) fn save(&self, config: &Map<String, Value>) -> Result<(), RevenantError> {
        fs::create_dir_all(&self.dir).map_err(|e| {
            RevenantError::Config(format!(
                "Cannot create config directory {}: {e}",
                self.dir.display()
            ))
        })?;
        harden_dir_permissions(&self.dir);

        // On-disk format is a stable contract: 2-space indent, non-ASCII left as
        // UTF-8 (not \u-escaped), trailing newline.
        let mut content = serde_json::to_string_pretty(config)
            .map_err(|e| RevenantError::Config(format!("Cannot serialize config: {e}")))?;
        content.push('\n');

        let mut tmp = NamedTempFile::new_in(&self.dir).map_err(|e| {
            RevenantError::Config(format!(
                "Cannot create temp file in {}: {e}",
                self.dir.display()
            ))
        })?;
        harden_file_permissions(tmp.path());
        tmp.write_all(content.as_bytes())
            .and_then(|()| tmp.as_file().sync_all())
            .map_err(|e| {
                RevenantError::Config(format!(
                    "Cannot write config to {}: {e}",
                    self.dir.display()
                ))
            })?;
        tmp.persist(&self.file).map_err(|e| {
            RevenantError::Config(format!(
                "Cannot replace config file {}: {}",
                self.file.display(),
                e.error
            ))
        })?;
        Ok(())
    }
}

/// Return `map[key]` when it is a JSON string, else `None`.
fn pick_str(map: &Map<String, Value>, key: &str) -> Option<String> {
    map.get(key).and_then(Value::as_str).map(str::to_owned)
}

/// Return `map["timeout"]` when it is an integer within the allowed range.
///
/// Non-integer values (floats, strings, bools, absent) are silently ignored,
/// while an in-schema integer that falls outside `[MIN, MAX]` is logged and
/// dropped.
fn pick_timeout(map: &Map<String, Value>) -> Option<u32> {
    let value = map.get(KEY_TIMEOUT)?;
    let Some(secs) = value.as_i64() else {
        return None; // not an integer (float/string/bool) -> ignore
    };
    match u64::try_from(secs) {
        Ok(secs) if (MIN_TIMEOUT_SECS..=MAX_TIMEOUT_SECS).contains(&secs) => {
            u32::try_from(secs).ok()
        }
        _ => {
            log::warn!(
                "Config timeout={secs} out of range [{MIN_TIMEOUT_SECS}, {MAX_TIMEOUT_SECS}], ignoring"
            );
            None
        }
    }
}

/// Best-effort restriction of the config directory to `0700` on Unix.
///
/// A permission failure is logged but not fatal: on a filesystem that rejects
/// chmod (some network mounts) the config is still usable, just less private.
#[cfg(unix)]
fn harden_dir_permissions(dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Err(e) = fs::set_permissions(dir, fs::Permissions::from_mode(0o700)) {
        log::warn!(
            "Failed to set restrictive permissions on {}: {e}",
            dir.display()
        );
    }
}

/// Restrict the temp config file to `0600` on Unix before it is renamed into
/// place, so the real file is never briefly world-readable.
#[cfg(unix)]
fn harden_file_permissions(file: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Err(e) = fs::set_permissions(file, fs::Permissions::from_mode(0o600)) {
        log::warn!(
            "Failed to set restrictive permissions on {}. \
             Config file may be readable by other users: {e}",
            file.display()
        );
    }
}

#[cfg(not(unix))]
fn harden_dir_permissions(_dir: &Path) {}

#[cfg(not(unix))]
fn harden_file_permissions(_file: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn temp_storage() -> (tempfile::TempDir, Storage) {
        let dir = tempfile::tempdir().expect("temp dir");
        let storage = Storage::new(dir.path().to_path_buf());
        (dir, storage)
    }

    #[test]
    fn load_missing_file_is_empty() {
        let (_guard, storage) = temp_storage();
        assert!(storage.load_raw().is_empty());
        assert!(storage.load_typed().url.is_none());
    }

    #[test]
    fn save_then_load_roundtrips_and_preserves_unknown_keys() {
        let (_guard, storage) = temp_storage();
        let mut map = Map::new();
        map.insert(KEY_URL.to_owned(), json!("https://ca.gov.am:8080/x"));
        map.insert(KEY_TIMEOUT.to_owned(), json!(90));
        // A key the current schema does not know about.
        map.insert("future_flag".to_owned(), json!(true));
        storage.save(&map).expect("save");

        let raw = storage.load_raw();
        assert_eq!(raw.get("future_flag"), Some(&json!(true)));

        let typed = storage.load_typed();
        assert_eq!(typed.url.as_deref(), Some("https://ca.gov.am:8080/x"));
        assert_eq!(typed.timeout, Some(90));
    }

    #[test]
    fn corrupt_json_loads_as_empty() {
        let (_guard, storage) = temp_storage();
        fs::create_dir_all(storage.dir()).unwrap();
        fs::write(storage.file(), b"{not valid json").unwrap();
        assert!(storage.load_raw().is_empty());
    }

    #[test]
    fn non_object_json_loads_as_empty() {
        let (_guard, storage) = temp_storage();
        fs::create_dir_all(storage.dir()).unwrap();
        fs::write(storage.file(), b"[1, 2, 3]").unwrap();
        assert!(storage.load_raw().is_empty());
    }

    #[test]
    fn timeout_out_of_range_is_dropped() {
        let (_guard, storage) = temp_storage();
        for bad in [json!(0), json!(3601), json!(-5), json!(120.5), json!("120")] {
            let mut map = Map::new();
            map.insert(KEY_TIMEOUT.to_owned(), bad);
            storage.save(&map).unwrap();
            assert_eq!(storage.load_typed().timeout, None);
        }
        let mut map = Map::new();
        map.insert(KEY_TIMEOUT.to_owned(), json!(3600));
        storage.save(&map).unwrap();
        assert_eq!(storage.load_typed().timeout, Some(3600));
    }

    #[test]
    fn saved_file_is_pretty_with_trailing_newline() {
        let (_guard, storage) = temp_storage();
        let mut map = Map::new();
        map.insert(KEY_NAME.to_owned(), json!("Jane"));
        storage.save(&map).unwrap();
        let text = fs::read_to_string(storage.file()).unwrap();
        assert_eq!(text, "{\n  \"name\": \"Jane\"\n}\n");
    }

    #[cfg(unix)]
    #[test]
    fn saved_file_has_0600_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let (_guard, storage) = temp_storage();
        storage.save(&Map::new()).unwrap();
        let mode = fs::metadata(storage.file()).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        let dir_mode = fs::metadata(storage.dir()).unwrap().permissions().mode();
        assert_eq!(dir_mode & 0o777, 0o700);
    }
}
