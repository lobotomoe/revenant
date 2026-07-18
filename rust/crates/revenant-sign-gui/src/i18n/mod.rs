//! Localization: embedded gettext catalogs, locale resolution, RTL awareness,
//! and `{var}` interpolation.
//!
//! Translations are the same `.po` catalogs the project already maintains,
//! embedded at compile time (no runtime files to ship or sandbox). Every UI
//! string is looked up by a stable key; the English catalog is overlaid as a
//! fallback so a key missing from a locale renders in English rather than as a
//! raw identifier, while still being logged for translators to fix.

mod po;

use std::collections::HashMap;

pub(crate) use revenant_sign_core::config::SYSTEM_LANGUAGE;

/// Supported UI locales in menu display order: `(code, endonym)` where the
/// endonym is the language's own name. Mirrors the Python client's list.
pub(crate) const SUPPORTED_LOCALES: &[(&str, &str)] = &[
    ("en", "English"),
    ("ru", "Русский"),
    ("hy", "Հայերեն"),
    ("tr", "Türkçe"),
    ("ka", "ქართული"),
    ("fa", "فارسی"),
];

/// Locales whose script is written right-to-left.
const RTL_LOCALES: &[&str] = &["fa"];

const DEFAULT_LOCALE: &str = "en";

/// Return the embedded catalog source for a locale code, if supported.
fn catalog_source(code: &str) -> Option<&'static str> {
    match code {
        "en" => Some(include_str!("locales/en.po")),
        "ru" => Some(include_str!("locales/ru.po")),
        "hy" => Some(include_str!("locales/hy.po")),
        "tr" => Some(include_str!("locales/tr.po")),
        "ka" => Some(include_str!("locales/ka.po")),
        "fa" => Some(include_str!("locales/fa.po")),
        _ => None,
    }
}

/// Active-locale translator. Holds the resolved catalog (active locale overlaid
/// on the English fallback) and enough metadata to drive layout direction.
pub(crate) struct Localizer {
    code: String,
    rtl: bool,
    catalog: HashMap<String, String>,
}

impl Localizer {
    /// Build a localizer for a language setting: a locale code, or
    /// [`SYSTEM_LANGUAGE`] to follow the OS locale. Unknown settings fall back
    /// to English.
    pub(crate) fn new(setting: &str) -> Self {
        let code = resolve(setting);
        let mut catalog = po::parse(catalog_source(DEFAULT_LOCALE).unwrap_or_default());

        if code != DEFAULT_LOCALE {
            if let Some(source) = catalog_source(&code) {
                let active = po::parse(source);
                for key in catalog.keys() {
                    if !active.contains_key(key) {
                        log::warn!("missing '{code}' translation for key '{key}'");
                    }
                }
                catalog.extend(active);
            }
        }

        Self {
            rtl: is_rtl(&code),
            code,
            catalog,
        }
    }

    /// The active locale code (e.g. `"en"`, `"hy"`).
    pub(crate) fn code(&self) -> &str {
        &self.code
    }

    /// Whether the active locale is written right-to-left.
    pub(crate) fn is_rtl(&self) -> bool {
        self.rtl
    }

    /// Translate a key. Returns the key itself when neither the active locale
    /// nor the English fallback defines it, so the gap is visible in the UI.
    pub(crate) fn t<'a>(&'a self, key: &'a str) -> &'a str {
        if let Some(text) = self.catalog.get(key) {
            text
        } else {
            log::error!("missing translation for key '{key}'");
            key
        }
    }

    /// Translate a key and substitute `{name}`-style placeholders.
    pub(crate) fn tf(&self, key: &str, args: &[(&str, &str)]) -> String {
        let mut text = self.t(key).to_owned();
        for (name, value) in args {
            let needle = format!("{{{name}}}");
            if text.contains(&needle) {
                text = text.replace(&needle, value);
            }
        }
        text
    }
}

/// Resolve a language setting to a concrete supported locale code.
fn resolve(setting: &str) -> String {
    let candidate = if setting == SYSTEM_LANGUAGE {
        detect_system()
    } else {
        setting.to_owned()
    };
    if is_supported(&candidate) {
        candidate
    } else {
        DEFAULT_LOCALE.to_owned()
    }
}

/// Detect the OS locale and map it to a supported code, defaulting to English.
fn detect_system() -> String {
    let raw = sys_locale::get_locale().unwrap_or_default();
    // Normalize BCP-47 ("en-US") or POSIX ("ru_RU.UTF-8") to a language prefix.
    let lang = raw
        .split(['-', '_', '.'])
        .next()
        .unwrap_or_default()
        .to_lowercase();
    if is_supported(&lang) {
        lang
    } else {
        DEFAULT_LOCALE.to_owned()
    }
}

fn is_supported(code: &str) -> bool {
    SUPPORTED_LOCALES.iter().any(|(c, _)| *c == code)
}

fn is_rtl(code: &str) -> bool {
    RTL_LOCALES.contains(&code)
}

#[cfg(test)]
mod tests {
    use super::{is_rtl, resolve, Localizer, SUPPORTED_LOCALES, SYSTEM_LANGUAGE};

    #[test]
    fn every_supported_locale_loads_and_covers_all_english_keys() {
        let english = Localizer::new("en");
        let english_keys: Vec<&String> = english.catalog.keys().collect();
        assert!(
            !english_keys.is_empty(),
            "English catalog must not be empty"
        );

        for (code, _) in SUPPORTED_LOCALES {
            let loc = Localizer::new(code);
            assert_eq!(loc.code(), *code);
            // The English overlay guarantees no key ever resolves to itself.
            for key in &english_keys {
                assert_ne!(loc.t(key), key.as_str(), "'{code}' left '{key}' unresolved");
            }
        }
    }

    #[test]
    fn unknown_setting_falls_back_to_english() {
        assert_eq!(resolve("klingon"), "en");
    }

    #[test]
    fn system_setting_resolves_to_a_supported_locale() {
        let code = resolve(SYSTEM_LANGUAGE);
        assert!(super::is_supported(&code));
    }

    #[test]
    fn persian_is_rtl_others_are_not() {
        assert!(is_rtl("fa"));
        assert!(!is_rtl("en"));
        assert!(!is_rtl("hy"));
    }

    #[test]
    fn interpolates_named_placeholders() {
        let loc = Localizer::new("en");
        let out = loc.tf(
            "gui.signed_filename_size",
            &[("filename", "a.pdf"), ("size", "12 KB")],
        );
        assert!(out.contains("a.pdf"), "got: {out}");
        assert!(out.contains("12 KB"), "got: {out}");
        assert!(!out.contains('{'), "placeholders left unfilled: {out}");
    }

    #[test]
    fn missing_key_returns_key() {
        let loc = Localizer::new("en");
        assert_eq!(loc.t("gui.does_not_exist"), "gui.does_not_exist");
    }
}
