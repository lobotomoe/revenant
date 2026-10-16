//! Shared UI colors, mirroring the Python client's result palette.

use std::sync::OnceLock;

use eframe::egui::Color32;

/// Success / valid.
pub(crate) const OK: Color32 = Color32::from_rgb(0x22, 0x8B, 0x22);

/// Failure / invalid.
pub(crate) const ERROR: Color32 = Color32::from_rgb(0xCC, 0x00, 0x00);

/// Caution — recoverable but needs attention (e.g. lockout warning).
pub(crate) const WARNING: Color32 = Color32::from_rgb(0xCC, 0x77, 0x00);

/// Accent where the platform does not offer one (and on macOS if it cannot be
/// read).
const DEFAULT_ACCENT: Color32 = Color32::from_rgb(0x2F, 0x6F, 0xEB);

static ACCENT: OnceLock<Color32> = OnceLock::new();

/// Accent for the primary action on a screen and for selection highlights: the
/// one chosen in System Settings on macOS, read once at startup.
pub(crate) fn accent() -> Color32 {
    *ACCENT.get_or_init(platform_accent)
}

#[cfg(target_os = "macos")]
fn platform_accent() -> Color32 {
    crate::macos::accent_color().unwrap_or_else(|| {
        log::warn!("the system accent color has no sRGB form; using the default accent");
        DEFAULT_ACCENT
    })
}

#[cfg(not(target_os = "macos"))]
fn platform_accent() -> Color32 {
    DEFAULT_ACCENT
}

/// Text drawn on top of [`accent`] (filled primary buttons): on macOS the
/// color AppKit itself uses on accent-filled controls, read once at startup.
pub(crate) fn on_accent() -> Color32 {
    *ON_ACCENT.get_or_init(platform_on_accent)
}

static ON_ACCENT: OnceLock<Color32> = OnceLock::new();

#[cfg(target_os = "macos")]
fn platform_on_accent() -> Color32 {
    crate::macos::on_accent_color().unwrap_or_else(|| {
        log::warn!("the system text-on-accent color has no sRGB form; using white");
        Color32::WHITE
    })
}

#[cfg(not(target_os = "macos"))]
fn platform_on_accent() -> Color32 {
    Color32::WHITE
}
