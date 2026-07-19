//! Shared UI colors, mirroring the Python client's result palette.

use eframe::egui::Color32;

/// Success / valid.
pub(crate) const OK: Color32 = Color32::from_rgb(0x22, 0x8B, 0x22);

/// Failure / invalid.
pub(crate) const ERROR: Color32 = Color32::from_rgb(0xCC, 0x00, 0x00);

/// Caution — recoverable but needs attention (e.g. lockout warning).
pub(crate) const WARNING: Color32 = Color32::from_rgb(0xCC, 0x77, 0x00);

/// De-emphasized secondary text (step indicators, storage hints).
pub(crate) const MUTED: Color32 = Color32::from_rgb(0xAA, 0xAA, 0xAA);

/// Accent for the primary action on a screen and for selection highlights.
pub(crate) const ACCENT: Color32 = Color32::from_rgb(0x2F, 0x6F, 0xEB);

/// Text drawn on top of [`ACCENT`] (filled primary buttons).
pub(crate) const ON_ACCENT: Color32 = Color32::WHITE;
