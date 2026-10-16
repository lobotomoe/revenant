//! What the app takes from macOS itself so it looks at home there: the user's
//! accent color and the system San Francisco fonts.
//!
//! San Francisco may not be redistributed, so it is never bundled; it is read
//! from the system font folder at startup, and the bundled Noto faces stay
//! behind it as fallbacks.

use std::path::Path;

use eframe::egui::Color32;
use objc2_app_kit::{NSColor, NSColorSpace};

const SYSTEM_FONT_DIR: &str = "/System/Library/Fonts";

/// The San Francisco faces to use, as (font name, file in [`SYSTEM_FONT_DIR`]),
/// in fallback order. Arabic script stays on the bundled Noto face, whose
/// rendering in the Persian UI is already checked.
const SYSTEM_FONTS: &[(&str, &str)] = &[
    ("SanFrancisco", "SFNS.ttf"),
    ("SanFranciscoArmenian", "SFArmenian.ttf"),
    ("SanFranciscoGeorgian", "SFGeorgian.ttf"),
];

/// The accent color chosen in System Settings > Appearance, in sRGB.
pub(crate) fn accent_color() -> Option<Color32> {
    to_color32(&NSColor::controlAccentColor())
}

/// The color AppKit draws text in on an accent-filled control.
pub(crate) fn on_accent_color() -> Option<Color32> {
    to_color32(&NSColor::alternateSelectedControlTextColor())
}

/// A system color resolved for the current appearance, in sRGB. `None` for a
/// color with no sRGB form, such as a pattern.
fn to_color32(color: &NSColor) -> Option<Color32> {
    let srgb = NSColorSpace::sRGBColorSpace();
    let resolved = color.colorUsingColorSpace(&srgb)?;
    Some(Color32::from_rgb(
        channel_to_byte(resolved.redComponent()),
        channel_to_byte(resolved.greenComponent()),
        channel_to_byte(resolved.blueComponent()),
    ))
}

fn channel_to_byte(channel: f64) -> u8 {
    // Clamped to 0..=255 first, so the cast cannot truncate.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let byte = (channel.clamp(0.0, 1.0) * 255.0).round() as u8;
    byte
}

/// The San Francisco fonts present on this system, as (font name, bytes). A
/// face that cannot be read is logged and left out, and the bundled font that
/// follows it in the fallback list draws that script instead.
pub(crate) fn system_fonts() -> Vec<(&'static str, Vec<u8>)> {
    let dir = Path::new(SYSTEM_FONT_DIR);
    SYSTEM_FONTS
        .iter()
        .filter_map(|(name, file)| {
            let path = dir.join(file);
            match std::fs::read(&path) {
                Ok(bytes) => Some((*name, bytes)),
                Err(error) => {
                    log::warn!("system font {} not loaded: {error}", path.display());
                    None
                }
            }
        })
        .collect()
}
