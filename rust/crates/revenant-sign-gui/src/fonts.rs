//! Font installation: bundle Noto Sans families so every supported UI language
//! renders real glyphs.
//!
//! egui's built-in fonts do not cover Armenian, Georgian, or Arabic, so we
//! install Noto Sans (Latin/Greek/Cyrillic) as the primary proportional face
//! and add the Armenian, Georgian, and Arabic subfamilies as per-glyph
//! fallbacks. This makes hy/ka/fa legible. Arabic contextual joining (Persian)
//! is a separate, deferred enhancement -- letters render in isolated forms for
//! now, matching the previous tkinter client.
//!
//! The fonts are Noto, licensed under the SIL Open Font License 1.1; see
//! `fonts/OFL.txt`.

use std::sync::Arc;

use eframe::egui;

/// Font families added as fallbacks, in priority order after the primary face.
const SCRIPT_FALLBACKS: &[&str] = &["NotoSansArmenian", "NotoSansGeorgian", "NotoSansArabic"];

/// Install the bundled Noto Sans fonts into the egui context. Called once at
/// startup from the creation context.
pub(crate) fn install(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();

    add(
        &mut fonts,
        "NotoSans",
        include_bytes!("fonts/NotoSans-Regular.ttf"),
    );
    add(
        &mut fonts,
        "NotoSansArmenian",
        include_bytes!("fonts/NotoSansArmenian-Regular.ttf"),
    );
    add(
        &mut fonts,
        "NotoSansGeorgian",
        include_bytes!("fonts/NotoSansGeorgian-Regular.ttf"),
    );
    add(
        &mut fonts,
        "NotoSansArabic",
        include_bytes!("fonts/NotoSansArabic-Regular.ttf"),
    );

    // Proportional: Noto Sans leads, the script subfamilies follow as fallbacks,
    // and egui's originals (including the emoji font) remain last. The first
    // font in the list that has a glyph wins.
    if let Some(prop) = fonts.families.get_mut(&egui::FontFamily::Proportional) {
        prop.insert(0, "NotoSans".to_owned());
        for (offset, name) in SCRIPT_FALLBACKS.iter().enumerate() {
            prop.insert(offset + 1, (*name).to_owned());
        }
    }

    // Monospace: keep egui's monospace face primary so code/technical text stays
    // fixed-width; append the script fallbacks only so non-Latin still renders
    // (proportionally) rather than as tofu.
    if let Some(mono) = fonts.families.get_mut(&egui::FontFamily::Monospace) {
        for name in SCRIPT_FALLBACKS {
            mono.push((*name).to_owned());
        }
    }

    ctx.set_fonts(fonts);
}

fn add(fonts: &mut egui::FontDefinitions, name: &str, bytes: &'static [u8]) {
    fonts.font_data.insert(
        name.to_owned(),
        Arc::new(egui::FontData::from_static(bytes)),
    );
}

#[cfg(test)]
mod tests {
    use ab_glyph::{Font, FontRef};

    /// Assert a font maps a character to a real glyph (glyph id 0 is `.notdef`,
    /// i.e. a missing-glyph box). Uses ab_glyph, the same rasterizer egui does.
    fn assert_covers(bytes: &[u8], ch: char) {
        let font = FontRef::try_from_slice(bytes).expect("bundled font is a valid TTF");
        assert_ne!(
            font.glyph_id(ch).0,
            0,
            "font is missing a glyph for '{ch}' (U+{:04X})",
            ch as u32
        );
    }

    #[test]
    fn base_font_covers_latin_cyrillic_and_turkish() {
        let bytes = include_bytes!("fonts/NotoSans-Regular.ttf");
        assert_covers(bytes, 'A');
        assert_covers(bytes, 'Р'); // Cyrillic (Russian)
        assert_covers(bytes, 'ş'); // Turkish
    }

    #[test]
    fn armenian_font_covers_armenian() {
        assert_covers(include_bytes!("fonts/NotoSansArmenian-Regular.ttf"), 'Հ');
    }

    #[test]
    fn georgian_font_covers_georgian() {
        assert_covers(include_bytes!("fonts/NotoSansGeorgian-Regular.ttf"), 'ქ');
    }

    #[test]
    fn arabic_font_covers_persian() {
        assert_covers(include_bytes!("fonts/NotoSansArabic-Regular.ttf"), 'ف');
    }
}
