//! Font registry and text measurement for PDF signature appearances.
//!
//! A [`Font`] bundles the subset-font metrics (glyph coverage, advance widths,
//! the PDF `/W` array and ToUnicode CMap) with the embedded TTF program and the
//! text operations the appearance layer needs: measure width, wrap lines, and
//! encode text as Identity-H hex glyph IDs.
//!
//! Fonts are fully static -- no lazy loading or caching -- so the registry
//! hands out `&'static Font` references, bundling the metrics and the TTF into
//! one type with methods.

use std::fmt;

use crate::appearance::font_data;
use crate::{Result, RevenantError};

/// A subset font: static metrics plus the embedded TTF program.
///
/// Instances are `static`s in the generated `font_data` modules; construct new
/// ones only via the font-preparation pipeline, never by hand.
pub struct Font {
    /// PDF `BaseFont` name, e.g. `"NotoSans"`.
    pub name: &'static str,
    /// Font design units per em (the width denominator).
    pub units_per_em: u32,
    pub ascent: i32,
    pub descent: i32,
    pub cap_height: i32,
    /// FontBBox `(x_min, y_min, x_max, y_max)`.
    pub bbox: (i32, i32, i32, i32),
    pub stem_v: i32,
    pub italic_angle: i32,
    /// Advance width for glyphs absent from [`Font::widths`] (the `/DW` value).
    pub default_width: u32,
    /// Unicode codepoint -> glyph ID, sorted by codepoint.
    pub cmap: &'static [(u32, u16)],
    /// Glyph ID -> advance width (font units), sorted by glyph ID.
    pub widths: &'static [(u16, u16)],
    /// The PDF `/W` array string for the CIDFontType2 dictionary.
    pub cid_widths_str: &'static str,
    /// The ToUnicode CMap stream contents.
    pub tounicode_cmap: &'static str,
    /// The embedded subset TTF (the FontFile2 program).
    pub ttf: &'static [u8],
}

impl fmt::Debug for Font {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never dump the multi-KB glyph tables or TTF program.
        f.debug_struct("Font")
            .field("name", &self.name)
            .field("units_per_em", &self.units_per_em)
            .field("glyphs", &self.cmap.len())
            .field("ttf_bytes", &self.ttf.len())
            .finish_non_exhaustive()
    }
}

impl Font {
    /// The glyph ID for a Unicode codepoint, if the font's cmap covers it.
    #[must_use]
    pub fn glyph_id(&self, codepoint: u32) -> Option<u16> {
        self.cmap
            .binary_search_by_key(&codepoint, |&(cp, _)| cp)
            .ok()
            .map(|i| self.cmap[i].1)
    }

    /// The advance width (in font units) of a glyph, or [`Font::default_width`].
    #[must_use]
    pub fn advance(&self, glyph_id: u16) -> u32 {
        match self.widths.binary_search_by_key(&glyph_id, |&(g, _)| g) {
            Ok(i) => u32::from(self.widths[i].1),
            Err(_) => self.default_width,
        }
    }

    /// Measure text width in PDF points at a given font size.
    ///
    /// Characters absent from the cmap fall back to glyph 0; the per-glyph
    /// advances are summed as exact integers, then scaled once, so the result
    /// is exact.
    #[must_use]
    pub fn text_width(&self, text: &str, font_size: f64) -> f64 {
        let mut total = 0.0f64;
        for ch in text.chars() {
            let gid = self.glyph_id(u32::from(ch)).unwrap_or(0);
            // Advances are < 2^16 and the sum of a signature line is well below
            // 2^53, so this f64 accumulation is exact.
            total += f64::from(self.advance(gid));
        }
        total * font_size / f64::from(self.units_per_em)
    }

    /// Encode text as concatenated 4-hex-digit glyph IDs for an Identity-H
    /// Type0 font. Characters absent from the cmap use the `?` glyph, so no
    /// invisible `.notdef` glyphs reach the rendered PDF.
    #[must_use]
    pub fn encode_text_hex(&self, text: &str) -> String {
        use std::fmt::Write as _;

        let question = self.glyph_id(u32::from('?')).unwrap_or(0);
        let mut out = String::with_capacity(text.len() * 4);
        for ch in text.chars() {
            let gid = self.glyph_id(u32::from(ch)).unwrap_or(question);
            let _ = write!(out, "{gid:04X}");
        }
        out
    }

    /// Format text as a PDF hex string (`<...>`) ready for the `Tj` operator.
    #[must_use]
    pub fn pdf_escape(&self, text: &str) -> String {
        format!("<{}>", self.encode_text_hex(text))
    }

    /// Word-wrap text to a maximum line width, measuring with this font.
    ///
    /// Splits on whitespace (collapsing runs) and greedily fills lines; a single
    /// word wider than `max_width` still occupies its own line.
    #[must_use]
    pub fn wrap_lines(&self, text: &str, font_size: f64, max_width: f64) -> Vec<String> {
        let mut lines = Vec::new();
        let mut current = String::new();
        for word in text.split_whitespace() {
            let candidate = if current.is_empty() {
                word.to_owned()
            } else {
                format!("{current} {word}")
            };
            if self.text_width(&candidate, font_size) <= max_width {
                current = candidate;
            } else {
                if !current.is_empty() {
                    lines.push(std::mem::take(&mut current));
                }
                word.clone_into(&mut current);
            }
        }
        if !current.is_empty() {
            lines.push(current);
        }
        lines
    }
}

// ── Registry ────────────────────────────────────────────────────────────

/// Font registry keys, in preference order.
pub const AVAILABLE_FONTS: [&str; 3] = ["noto-sans", "ghea-mariam", "ghea-grapalat"];

/// The default font key.
pub const DEFAULT_FONT: &str = "noto-sans";

/// Look up a font by registry key, or the default when `name` is `None`.
///
/// # Errors
///
/// Returns [`RevenantError::Pdf`] if the key is not a known font.
pub fn get_font(name: Option<&str>) -> Result<&'static Font> {
    let key = name.unwrap_or(DEFAULT_FONT);
    match key {
        "noto-sans" => Ok(&font_data::noto_sans::FONT),
        "ghea-mariam" => Ok(&font_data::ghea_mariam::FONT),
        "ghea-grapalat" => Ok(&font_data::ghea_grapalat::FONT),
        _ => Err(RevenantError::Pdf(format!(
            "Unknown font {key:?}. Available: {}",
            AVAILABLE_FONTS.join(", ")
        ))),
    }
}

/// The default font (`noto-sans`).
#[must_use]
pub fn get_default_font() -> &'static Font {
    &font_data::noto_sans::FONT
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_resolves_and_defaults() {
        assert_eq!(get_font(None).unwrap().name, "NotoSans");
        assert_eq!(get_font(Some("noto-sans")).unwrap().name, "NotoSans");
        assert_eq!(get_font(Some("ghea-mariam")).unwrap().name, "GHEAMariam");
        assert_eq!(
            get_font(Some("ghea-grapalat")).unwrap().name,
            "GHEAGrapalat"
        );
        assert_eq!(get_default_font().name, "NotoSans");
    }

    #[test]
    fn rejects_unknown_font() {
        let err = get_font(Some("comic-sans")).unwrap_err();
        assert!(err.to_string().contains("Unknown font"), "{err}");
        assert!(err.to_string().contains("noto-sans"), "{err}");
    }

    #[test]
    fn cmap_and_widths_are_sorted() {
        for key in AVAILABLE_FONTS {
            let font = get_font(Some(key)).unwrap();
            assert!(
                font.cmap.windows(2).all(|w| w[0].0 < w[1].0),
                "{key} cmap not sorted"
            );
            assert!(
                font.widths.windows(2).all(|w| w[0].0 < w[1].0),
                "{key} widths not sorted"
            );
        }
    }

    #[test]
    fn glyph_lookup_matches_generated_cmap() {
        let font = get_default_font();
        // NotoSans cmap maps 'A' (65) -> glyph 34 (0x22).
        assert_eq!(font.glyph_id(u32::from('A')), Some(34));
        assert_eq!(font.encode_text_hex("A"), "0022");
        assert_eq!(font.pdf_escape("A"), "<0022>");
    }

    #[test]
    fn unknown_glyph_encodes_as_question() {
        let font = get_default_font();
        let question_gid = font.glyph_id(u32::from('?')).unwrap();
        // U+1F600 (emoji) is outside the subset -> encodes as the '?' glyph.
        let encoded = font.encode_text_hex("\u{1F600}");
        assert_eq!(encoded, format!("{question_gid:04X}"));
    }

    #[test]
    fn text_width_is_additive_and_scales() {
        let font = get_default_font();
        assert!(font.text_width("", 10.0).abs() < 1e-12);
        let a = font.text_width("A", 10.0);
        let b = font.text_width("B", 10.0);
        let ab = font.text_width("AB", 10.0);
        assert!((ab - (a + b)).abs() < 1e-9);
        // Linear in font size.
        assert!(
            (font.text_width("Signature", 20.0) - 2.0 * font.text_width("Signature", 10.0)).abs()
                < 1e-9
        );
    }

    #[test]
    fn measurements_match_python_reference() {
        // Reference values from the Python client (source of truth), proving the
        // embedded metrics and measurement arithmetic are byte-faithful.
        let noto = get_font(Some("noto-sans")).unwrap();
        assert!((noto.text_width("Signature", 12.0) - 54.684).abs() < 1e-9);
        assert!((noto.text_width("Test 2026 UTC+4", 10.0) - 78.31).abs() < 1e-9);
        assert_eq!(noto.pdf_escape("Sig"), "<0034004A0048>");

        let ghea = get_font(Some("ghea-mariam")).unwrap();
        assert!((ghea.text_width("Ստորագրություն", 10.0) - 78.99).abs() < 1e-9);
        assert_eq!(ghea.pdf_escape("Ա"), "<00C0>");
    }

    #[test]
    fn wrap_lines_greedy() {
        let font = get_default_font();
        // A generous width keeps everything on one line.
        assert_eq!(
            font.wrap_lines("one two three", 10.0, 1000.0),
            vec!["one two three"]
        );
        // A tiny width forces one word per line.
        let narrow = font.wrap_lines("one two three", 10.0, 1.0);
        assert_eq!(narrow, vec!["one", "two", "three"]);
        // Whitespace runs collapse.
        assert_eq!(font.wrap_lines("  a   b  ", 10.0, 1000.0), vec!["a b"]);
    }
}
