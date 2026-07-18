//! Visual appearance content stream for PDF signature fields.
//!
//! Generates the `/AP /N` content stream that Adobe Acrobat and other readers
//! render inside the signature widget: a translucent backdrop, a border, an
//! optional image column on the left, and a stacked text block (a large name
//! line followed by smaller gray detail lines).
//!
//! These bytes lie inside the signed byte range, so they must form a valid
//! content stream, but their exact layout is not otherwise constrained.

use crate::appearance::fonts::Font;

mod ops;

// ── Layout constants ────────────────────────────────────────────────────

/// Horizontal content padding from the border inward (~2.8 mm).
const PAD_H: f64 = 8.0;
/// Vertical content padding (~1.4 mm).
const PAD_V: f64 = 4.0;

/// Fraction of content width the image column occupies when an image is present.
const IMAGE_COLUMN_RATIO: f64 = 0.40;
/// Gap between the image column and the text column.
const COLUMN_GAP: f64 = 4.0;

// Name line (fields[0]) font sizing.
const NAME_MAX_FONT_SIZE: f64 = 14.0;
const NAME_MIN_FONT_SIZE: f64 = 5.0;
const NAME_FONT_STEP: f64 = 0.5;

// Detail line (fields[1:]) font sizing.
const DETAIL_MAX_FONT_SIZE: f64 = 8.0;
const DETAIL_MIN_FONT_SIZE: f64 = 4.0;
const DETAIL_FONT_STEP: f64 = 0.5;
const DETAIL_HEIGHT_DIVISOR: f64 = 7.5;
/// Detail text gray level.
const DETAIL_COLOR: f64 = 0.35;

/// Vertical gap between name and details, as a fraction of the name font size.
const NAME_DETAIL_GAP_RATIO: f64 = 1.0;
/// The name font takes at most this fraction of content height.
const NAME_HEIGHT_DIVISOR: f64 = 3.0;
/// Small horizontal margin added to the widest measured text.
const TEXT_WIDTH_MARGIN: f64 = 4.0;
/// Line-spacing multiplier.
const LINE_LEADING: f64 = 1.4;

// Border styling.
const BORDER_COLOR: f64 = 0.70;
const BORDER_WIDTH: f64 = 0.75;

// Near-opaque light-gray backdrop so the signature reads over page content.
const BG_OPACITY: f64 = 0.90;
const BG_COLOR: f64 = 0.97;

// Adaptive size bounds (used by the optimal-size helpers).
const MIN_SIG_WIDTH: f64 = 150.0;
const MAX_SIG_WIDTH: f64 = 300.0;
const MIN_SIG_HEIGHT: f64 = 40.0;
const MAX_SIG_HEIGHT: f64 = 120.0;

/// Font resources referenced by an appearance stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FontResources {
    /// Resource name in the form's `/Font` dictionary (e.g. `"F1"`).
    pub font_name: String,
    /// PDF BaseFont name (e.g. `"NotoSans"`).
    pub base_font: String,
}

/// The result of building an appearance stream.
#[derive(Debug, Clone, PartialEq)]
pub struct AppearanceData {
    /// The raw content stream for `/AP /N`.
    pub stream: Vec<u8>,
    /// The form XObject BBox `(x0, y0, x1, y1)`.
    pub bbox: (f64, f64, f64, f64),
    /// The font resources the stream requires.
    pub resources: FontResources,
    /// Whether the stream references the `/Img1` image XObject.
    pub needs_image: bool,
    /// The ExtGState `/ca` value for the backdrop (0 disables it).
    pub bg_opacity: f64,
}

/// Convert a small count to `f64` exactly, without a precision-loss cast.
fn count_f64(n: usize) -> f64 {
    f64::from(u32::try_from(n).unwrap_or(u32::MAX))
}

// ── Optimal size helpers ────────────────────────────────────────────────

/// Compute an optimal field width so the first field fits on one line.
///
/// Clamped to `[MIN_SIG_WIDTH, MAX_SIG_WIDTH]`.
#[must_use]
pub fn compute_optimal_width(fields: &[String], height: f64, has_image: bool, font: &Font) -> f64 {
    if fields.is_empty() {
        return MIN_SIG_WIDTH;
    }

    let content_h = height - 2.0 * PAD_V;
    let name_font = NAME_MAX_FONT_SIZE.min(content_h / NAME_HEIGHT_DIVISOR);
    let detail_font = DETAIL_MAX_FONT_SIZE.min(content_h / DETAIL_HEIGHT_DIVISOR);

    let mut widest = font.text_width(&fields[0], name_font);
    for field in &fields[1..] {
        widest = widest.max(font.text_width(field, detail_font));
    }
    let text_w = widest + TEXT_WIDTH_MARGIN;

    let content_w = if has_image {
        (text_w + COLUMN_GAP) / (1.0 - IMAGE_COLUMN_RATIO)
    } else {
        text_w
    };
    let total_w = content_w + 2.0 * PAD_H;
    MIN_SIG_WIDTH.max(MAX_SIG_WIDTH.min(total_w))
}

/// Compute an optimal field height to fit all fields without cramming.
///
/// Clamped to `[MIN_SIG_HEIGHT, MAX_SIG_HEIGHT]`.
#[must_use]
pub fn compute_optimal_height(fields: &[String], width: f64, has_image: bool, font: &Font) -> f64 {
    if fields.is_empty() {
        return MIN_SIG_HEIGHT;
    }

    let content_w = width - 2.0 * PAD_H;
    let text_w = if has_image {
        let img_w = content_w * IMAGE_COLUMN_RATIO;
        content_w - img_w - COLUMN_GAP
    } else {
        content_w
    };

    let name_font = NAME_MAX_FONT_SIZE;
    let detail_font = DETAIL_MAX_FONT_SIZE;

    let name_text = &fields[0];
    let detail_texts = &fields[1..];

    let name_lines = font.wrap_lines(name_text, name_font, text_w);
    let name_leading = name_font * LINE_LEADING;
    let detail_leading = detail_font * LINE_LEADING;
    let total_detail_lines: usize = detail_texts
        .iter()
        .map(|d| font.wrap_lines(d, detail_font, text_w).len())
        .sum();

    let name_section_h = count_f64(name_lines.len()) * name_leading;
    let name_detail_gap = if detail_texts.is_empty() {
        0.0
    } else {
        name_font * NAME_DETAIL_GAP_RATIO
    };
    let detail_section_h = count_f64(total_detail_lines) * detail_leading;

    let content_h = name_section_h + name_detail_gap + detail_section_h;
    let total_h = content_h + 2.0 * PAD_V;
    MIN_SIG_HEIGHT.max(MAX_SIG_HEIGHT.min(total_h))
}

// ── Appearance stream builder ───────────────────────────────────────────

/// The current name/detail font sizes and their line leadings, shrunk in place
/// as the layout is fitted.
#[derive(Debug, Clone, Copy)]
struct Sizing {
    name_font: f64,
    name_leading: f64,
    detail_font: f64,
    detail_leading: f64,
}

impl Sizing {
    fn new(content_h: f64) -> Self {
        let name_font = NAME_MAX_FONT_SIZE.min(content_h / NAME_HEIGHT_DIVISOR);
        let detail_font = DETAIL_MAX_FONT_SIZE.min(content_h / DETAIL_HEIGHT_DIVISOR);
        Self {
            name_font,
            name_leading: name_font * LINE_LEADING,
            detail_font,
            detail_leading: detail_font * LINE_LEADING,
        }
    }
}

/// Total text-block height for the current name/detail font sizes.
fn total_height(
    font: &Font,
    name_lines_count: usize,
    s: &Sizing,
    detail_texts: &[String],
    text_w: f64,
) -> f64 {
    let n_detail: usize = detail_texts
        .iter()
        .map(|d| font.wrap_lines(d, s.detail_font, text_w).len())
        .sum();
    let name_h = count_f64(name_lines_count) * s.name_leading;
    let detail_h = count_f64(n_detail) * s.detail_leading;
    let gap = if detail_texts.is_empty() {
        0.0
    } else {
        s.name_font * NAME_DETAIL_GAP_RATIO
    };
    name_h + gap + detail_h
}

/// Build a PDF appearance stream (`/AP /N`) for a signature field.
///
/// `fields[0]` is the large black name line; `fields[1..]` are smaller gray
/// detail lines. When `has_image` is set, an image column is drawn on the left
/// and the stream references `/Img1`; `image_aspect` (width/height) keeps it
/// aspect-correct.
#[must_use]
pub fn build_appearance_stream(
    width: f64,
    height: f64,
    fields: &[String],
    has_image: bool,
    font: &Font,
    image_aspect: Option<f64>,
) -> AppearanceData {
    let bw = BORDER_WIDTH;
    let half_bw = bw / 2.0;

    let content_x = PAD_H;
    let content_y = PAD_V;
    let content_w = width - 2.0 * PAD_H;
    let content_h = height - 2.0 * PAD_V;

    // Text area: full width, or the right portion when an image is present.
    let (img_w, text_x, text_w) = if has_image {
        let img_w = content_w * IMAGE_COLUMN_RATIO;
        (
            img_w,
            content_x + img_w + COLUMN_GAP,
            content_w - img_w - COLUMN_GAP,
        )
    } else {
        (0.0, content_x, content_w)
    };

    // Font sizing (shrunk in place to fit).
    let mut sizing = Sizing::new(content_h);

    let name_text = fields.first().map_or("", String::as_str);
    let detail_texts: &[String] = if fields.len() > 1 { &fields[1..] } else { &[] };

    let mut name_lines = if name_text.is_empty() {
        Vec::new()
    } else {
        font.wrap_lines(name_text, sizing.name_font, text_w)
    };

    // Phase 1: shrink the name font until the block fits (or hits the floor).
    while sizing.name_font > NAME_MIN_FONT_SIZE && !name_lines.is_empty() {
        if total_height(font, name_lines.len(), &sizing, detail_texts, text_w) <= content_h {
            break;
        }
        sizing.name_font -= NAME_FONT_STEP;
        name_lines = font.wrap_lines(name_text, sizing.name_font, text_w);
        sizing.name_leading = sizing.name_font * LINE_LEADING;
    }

    // Phase 2: shrink the detail font if the name is already at its floor.
    while sizing.detail_font > DETAIL_MIN_FONT_SIZE && !detail_texts.is_empty() {
        if total_height(font, name_lines.len(), &sizing, detail_texts, text_w) <= content_h {
            break;
        }
        sizing.detail_font -= DETAIL_FONT_STEP;
        sizing.detail_leading = sizing.detail_font * LINE_LEADING;
    }

    if total_height(font, name_lines.len(), &sizing, detail_texts, text_w) > content_h {
        log::warn!(
            "Signature text exceeds field height at minimum font sizes \
             (name={:.1}, detail={:.1}); content will be clipped.",
            sizing.name_font,
            sizing.detail_font
        );
    }

    // Vertical centering: span from the top of the first glyph to the last
    // baseline.
    let total_detail_lines: usize = detail_texts
        .iter()
        .map(|d| font.wrap_lines(d, sizing.detail_font, text_w).len())
        .sum();
    let name_detail_gap = if detail_texts.is_empty() {
        0.0
    } else {
        sizing.name_font * NAME_DETAIL_GAP_RATIO
    };
    let mut text_span =
        sizing.name_font + count_f64(name_lines.len().saturating_sub(1)) * sizing.name_leading;
    if total_detail_lines > 0 {
        text_span += name_detail_gap + count_f64(total_detail_lines - 1) * sizing.detail_leading;
    }
    let v_offset = ((content_h - text_span) / 2.0).max(0.0);

    let stream = ops::render_ops(
        font,
        &RenderParams {
            width,
            height,
            content_x,
            content_y,
            content_h,
            img_w,
            text_x,
            text_w,
            bw,
            half_bw,
            name_font: sizing.name_font,
            name_leading: sizing.name_leading,
            detail_font: sizing.detail_font,
            detail_leading: sizing.detail_leading,
            v_offset,
            has_image,
            image_aspect,
        },
        &name_lines,
        detail_texts,
    );

    AppearanceData {
        stream,
        bbox: (0.0, 0.0, width, height),
        resources: FontResources {
            font_name: "F1".to_owned(),
            base_font: font.name.to_owned(),
        },
        needs_image: has_image,
        bg_opacity: BG_OPACITY,
    }
}

/// Geometry and font sizes needed to emit the content-stream operators.
///
/// Fields are read by the sibling [`ops`] child module (which can see this
/// parent module's private items).
struct RenderParams {
    width: f64,
    height: f64,
    content_x: f64,
    content_y: f64,
    content_h: f64,
    img_w: f64,
    text_x: f64,
    text_w: f64,
    bw: f64,
    half_bw: f64,
    name_font: f64,
    name_leading: f64,
    detail_font: f64,
    detail_leading: f64,
    v_offset: f64,
    has_image: bool,
    image_aspect: Option<f64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::appearance::get_default_font;

    fn fields(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn stream_has_required_operators() {
        let font = get_default_font();
        let ap = build_appearance_stream(
            210.0,
            70.0,
            &fields(&["John Doe", "Date: 7 Feb 2026"]),
            false,
            font,
            None,
        );
        let s = String::from_utf8(ap.stream.clone()).unwrap();
        // Backdrop, border, text block, font selection, and hex-encoded text.
        assert!(s.contains("/GS1 gs"), "{s}");
        assert!(s.contains(" re"), "{s}");
        assert!(s.contains("BT"), "{s}");
        assert!(s.contains("ET"), "{s}");
        assert!(s.contains("/F1 "), "{s}");
        assert!(s.contains(" Tj"), "{s}");
        assert!(!ap.needs_image);
        assert_eq!(ap.resources.font_name, "F1");
        assert_eq!(ap.resources.base_font, "NotoSans");
        assert!((ap.bg_opacity - 0.90).abs() < 1e-9);
    }

    #[test]
    fn image_stream_references_img1() {
        let font = get_default_font();
        let ap = build_appearance_stream(210.0, 70.0, &fields(&["Jane"]), true, font, Some(2.0));
        let s = String::from_utf8(ap.stream.clone()).unwrap();
        assert!(ap.needs_image);
        assert!(s.contains("/Img1 Do"), "{s}");
        assert!(s.contains(" cm"), "{s}");
    }

    #[test]
    fn empty_fields_still_valid_stream() {
        let font = get_default_font();
        let ap = build_appearance_stream(210.0, 70.0, &[], false, font, None);
        let s = String::from_utf8(ap.stream).unwrap();
        assert!(s.contains("BT"));
        assert!(s.contains("ET"));
    }

    #[test]
    fn optimal_size_within_bounds() {
        let font = get_default_font();
        let w = compute_optimal_width(&fields(&["A name", "detail"]), 70.0, false, font);
        assert!((MIN_SIG_WIDTH..=MAX_SIG_WIDTH).contains(&w), "w={w}");
        let h = compute_optimal_height(&fields(&["A name", "detail"]), 210.0, false, font);
        assert!((MIN_SIG_HEIGHT..=MAX_SIG_HEIGHT).contains(&h), "h={h}");
    }

    #[test]
    fn optimal_size_empty_fields() {
        let font = get_default_font();
        assert!((compute_optimal_width(&[], 70.0, false, font) - MIN_SIG_WIDTH).abs() < 1e-9);
        assert!((compute_optimal_height(&[], 210.0, false, font) - MIN_SIG_HEIGHT).abs() < 1e-9);
    }
}
