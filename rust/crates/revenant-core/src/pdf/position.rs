//! Signature field positioning and page selection.
//!
//! Pure geometry: where to place the signature rectangle on a page given a
//! preset (`bottom-right`, `br`, ...) or explicit coordinates, and how to
//! resolve a user-facing page specifier (`first`, `last`, or a 1-based number)
//! to a concrete 0-based index. Reading actual page dimensions from a PDF lives
//! in [`super::reader`]; this module never touches a document.

use std::str::FromStr;

use crate::{Result, RevenantError};

// ── Signature field size defaults (PDF points) ──────────────────────────

/// Default signature field width (3:1 aspect, ~75 mm).
pub const SIG_WIDTH: f64 = 210.0;
/// Default signature field height (~25 mm).
pub const SIG_HEIGHT: f64 = 70.0;
/// Horizontal margin from the left/right page edge (~13 mm).
pub const SIG_MARGIN_H: f64 = 36.0;
/// Vertical margin from the top/bottom page edge (~21 mm).
pub const SIG_MARGIN_V: f64 = 60.0;

/// A signature placement preset, decomposed into an anchor corner/edge.
///
/// An exhaustive enum rather than free-form strings, so the geometry in
/// [`compute_sig_rect`] can never be reached with an unrecognized position name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Position {
    BottomRight,
    TopRight,
    BottomLeft,
    TopLeft,
    BottomCenter,
}

#[derive(Debug, Clone, Copy)]
enum Horizontal {
    Right,
    Left,
    Center,
}

#[derive(Debug, Clone, Copy)]
enum Vertical {
    Bottom,
    Top,
}

impl Position {
    fn horizontal(self) -> Horizontal {
        match self {
            Position::BottomRight | Position::TopRight => Horizontal::Right,
            Position::BottomLeft | Position::TopLeft => Horizontal::Left,
            Position::BottomCenter => Horizontal::Center,
        }
    }

    fn vertical(self) -> Vertical {
        match self {
            Position::BottomRight | Position::BottomLeft | Position::BottomCenter => {
                Vertical::Bottom
            }
            Position::TopRight | Position::TopLeft => Vertical::Top,
        }
    }

    /// The canonical preset name (e.g. `"bottom-right"`).
    #[must_use]
    pub fn canonical_name(self) -> &'static str {
        match self {
            Position::BottomRight => "bottom-right",
            Position::TopRight => "top-right",
            Position::BottomLeft => "bottom-left",
            Position::TopLeft => "top-left",
            Position::BottomCenter => "bottom-center",
        }
    }
}

/// Full preset names, sorted for stable error messages.
const PRESET_NAMES: [&str; 5] = [
    "bottom-center",
    "bottom-left",
    "bottom-right",
    "top-left",
    "top-right",
];

/// Short aliases -> canonical name, sorted by alias.
const ALIASES: [(&str, Position); 5] = [
    ("bc", Position::BottomCenter),
    ("bl", Position::BottomLeft),
    ("br", Position::BottomRight),
    ("tl", Position::TopLeft),
    ("tr", Position::TopRight),
];

impl FromStr for Position {
    type Err = RevenantError;

    /// Parse a placement preset from its canonical name (`bottom-right`, ...) or
    /// short alias (`br`, `tr`, `bl`, `tl`, `bc`), case-insensitively with
    /// surrounding whitespace trimmed.
    ///
    /// # Errors
    ///
    /// Returns [`RevenantError::Pdf`] for an unrecognized position.
    fn from_str(s: &str) -> Result<Self> {
        let name = s.trim().to_lowercase();

        if let Some((_, pos)) = ALIASES.iter().find(|(alias, _)| *alias == name) {
            return Ok(*pos);
        }
        match name.as_str() {
            "bottom-right" => Ok(Position::BottomRight),
            "top-right" => Ok(Position::TopRight),
            "bottom-left" => Ok(Position::BottomLeft),
            "top-left" => Ok(Position::TopLeft),
            "bottom-center" => Ok(Position::BottomCenter),
            _ => {
                let aliases: Vec<&str> = ALIASES.iter().map(|(a, _)| *a).collect();
                let valid = [PRESET_NAMES.as_slice(), aliases.as_slice()]
                    .concat()
                    .join(", ");
                Err(RevenantError::Pdf(format!(
                    "Unknown position {s:?}. Valid: {valid}"
                )))
            }
        }
    }
}

// ── Page specifier ──────────────────────────────────────────────────────

/// A user-facing page selection: an edge keyword or a concrete 0-based index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageSpec {
    First,
    Last,
    /// 0-based page index.
    Index(usize),
}

impl FromStr for PageSpec {
    type Err = RevenantError;

    /// Parse a page specifier: `first`, `last`, or a 1-based page number
    /// (converted to a 0-based index), case-insensitively with surrounding
    /// whitespace trimmed.
    ///
    /// # Errors
    ///
    /// Returns [`RevenantError::Pdf`] if the specifier is not a keyword or a
    /// positive integer.
    fn from_str(s: &str) -> Result<Self> {
        let spec = s.trim().to_lowercase();
        if spec == "first" {
            return Ok(PageSpec::First);
        }
        if spec == "last" {
            return Ok(PageSpec::Last);
        }
        let page_num: i64 = spec.parse().map_err(|_| {
            RevenantError::Pdf(format!(
                "Invalid page: {s:?}. Use 'first', 'last', or a page number."
            ))
        })?;
        if page_num < 1 {
            return Err(RevenantError::Pdf(format!(
                "Page number must be 1 or greater, got {page_num}"
            )));
        }
        // 1-based -> 0-based; page_num >= 1 so the subtraction is non-negative.
        let idx = usize::try_from(page_num - 1)
            .map_err(|_| RevenantError::Pdf(format!("Page number too large: {page_num}")))?;
        Ok(PageSpec::Index(idx))
    }
}

/// Resolve a [`PageSpec`] to a concrete 0-based index against a page count.
///
/// # Errors
///
/// Returns [`RevenantError::Pdf`] if the resulting index is out of range, or if
/// the document reports zero pages.
pub fn resolve_page_index(spec: PageSpec, total_pages: usize) -> Result<usize> {
    if total_pages == 0 {
        return Err(RevenantError::Pdf("PDF has no pages.".to_owned()));
    }
    let idx = match spec {
        PageSpec::First => 0,
        PageSpec::Last => total_pages - 1,
        PageSpec::Index(i) => i,
    };
    if idx >= total_pages {
        return Err(RevenantError::Pdf(format!(
            "Page {idx} out of range (PDF has {total_pages} page(s), 0-based)."
        )));
    }
    Ok(idx)
}

// ── Rectangle computation ───────────────────────────────────────────────

/// A signature rectangle in PDF coordinate space (origin = bottom-left).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SigRect {
    pub x: f64,
    pub y: f64,
    pub w: f64,
    pub h: f64,
}

/// Compute the signature rectangle for a page, given its dimensions and a preset.
///
/// # Errors
///
/// Returns [`RevenantError::Pdf`] if the page or signature dimensions are
/// non-positive, or if the signature does not fit on the page (negative
/// computed origin).
pub fn compute_sig_rect(
    page_width: f64,
    page_height: f64,
    position: Position,
    sig_w: f64,
    sig_h: f64,
    margin_h: f64,
    margin_v: f64,
) -> Result<SigRect> {
    if page_width <= 0.0 || page_height <= 0.0 {
        return Err(RevenantError::Pdf(format!(
            "Invalid page dimensions: {page_width:.1} x {page_height:.1} pt"
        )));
    }
    if sig_w <= 0.0 || sig_h <= 0.0 {
        return Err(RevenantError::Pdf(format!(
            "Invalid signature dimensions: {sig_w:.1} x {sig_h:.1} pt"
        )));
    }

    let x = match position.horizontal() {
        Horizontal::Right => page_width - margin_h - sig_w,
        Horizontal::Left => margin_h,
        Horizontal::Center => (page_width - sig_w) / 2.0,
    };
    let y = match position.vertical() {
        Vertical::Bottom => margin_v,
        Vertical::Top => page_height - margin_v - sig_h,
    };

    if x < 0.0 || y < 0.0 {
        return Err(RevenantError::Pdf(format!(
            "Signature does not fit on page: computed position ({x:.1}, {y:.1}) is negative. \
             Page: {page_width:.0}x{page_height:.0} pt, \
             signature: {sig_w:.0}x{sig_h:.0} pt, \
             margins: {margin_h:.0}x{margin_v:.0} pt"
        )));
    }

    Ok(SigRect {
        x,
        y,
        w: sig_w,
        h: sig_h,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_aliases_and_full_names() {
        assert_eq!("br".parse::<Position>().unwrap(), Position::BottomRight);
        assert_eq!("  BR ".parse::<Position>().unwrap(), Position::BottomRight);
        assert_eq!(
            "bottom-right".parse::<Position>().unwrap(),
            Position::BottomRight
        );
        assert_eq!("TL".parse::<Position>().unwrap(), Position::TopLeft);
        assert_eq!(
            "bottom-center".parse::<Position>().unwrap(),
            Position::BottomCenter
        );
    }

    #[test]
    fn rejects_unknown_position() {
        let err = "middle".parse::<Position>().unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("Unknown position"), "{msg}");
        assert!(msg.contains("bottom-right"), "{msg}");
        assert!(msg.contains("br"), "{msg}");
    }

    #[test]
    fn bottom_right_rectangle() {
        // A4-ish page 595x842.
        let r = compute_sig_rect(
            595.0,
            842.0,
            Position::BottomRight,
            SIG_WIDTH,
            SIG_HEIGHT,
            SIG_MARGIN_H,
            SIG_MARGIN_V,
        )
        .unwrap();
        assert!((r.x - (595.0 - 36.0 - 210.0)).abs() < 1e-9);
        assert!((r.y - 60.0).abs() < 1e-9);
        assert!((r.w - SIG_WIDTH).abs() < 1e-9);
        assert!((r.h - SIG_HEIGHT).abs() < 1e-9);
    }

    #[test]
    fn top_left_rectangle() {
        let r = compute_sig_rect(
            595.0,
            842.0,
            Position::TopLeft,
            SIG_WIDTH,
            SIG_HEIGHT,
            SIG_MARGIN_H,
            SIG_MARGIN_V,
        )
        .unwrap();
        assert!((r.x - 36.0).abs() < 1e-9);
        assert!((r.y - (842.0 - 60.0 - 70.0)).abs() < 1e-9);
    }

    #[test]
    fn center_is_horizontally_centered() {
        let r = compute_sig_rect(
            600.0,
            800.0,
            Position::BottomCenter,
            200.0,
            70.0,
            36.0,
            60.0,
        )
        .unwrap();
        assert!((r.x - 200.0).abs() < 1e-9); // (600 - 200) / 2
    }

    #[test]
    fn rejects_signature_larger_than_page() {
        let err = compute_sig_rect(
            100.0,
            100.0,
            Position::BottomRight,
            SIG_WIDTH,
            SIG_HEIGHT,
            SIG_MARGIN_H,
            SIG_MARGIN_V,
        )
        .unwrap_err();
        assert!(err.to_string().contains("does not fit"), "{err}");
    }

    #[test]
    fn rejects_invalid_page_dimensions() {
        let err = compute_sig_rect(
            0.0,
            800.0,
            Position::BottomRight,
            SIG_WIDTH,
            SIG_HEIGHT,
            SIG_MARGIN_H,
            SIG_MARGIN_V,
        )
        .unwrap_err();
        assert!(err.to_string().contains("Invalid page dimensions"), "{err}");
    }

    #[test]
    fn parses_page_specs() {
        assert_eq!("first".parse::<PageSpec>().unwrap(), PageSpec::First);
        assert_eq!(" LAST ".parse::<PageSpec>().unwrap(), PageSpec::Last);
        assert_eq!("1".parse::<PageSpec>().unwrap(), PageSpec::Index(0));
        assert_eq!("5".parse::<PageSpec>().unwrap(), PageSpec::Index(4));
    }

    #[test]
    fn rejects_bad_page_specs() {
        assert!("zero"
            .parse::<PageSpec>()
            .unwrap_err()
            .to_string()
            .contains("Invalid page"));
        assert!("0"
            .parse::<PageSpec>()
            .unwrap_err()
            .to_string()
            .contains("1 or greater"));
    }

    #[test]
    fn resolves_page_index() {
        assert_eq!(resolve_page_index(PageSpec::First, 3).unwrap(), 0);
        assert_eq!(resolve_page_index(PageSpec::Last, 3).unwrap(), 2);
        assert_eq!(resolve_page_index(PageSpec::Index(1), 3).unwrap(), 1);
        assert!(resolve_page_index(PageSpec::Index(3), 3).is_err());
        assert!(resolve_page_index(PageSpec::First, 0).is_err());
    }
}
