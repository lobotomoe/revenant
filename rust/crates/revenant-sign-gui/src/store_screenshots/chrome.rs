//! Window frames: the title bar each store's platform draws around the app.
//!
//! The app's own pixels come from the real UI; only the frame the operating
//! system would add is drawn here, in the platform's default light style.
//! Sizes are in app points and scaled with the window.

use eframe::egui::{
    pos2, vec2, Align2, Color32, CornerRadius, FontFamily, FontId, Painter, Pos2, Rect, Stroke,
    TextureId,
};

use super::listing::Chrome;

const WINDOW_TITLE: &str = "Revenant";

/// Horizontal centers of the macOS close, minimize and zoom buttons, in points.
const TRAFFIC_LIGHT_OFFSETS: [f32; 3] = [14.0, 34.0, 54.0];

impl Chrome {
    /// Title bar height in points.
    pub(crate) fn title_bar_height(self) -> f32 {
        match self {
            Chrome::MacOs => 28.0,
            Chrome::Windows => 32.0,
            Chrome::Gnome => 46.0,
        }
    }

    /// Window corner radius in points.
    pub(crate) fn corner_radius(self) -> f32 {
        match self {
            Chrome::MacOs => 10.0,
            Chrome::Windows => 8.0,
            Chrome::Gnome => 12.0,
        }
    }

    fn title_bar_fill(self) -> Color32 {
        match self {
            Chrome::MacOs => Color32::from_gray(0xE8),
            Chrome::Windows => Color32::from_gray(0xF3),
            Chrome::Gnome => Color32::from_gray(0xEB),
        }
    }
}

/// Paint the title bar into `bar` (the top strip of the window).
///
/// `scale` is pixels per app point; `icon` is the app icon texture, which only
/// the Windows frame shows.
pub(crate) fn paint_title_bar(
    painter: &Painter,
    chrome: Chrome,
    bar: Rect,
    scale: f32,
    icon: TextureId,
) {
    let corner = radius(chrome.corner_radius() * scale);
    let top_corners = CornerRadius {
        nw: corner,
        ne: corner,
        sw: 0,
        se: 0,
    };
    painter.rect_filled(bar, top_corners, chrome.title_bar_fill());
    painter.line_segment(
        [bar.left_bottom(), bar.right_bottom()],
        Stroke::new(scale, Color32::from_gray(0xD2)),
    );

    match chrome {
        Chrome::MacOs => paint_macos(painter, bar, scale),
        Chrome::Windows => paint_windows(painter, bar, scale, icon),
        Chrome::Gnome => paint_gnome(painter, bar, scale),
    }
}

/// Traffic lights on the left, a centered title.
fn paint_macos(painter: &Painter, bar: Rect, scale: f32) {
    const LIGHTS: [(Color32, Color32); 3] = [
        (
            Color32::from_rgb(0xFF, 0x5F, 0x57),
            Color32::from_rgb(0xE0, 0x44, 0x3E),
        ),
        (
            Color32::from_rgb(0xFE, 0xBC, 0x2E),
            Color32::from_rgb(0xDE, 0xA1, 0x23),
        ),
        (
            Color32::from_rgb(0x28, 0xC8, 0x40),
            Color32::from_rgb(0x1A, 0xAB, 0x29),
        ),
    ];
    let y = bar.center().y;
    for (offset, (fill, rim)) in TRAFFIC_LIGHT_OFFSETS.into_iter().zip(LIGHTS) {
        let x = bar.left() + offset * scale;
        painter.circle(pos2(x, y), 6.0 * scale, fill, Stroke::new(0.5 * scale, rim));
    }
    title(
        painter,
        bar.center(),
        Align2::CENTER_CENTER,
        13.0 * scale,
        false,
        Color32::from_gray(0x4C),
    );
}

/// App icon and title on the left; minimize, maximize and close on the right.
fn paint_windows(painter: &Painter, bar: Rect, scale: f32, icon: TextureId) {
    let y = bar.center().y;
    let icon_rect =
        Rect::from_center_size(pos2(bar.left() + 20.0 * scale, y), vec2(16.0, 16.0) * scale);
    let full_uv = Rect::from_min_max(pos2(0.0, 0.0), pos2(1.0, 1.0));
    painter.image(icon, icon_rect, full_uv, Color32::WHITE);
    title(
        painter,
        pos2(bar.left() + 38.0 * scale, y),
        Align2::LEFT_CENTER,
        12.0 * scale,
        false,
        Color32::from_gray(0x1A),
    );

    let glyph = Stroke::new(1.0 * scale, Color32::from_gray(0x1A));
    let button_width = 46.0 * scale;
    let half = 5.0 * scale;
    let close = pos2(bar.right() - button_width * 0.5, y);
    let maximize = close - vec2(button_width, 0.0);
    let minimize = maximize - vec2(button_width, 0.0);

    painter.line_segment(
        [minimize - vec2(half, 0.0), minimize + vec2(half, 0.0)],
        glyph,
    );
    painter.rect_stroke(
        Rect::from_center_size(maximize, vec2(2.0 * half, 2.0 * half)),
        CornerRadius::same(radius(scale)),
        glyph,
        eframe::egui::StrokeKind::Middle,
    );
    painter.line_segment([close - vec2(half, half), close + vec2(half, half)], glyph);
    painter.line_segment(
        [close + vec2(-half, half), close + vec2(half, -half)],
        glyph,
    );
}

/// A bold centered title and a round close button on the right, as an
/// Adwaita header bar draws them.
fn paint_gnome(painter: &Painter, bar: Rect, scale: f32) {
    title(
        painter,
        bar.center(),
        Align2::CENTER_CENTER,
        14.0 * scale,
        true,
        Color32::from_gray(0x2E),
    );

    let center = pos2(bar.right() - 22.0 * scale, bar.center().y);
    painter.circle_filled(center, 12.0 * scale, Color32::from_gray(0xDA));
    let half = 4.0 * scale;
    let glyph = Stroke::new(1.6 * scale, Color32::from_gray(0x2E));
    painter.line_segment(
        [center - vec2(half, half), center + vec2(half, half)],
        glyph,
    );
    painter.line_segment(
        [center + vec2(-half, half), center + vec2(half, -half)],
        glyph,
    );
}

fn title(painter: &Painter, at: Pos2, anchor: Align2, size: f32, bold: bool, color: Color32) {
    let family = if bold {
        FontFamily::Name(super::compose::BOLD_FAMILY.into())
    } else {
        FontFamily::Proportional
    };
    painter.text(at, anchor, WINDOW_TITLE, FontId::new(size, family), color);
}

/// A corner radius in whole pixels, as egui stores it.
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "rounded and clamped to the u8 range first, so the cast is exact"
)]
pub(crate) fn radius(pixels: f32) -> u8 {
    pixels.round().clamp(0.0, f32::from(u8::MAX)) as u8
}
