//! A small page thumbnail that shows where the visible signature will land.
//!
//! It reacts live to the chosen position, so the signer sees the placement
//! before committing -- something the Python client never offered. The drawing
//! is schematic (a page outline, a few faux text lines, and a highlighted stamp
//! box); it is not a real render of the PDF.

use eframe::egui;
use revenant_sign_core::pdf::Position;

use crate::i18n::Localizer;
use crate::theme;

/// Thumbnail size, roughly A4 portrait proportions (1 : 1.41).
const PAGE_W: f32 = 84.0;
const PAGE_H: f32 = 118.0;
/// Inset of the stamp box from the page edge.
const MARGIN: f32 = 6.0;
/// Stamp box size as a fraction of the page.
const BOX_W_FRAC: f32 = 0.44;
const BOX_H_FRAC: f32 = 0.13;

/// Draw the preview thumbnail. When `visible` is false (detached or invisible
/// signature) the stamp box is replaced with a muted "no visible signature"
/// note, so the preview always reflects the current settings.
pub(crate) fn signature_preview(
    ui: &mut egui::Ui,
    l10n: &Localizer,
    position: Position,
    visible: bool,
) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(PAGE_W, PAGE_H), egui::Sense::hover());
    if !ui.is_rect_visible(rect) {
        return;
    }
    let visuals = ui.visuals();
    let page_fill = visuals.extreme_bg_color;
    let page_stroke = visuals.widgets.noninteractive.bg_stroke;
    let line_color = theme::MUTED.gamma_multiply(0.5);
    let painter = ui.painter_at(rect);

    painter.rect_filled(rect, 3.0, page_fill);
    painter.rect_stroke(rect, 3.0, page_stroke, egui::StrokeKind::Inside);
    draw_faux_text(&painter, rect, line_color);

    if !visible {
        painter.text(
            rect.center(),
            egui::Align2::CENTER_CENTER,
            l10n.t("gui.invisible_signature"),
            egui::FontId::proportional(9.0),
            theme::MUTED,
        );
        return;
    }

    let stamp = stamp_rect(rect, position);
    painter.rect_filled(stamp, 2.0, theme::OK.gamma_multiply(0.30));
    painter.rect_stroke(
        stamp,
        2.0,
        egui::Stroke::new(1.0, theme::OK),
        egui::StrokeKind::Inside,
    );
}

/// A handful of thin lines suggesting body text, so the thumbnail reads as a
/// page rather than an empty box.
fn draw_faux_text(painter: &egui::Painter, page: egui::Rect, color: egui::Color32) {
    const LINES: u16 = 5;
    const STEP: f32 = 11.0;
    let inner = page.shrink(MARGIN);
    let stroke = egui::Stroke::new(1.0, color);
    for i in 0..LINES {
        // The last line is shorter, like a trailing paragraph line.
        let width = if i == LINES - 1 { 0.55 } else { 1.0 };
        // `f32::from(u16)` is lossless, sidestepping the precision-loss lint.
        let y = inner.top() + STEP * (f32::from(i) + 0.5);
        let left = inner.left();
        let right = left + inner.width() * width;
        painter.line_segment([egui::pos2(left, y), egui::pos2(right, y)], stroke);
    }
}

/// The stamp box for a given position, inset by [`MARGIN`] from the page edge.
fn stamp_rect(page: egui::Rect, position: Position) -> egui::Rect {
    let inner = page.shrink(MARGIN);
    let size = egui::vec2(page.width() * BOX_W_FRAC, page.height() * BOX_H_FRAC);
    let min = match position {
        Position::BottomRight => egui::pos2(inner.right() - size.x, inner.bottom() - size.y),
        Position::BottomLeft => egui::pos2(inner.left(), inner.bottom() - size.y),
        Position::BottomCenter => {
            egui::pos2(inner.center().x - size.x / 2.0, inner.bottom() - size.y)
        }
        Position::TopLeft => egui::pos2(inner.left(), inner.top()),
        Position::TopRight => egui::pos2(inner.right() - size.x, inner.top()),
    };
    egui::Rect::from_min_size(min, size)
}
