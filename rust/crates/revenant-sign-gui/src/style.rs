//! One-time global visual style plus a couple of shared widget builders.
//!
//! `install` is applied to both the light and dark themes (via
//! [`egui::Context::all_styles_mut`]) so the look survives an OS theme switch.
//! It sets a comfortable spacing rhythm, the platform's type scale, a readable
//! secondary text color, rounded widgets, and the accent color used for
//! selection and primary actions -- the difference
//! between "default egui" and a finished app. Fonts are installed separately in
//! [`crate::fonts`].

use eframe::egui::{self, Color32, CornerRadius, FontId, Margin, Stroke, TextStyle, Vec2};

use crate::theme;
use crate::window_style::TextSizes;

/// Minimum size of the primary (accent) button, so it reads as the main action.
const PRIMARY_BUTTON_MIN: [f32; 2] = [0.0, 30.0];
const CHECKBOX_RADIUS: u8 = 3;

/// Apply the global style to every theme.
pub(crate) fn install(ctx: &egui::Context, text: TextSizes) {
    ctx.all_styles_mut(|style| tune(style, text));
}

fn tune(style: &mut egui::Style, text: TextSizes) {
    style.spacing.item_spacing = Vec2::new(8.0, 8.0);
    style.spacing.button_padding = Vec2::new(12.0, 6.0);
    style.spacing.interact_size.y = 26.0;
    style.spacing.window_margin = Margin::same(12);

    style.text_styles = [
        (TextStyle::Heading, FontId::proportional(text.heading)),
        (TextStyle::Body, FontId::proportional(text.body)),
        (TextStyle::Button, FontId::proportional(text.body)),
        (TextStyle::Small, FontId::proportional(text.small)),
        (TextStyle::Monospace, FontId::monospace(text.monospace)),
    ]
    .into();

    style.visuals.weak_text_color = Some(secondary_text(&style.visuals));

    // Round every widget state consistently.
    for widget in [
        &mut style.visuals.widgets.noninteractive,
        &mut style.visuals.widgets.inactive,
        &mut style.visuals.widgets.hovered,
        &mut style.visuals.widgets.active,
        &mut style.visuals.widgets.open,
    ] {
        widget.corner_radius = CornerRadius::same(6);
    }
    style.visuals.window_corner_radius = CornerRadius::same(10);

    // A hairline border on controls at rest, so checkboxes, radio buttons and
    // text fields read as controls rather than faint patches of fill.
    style.visuals.widgets.inactive.bg_stroke = Stroke::new(1.0_f32, control_border(&style.visuals));

    // Accent for selection (tabs, segmented controls) and links. A translucent
    // fill reads well over both light and dark backgrounds.
    let accent = theme::accent();
    style.visuals.selection.bg_fill =
        Color32::from_rgba_unmultiplied(accent.r(), accent.g(), accent.b(), 0x55);
    style.visuals.selection.stroke = Stroke::new(1.0_f32, accent);
    style.visuals.hyperlink_color = accent;
}

/// Secondary text (hints, captions, a wizard's step counter): a step back from
/// the body text, but still at least 4.5:1 against every surface it sits on,
/// the WCAG AA minimum for text. egui's own weak color is well under that on
/// the light theme.
fn secondary_text(visuals: &egui::Visuals) -> Color32 {
    if visuals.dark_mode {
        Color32::from_gray(0xA0)
    } else {
        Color32::from_gray(0x66)
    }
}

/// The border of a control at rest: dark enough to find the control, light
/// enough not to compete with its label.
fn control_border(visuals: &egui::Visuals) -> Color32 {
    if visuals.dark_mode {
        Color32::from_gray(0x5A)
    } else {
        Color32::from_gray(0xC4)
    }
}

/// A checkbox with the small square corners checkboxes have on every
/// platform. The app-wide widget rounding would otherwise make it a circle,
/// indistinguishable from a radio button.
pub(crate) fn checkbox(ui: &mut egui::Ui, checked: &mut bool, text: &str) -> egui::Response {
    ui.scope(|ui| {
        let widgets = &mut ui.visuals_mut().widgets;
        for state in [
            &mut widgets.inactive,
            &mut widgets.hovered,
            &mut widgets.active,
        ] {
            state.corner_radius = CornerRadius::same(CHECKBOX_RADIUS);
        }
        ui.checkbox(checked, text)
    })
    .inner
}

/// An accent-filled button for the single primary action on a screen. Callers
/// add it with [`egui::Ui::add`] / [`egui::Ui::add_enabled`] and may chain
/// `.min_size(...)` for a larger hero button.
pub(crate) fn primary_button(text: impl Into<String>) -> egui::Button<'static> {
    egui::Button::new(egui::RichText::new(text.into()).color(theme::on_accent()))
        .fill(theme::accent())
        .min_size(Vec2::new(PRIMARY_BUTTON_MIN[0], PRIMARY_BUTTON_MIN[1]))
}

/// A card: a group of related content on a fill a step lighter than the window,
/// with a hairline border, as Fluent settings cards and macOS grouped forms
/// draw them. No shadow: a card is part of the page, not floating above it.
pub(crate) fn card(ui: &egui::Ui) -> egui::Frame {
    let visuals = ui.visuals();
    egui::Frame::new()
        .fill(card_fill(visuals))
        .stroke(visuals.widgets.noninteractive.bg_stroke)
        .corner_radius(CornerRadius::same(8))
        .inner_margin(Margin::same(16))
}

fn card_fill(visuals: &egui::Visuals) -> Color32 {
    if visuals.dark_mode {
        Color32::from_white_alpha(10)
    } else {
        Color32::WHITE
    }
}

/// A single-line text field whose vertical padding matches the buttons, so
/// label/field/button rows line up. Callers chain `.desired_width(...)`.
pub(crate) fn text_edit(value: &mut String) -> egui::TextEdit<'_> {
    egui::TextEdit::singleline(value).margin(Margin::symmetric(8, 6))
}

/// Height of a file drop zone.
pub(crate) const DROP_ZONE_HEIGHT: f32 = 66.0;

/// Accepted extensions for the PDF and image drop zones (case-insensitive).
pub(crate) const PDF_EXTS: &[&str] = &["pdf"];
pub(crate) const IMAGE_EXTS: &[&str] = &["png", "jpg", "jpeg"];

/// The result of rendering a [`drop_zone`].
pub(crate) struct DropZone {
    /// The user clicked the zone (the caller should open a file picker).
    pub(crate) clicked: bool,
}

/// A clickable file drop target: a rounded box showing the current file name (or
/// a muted placeholder). Clicking opens a picker. While a file whose extension
/// is in `accept_exts` is dragged over the window, the zone highlights -- keyed
/// off the hovered file's *type*, not the pointer position (which macOS does not
/// report during an external drag), so only the matching zone lights up.
pub(crate) fn drop_zone(
    ui: &mut egui::Ui,
    icon: &str,
    title: &str,
    filename: Option<&str>,
    placeholder: &str,
    accept_exts: &[&str],
) -> DropZone {
    let size = Vec2::new(ui.available_width(), DROP_ZONE_HEIGHT);
    let (rect, response) = ui.allocate_exact_size(size, egui::Sense::click());

    let enabled = ui.is_enabled();
    let file_matches = enabled
        && ui.ctx().input(|i| {
            i.raw
                .hovered_files
                .iter()
                .any(|file| path_has_extension(file.path.as_deref(), accept_exts))
        });
    if file_matches {
        ui.ctx().request_repaint(); // keep the highlight live during the drag
    }

    let visuals = ui.visuals();
    let accent = theme::accent();
    let (fill, stroke) = if file_matches {
        (
            Color32::from_rgba_unmultiplied(accent.r(), accent.g(), accent.b(), 0x33),
            Stroke::new(2.5_f32, accent),
        )
    } else if response.hovered() {
        (
            visuals.widgets.hovered.bg_fill,
            visuals.widgets.hovered.bg_stroke,
        )
    } else {
        (
            visuals.faint_bg_color,
            visuals.widgets.noninteractive.bg_stroke,
        )
    };

    let painter = ui.painter_at(rect);
    painter.rect(
        rect,
        CornerRadius::same(8),
        fill,
        stroke,
        egui::StrokeKind::Inside,
    );
    painter.text(
        rect.center_top() + Vec2::new(0.0, 12.0),
        egui::Align2::CENTER_CENTER,
        format!("{icon}  {title}"),
        TextStyle::Small.resolve(ui.style()),
        visuals.weak_text_color(),
    );
    let (body, color) = match filename {
        Some(name) => (elide(name, 36), visuals.text_color()),
        None => (placeholder.to_owned(), visuals.weak_text_color()),
    };
    painter.text(
        rect.center() + Vec2::new(0.0, 6.0),
        egui::Align2::CENTER_CENTER,
        body,
        TextStyle::Body.resolve(ui.style()),
        color,
    );

    if response.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    DropZone {
        clicked: response.clicked(),
    }
}

/// Whether `path`'s extension is one of `exts` (case-insensitive).
pub(crate) fn path_has_extension(path: Option<&std::path::Path>, exts: &[&str]) -> bool {
    path.and_then(std::path::Path::extension)
        .is_some_and(|ext| {
            exts.iter()
                .any(|candidate| ext.eq_ignore_ascii_case(candidate))
        })
}

/// A drop-zone heading from a form label, without its trailing colon.
pub(crate) fn zone_title(label: &str) -> String {
    label.trim_end_matches(':').trim().to_owned()
}

/// The file name of a path string, or `None` if the string is empty.
pub(crate) fn zone_basename(path: &str) -> Option<String> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return None;
    }
    let name = std::path::Path::new(trimmed)
        .file_name()
        .map_or_else(|| trimmed.to_owned(), |n| n.to_string_lossy().into_owned());
    Some(name)
}

/// Shorten `text` to at most `max` characters with a middle "..." so the file
/// extension stays visible.
fn elide(text: &str, max: usize) -> String {
    let chars: Vec<char> = text.chars().collect();
    if chars.len() <= max {
        return text.to_owned();
    }
    let head = max / 2 - 2;
    let tail = max - head - 3;
    let start: String = chars[..head].iter().collect();
    let end: String = chars[chars.len() - tail..].iter().collect();
    format!("{start}...{end}")
}

#[cfg(test)]
mod tests {
    use eframe::egui::{Color32, Visuals};

    use super::{card_fill, elide, secondary_text};

    /// WCAG relative luminance of an opaque sRGB color.
    fn luminance(color: Color32) -> f32 {
        let channel = |value: u8| {
            let value = f32::from(value) / 255.0;
            if value <= 0.040_45 {
                value / 12.92
            } else {
                ((value + 0.055) / 1.055).powf(2.4)
            }
        };
        0.2126 * channel(color.r()) + 0.7152 * channel(color.g()) + 0.0722 * channel(color.b())
    }

    fn contrast(a: Color32, b: Color32) -> f32 {
        let (light, dark) = (
            luminance(a).max(luminance(b)),
            luminance(a).min(luminance(b)),
        );
        (light + 0.05) / (dark + 0.05)
    }

    /// `over` (premultiplied, possibly translucent) composited onto `under`.
    fn composite(over: Color32, under: Color32) -> Color32 {
        let behind = 1.0 - f32::from(over.a()) / 255.0;
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // 0..=255
        let mix = |top: u8, bottom: u8| (f32::from(top) + f32::from(bottom) * behind).round() as u8;
        Color32::from_rgb(
            mix(over.r(), under.r()),
            mix(over.g(), under.g()),
            mix(over.b(), under.b()),
        )
    }

    #[test]
    fn secondary_text_is_readable_on_every_surface() {
        for visuals in [Visuals::light(), Visuals::dark()] {
            let text = secondary_text(&visuals);
            let card = composite(card_fill(&visuals), visuals.panel_fill);
            for surface in [
                visuals.panel_fill,
                visuals.window_fill,
                visuals.faint_bg_color,
                card,
            ] {
                let surface = composite(surface, visuals.panel_fill);
                let ratio = contrast(text, surface);
                assert!(
                    ratio >= 4.5,
                    "{text:?} on {surface:?} is {ratio:.2}:1 (dark: {})",
                    visuals.dark_mode
                );
            }
        }
    }

    #[test]
    fn elide_keeps_short_strings() {
        assert_eq!(elide("report.pdf", 36), "report.pdf");
    }

    #[test]
    fn elide_shortens_with_middle_ellipsis_keeping_extension() {
        let long = "a_very_long_document_name_that_will_not_fit_here.pdf";
        let out = elide(long, 20);
        assert_eq!(out.chars().count(), 20);
        assert!(out.contains("..."));
        // The extension (last dot-segment) survives the middle elision.
        assert_eq!(out.rsplit('.').next(), Some("pdf"));
    }
}
