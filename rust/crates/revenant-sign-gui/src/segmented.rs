//! A segmented control: a row of equal-width segments on a shared track, one of
//! which is selected, drawn the way macOS draws one (a raised light segment on a
//! recessed track). Used where the user picks one of a few modes, so that choice
//! does not look like a tab or a button.

use eframe::egui::{
    self, Color32, CornerRadius, Response, Sense, TextStyle, Ui, Vec2, Widget, WidgetInfo,
    WidgetText, WidgetType,
};

/// Height of the whole control, in points.
const HEIGHT: f32 = 24.0;
/// Horizontal padding inside each segment, around its label.
const SEGMENT_PADDING_X: f32 = 14.0;
/// Gap between the track's edge and the selected segment.
const TRACK_INSET: f32 = 2.0;
const TRACK_RADIUS: u8 = 7;
const SEGMENT_RADIUS: u8 = 5;

/// One choice of `T`, shown with its label, among `options`.
#[derive(Debug)]
pub(crate) struct Segmented<'a, T> {
    selected: &'a mut T,
    options: &'a [(T, &'a str)],
}

impl<'a, T: Copy + PartialEq> Segmented<'a, T> {
    pub(crate) fn new(selected: &'a mut T, options: &'a [(T, &'a str)]) -> Self {
        Self { selected, options }
    }

    /// The size the control takes, for callers that place it themselves (for
    /// example centred in a toolbar).
    pub(crate) fn size(&self, ui: &Ui) -> Vec2 {
        let widest = self
            .options
            .iter()
            .map(|(_, label)| label_galley(ui, label).size().x)
            .fold(0.0_f32, f32::max);
        let segment_width = widest + 2.0 * SEGMENT_PADDING_X;
        #[allow(clippy::cast_precision_loss)] // a handful of segments
        let count = self.options.len() as f32;
        Vec2::new(segment_width * count + 2.0 * TRACK_INSET, HEIGHT)
    }
}

impl<T: Copy + PartialEq> Widget for Segmented<'_, T> {
    fn ui(self, ui: &mut Ui) -> Response {
        let size = self.size(ui);
        let (rect, mut response) = ui.allocate_exact_size(size, Sense::hover());
        let dark = ui.visuals().dark_mode;
        let (track, raised) = if dark {
            (Color32::from_gray(0x3A), Color32::from_gray(0x63))
        } else {
            (Color32::from_gray(0xE3), Color32::WHITE)
        };
        let painter = ui.painter_at(rect);
        painter.rect_filled(rect, CornerRadius::same(TRACK_RADIUS), track);

        #[allow(clippy::cast_precision_loss)] // a handful of segments
        let segment_width = (rect.width() - 2.0 * TRACK_INSET) / self.options.len() as f32;
        for (index, (value, label)) in self.options.iter().enumerate() {
            #[allow(clippy::cast_precision_loss)]
            let left = rect.left() + TRACK_INSET + segment_width * index as f32;
            let segment = egui::Rect::from_min_size(
                egui::pos2(left, rect.top() + TRACK_INSET),
                Vec2::new(segment_width, rect.height() - 2.0 * TRACK_INSET),
            );
            let segment_response = ui.interact(segment, response.id.with(index), Sense::click());
            let is_selected = *self.selected == *value;
            if segment_response.clicked() && !is_selected {
                *self.selected = *value;
                response.mark_changed();
            }
            let enabled = ui.is_enabled();
            segment_response.widget_info(|| {
                WidgetInfo::selected(WidgetType::RadioButton, enabled, is_selected, *label)
            });

            if is_selected {
                painter.rect_filled(segment, CornerRadius::same(SEGMENT_RADIUS), raised);
            } else if segment_response.hovered() {
                painter.rect_filled(
                    segment,
                    CornerRadius::same(SEGMENT_RADIUS),
                    ui.visuals().widgets.hovered.weak_bg_fill,
                );
            }
            let text_color = if is_selected {
                ui.visuals().strong_text_color()
            } else {
                ui.visuals().text_color()
            };
            let galley = label_galley(ui, label);
            let text_pos = segment.center() - galley.size() / 2.0;
            painter.galley(text_pos, galley, text_color);
            response = response.union(segment_response);
        }
        response
    }
}

fn label_galley(ui: &Ui, label: &str) -> std::sync::Arc<egui::Galley> {
    WidgetText::from(label).into_galley(
        ui,
        Some(egui::TextWrapMode::Extend),
        f32::INFINITY,
        TextStyle::Button,
    )
}
