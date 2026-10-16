//! A form of labelled rows: the labels right-aligned in one column, the controls
//! starting on one line beside them, the way desktop forms line up on macOS and
//! in Windows dialogs. egui's `Grid` sizes its columns a frame late and cannot
//! right-align a cell, so the label column is measured up front instead.

use eframe::egui::{self, Align, Layout, Ui, Vec2, WidgetText};

/// The measured label column of one form.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Form {
    label_width: f32,
}

impl Form {
    /// A form whose label column fits the widest of `labels`.
    pub(crate) fn new(ui: &Ui, labels: &[&str]) -> Self {
        let label_width = labels
            .iter()
            .map(|label| {
                WidgetText::from(*label)
                    .into_galley(
                        ui,
                        Some(egui::TextWrapMode::Extend),
                        f32::INFINITY,
                        egui::TextStyle::Body,
                    )
                    .size()
                    .x
            })
            .fold(0.0_f32, f32::max);
        Self { label_width }
    }

    /// One row: `label` (or an empty label cell, for a control such as a
    /// checkbox that carries its own text) and the controls `add_contents` adds.
    pub(crate) fn row<R>(
        self,
        ui: &mut Ui,
        label: Option<&str>,
        add_contents: impl FnOnce(&mut Ui) -> R,
    ) -> R {
        ui.horizontal(|ui| {
            let height = ui.spacing().interact_size.y;
            ui.allocate_ui_with_layout(
                Vec2::new(self.label_width, height),
                Layout::right_to_left(Align::Center),
                |ui| {
                    ui.set_min_size(Vec2::new(self.label_width, height));
                    if let Some(label) = label {
                        ui.label(label);
                    }
                },
            );
            add_contents(ui)
        })
        .inner
    }
}
