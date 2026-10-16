//! The signature options: embedded or detached, how a visible signature looks
//! and where it goes, and the reason. Laid out as a form of labelled rows that
//! ends in the placement preview.

use eframe::egui::{self, Ui};
use revenant_sign_core::appearance::AVAILABLE_FONTS;
use revenant_sign_core::pdf::{PageSpec, Position};

use super::{Mode, SignForm, MAX_PAGE, MIN_PAGE};
use crate::form::Form;
use crate::i18n::Localizer;
use crate::segmented::Segmented;

/// Position presets offered in the appearance combo, in display order.
const POSITIONS: [Position; 5] = [
    Position::BottomRight,
    Position::BottomLeft,
    Position::BottomCenter,
    Position::TopLeft,
    Position::TopRight,
];

/// Max digits and width of the explicit page-number field.
const PAGE_DIGITS: usize = 4;
const PAGE_FIELD_WIDTH: f32 = 52.0;
const REASON_FIELD_WIDTH: f32 = 260.0;

/// Which page the signature goes on, as the page control offers it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum PageChoice {
    Last,
    First,
    /// The page typed into the number field.
    Number,
}

impl SignForm {
    pub(super) fn options(&mut self, ui: &mut Ui, l10n: &Localizer) {
        let form = Form::new(
            ui,
            &[
                l10n.t("gui.signature_label"),
                l10n.t("gui.position_label"),
                l10n.t("gui.page_label"),
                l10n.t("gui.font_label"),
                l10n.t("gui.reason_label"),
            ],
        );
        form.row(ui, Some(l10n.t("gui.signature_label")), |ui| {
            let modes = [
                (Mode::Embedded, l10n.t("gui.embedded")),
                (Mode::Detached, l10n.t("gui.detached_p7s")),
            ];
            ui.add(Segmented::new(&mut self.mode, &modes));
        });

        let embedded = !self.is_detached();
        form.row(ui, None, |ui| {
            ui.add_enabled_ui(embedded, |ui| {
                crate::style::checkbox(ui, &mut self.invisible, l10n.t("gui.invisible_signature"));
            });
        });

        let appearance_enabled = self.appearance_enabled();
        ui.add_enabled_ui(appearance_enabled, |ui| {
            form.row(ui, Some(l10n.t("gui.position_label")), |ui| {
                self.position_combo(ui, l10n);
            });
            form.row(ui, Some(l10n.t("gui.page_label")), |ui| {
                self.page_selector(ui, l10n);
            });
            form.row(ui, Some(l10n.t("gui.font_label")), |ui| {
                self.font_combo(ui);
            });
        });

        ui.add_enabled_ui(embedded, |ui| {
            form.row(ui, Some(l10n.t("gui.reason_label")), |ui| {
                ui.add(crate::style::text_edit(&mut self.reason).desired_width(REASON_FIELD_WIDTH));
            });
        });

        // Under the placement controls and lined up with them, so a change of
        // position or page shows where the stamp lands right where it was made.
        form.row(ui, None, |ui| {
            super::super::preview::signature_preview(ui, l10n, self.position, appearance_enabled);
        });
    }

    fn position_combo(&mut self, ui: &mut Ui, l10n: &Localizer) {
        egui::ComboBox::from_id_salt("sign_position")
            .selected_text(position_label(l10n, self.position))
            .show_ui(ui, |ui| {
                for position in POSITIONS {
                    ui.selectable_value(
                        &mut self.position,
                        position,
                        position_label(l10n, position),
                    );
                }
            });
    }

    /// Last, First, or a page number. The number field only takes input once
    /// Number is chosen, so it never reads as a stray "1" next to the presets.
    fn page_selector(&mut self, ui: &mut Ui, l10n: &Localizer) {
        let mut choice = match self.page {
            PageSpec::Last => PageChoice::Last,
            PageSpec::First => PageChoice::First,
            PageSpec::Index(_) => PageChoice::Number,
        };
        let choices = [
            (PageChoice::Last, l10n.t("gui.page_last")),
            (PageChoice::First, l10n.t("gui.page_first")),
            (PageChoice::Number, l10n.t("gui.page_number")),
        ];
        if ui.add(Segmented::new(&mut choice, &choices)).changed() {
            self.page = match choice {
                PageChoice::Last => PageSpec::Last,
                PageChoice::First => PageSpec::First,
                PageChoice::Number => PageSpec::Index(self.typed_page() - 1),
            };
        }

        ui.add_enabled_ui(choice == PageChoice::Number, |ui| {
            // A fixed-width, digit-only field (1-based). Unlike `DragValue`, it
            // cannot grow with its content and blow up the layout.
            let field = ui.add(
                crate::style::text_edit(&mut self.page_input)
                    .char_limit(PAGE_DIGITS)
                    .desired_width(PAGE_FIELD_WIDTH)
                    .horizontal_align(egui::Align::Center),
            );
            if field.changed() {
                self.page_input.retain(|c| c.is_ascii_digit());
                if !self.page_input.is_empty() {
                    self.page = PageSpec::Index(self.typed_page() - 1);
                }
            }
        });
    }

    /// The 1-based page in the number field, kept within the accepted range.
    /// An empty field (mid-edit) counts as the first page.
    fn typed_page(&self) -> usize {
        self.page_input
            .parse::<usize>()
            .unwrap_or(MIN_PAGE)
            .clamp(MIN_PAGE, MAX_PAGE)
    }

    fn font_combo(&mut self, ui: &mut Ui) {
        egui::ComboBox::from_id_salt("sign_font")
            .selected_text(font_display_name(&self.font))
            .show_ui(ui, |ui| {
                for font in AVAILABLE_FONTS {
                    ui.selectable_value(&mut self.font, font.to_owned(), font_display_name(font));
                }
            });
    }
}

/// A font's name as its foundry writes it. The keys are what the config and
/// the CLI use; these are proper names, so they are not translated.
fn font_display_name(key: &str) -> &str {
    match key {
        "noto-sans" => "Noto Sans",
        "ghea-mariam" => "GHEA Mariam",
        "ghea-grapalat" => "GHEA Grapalat",
        // A key this build does not know (a config written by a newer CLI):
        // the key itself is still the truthful thing to show.
        other => other,
    }
}

fn position_label(l10n: &Localizer, position: Position) -> &str {
    match position {
        Position::BottomRight => l10n.t("gui.pos_bottom_right"),
        Position::BottomLeft => l10n.t("gui.pos_bottom_left"),
        Position::BottomCenter => l10n.t("gui.pos_bottom_center"),
        Position::TopLeft => l10n.t("gui.pos_top_left"),
        Position::TopRight => l10n.t("gui.pos_top_right"),
    }
}

#[cfg(test)]
mod tests {
    use super::font_display_name;
    use revenant_sign_core::appearance::AVAILABLE_FONTS;

    #[test]
    fn every_available_font_has_a_display_name() {
        for key in AVAILABLE_FONTS {
            assert_ne!(font_display_name(key), key, "no display name for {key}");
        }
    }
}
