//! The top of the form: the PDF to sign (or the files of a batch) and the
//! optional stamp image, each a drop zone that also opens a picker.

use eframe::egui;

use super::{SignAction, SignForm};
use crate::i18n::Localizer;

const BATCH_LIST_MAX_HEIGHT: f32 = 110.0;

impl SignForm {
    /// The top section: two drop zones -- the required PDF (or batch) on the
    /// left, the optional stamp image on the right. Each is click-to-browse and
    /// a drop target; the app routes drops using the stored zone rect.
    pub(super) fn input_section(&mut self, ui: &mut egui::Ui, l10n: &Localizer) -> SignAction {
        let mut action = SignAction::None;

        let pdf_title = crate::style::zone_title(l10n.t("gui.pdf_file_label"));
        let image_title = crate::style::zone_title(l10n.t("gui.image_opt_label"));
        let pdf_name = self.pdf_zone_name();
        let image_name = crate::style::zone_basename(&self.image_path);
        let appearance_enabled = self.appearance_enabled();

        ui.columns(2, |cols| {
            if let [left, right] = cols {
                let pdf = crate::style::drop_zone(
                    left,
                    crate::icons::PDF,
                    &pdf_title,
                    pdf_name.as_deref(),
                    l10n.t("gui.drop_pdf_hint"),
                    crate::style::PDF_EXTS,
                );
                if pdf.clicked {
                    action = SignAction::BrowsePdf;
                }
                right.add_enabled_ui(appearance_enabled, |ui| {
                    let image = crate::style::drop_zone(
                        ui,
                        crate::icons::IMAGE,
                        &image_title,
                        image_name.as_deref(),
                        l10n.t("gui.drop_image_hint"),
                        crate::style::IMAGE_EXTS,
                    );
                    if image.clicked {
                        action = SignAction::BrowseImage;
                    }
                });
            }
        });

        // Batch: list the queued files below the zones.
        if self.is_batch() {
            ui.add_space(4.0);
            self.batch_list(ui, l10n);
        }
        action
    }

    /// The PDF zone's body text: the file name, a batch count, or nothing (which
    /// falls back to the drop hint).
    fn pdf_zone_name(&self) -> Option<String> {
        if self.is_batch() {
            return Some(format!("{} PDF", self.batch.len()));
        }
        crate::style::zone_basename(&self.pdf_path)
    }

    /// The queued files, one per row, each with a remove button at the end.
    fn batch_list(&mut self, ui: &mut egui::Ui, l10n: &Localizer) {
        let mut remove = None;
        egui::ScrollArea::vertical()
            .max_height(BATCH_LIST_MAX_HEIGHT)
            .show(ui, |ui| {
                for (index, path) in self.batch.iter().enumerate() {
                    ui.horizontal(|ui| {
                        let name = path
                            .file_name()
                            .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
                        ui.label(format!("{}  {name}", crate::icons::PDF));
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            let button = egui::Button::new(crate::icons::REMOVE).frame(false);
                            if ui.add(button).on_hover_text(l10n.t("gui.remove")).clicked() {
                                remove = Some(index);
                            }
                        });
                    });
                }
            });
        if let Some(index) = remove {
            self.batch.remove(index);
        }
    }
}
