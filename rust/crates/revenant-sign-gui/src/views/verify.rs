//! Verify tab. The full verification UI (file pickers, local + server checks,
//! per-signature results) lands in a later step; for now it shows its help text.

use eframe::egui;

use crate::i18n::Localizer;

pub(crate) fn show(ui: &mut egui::Ui, l10n: &Localizer) {
    ui.vertical_centered(|ui| {
        ui.add_space(24.0);
        ui.label(l10n.t("gui.select_a_pdf_file_and_click_verify_to_check_signat_8fbc47f0"));
    });
}
