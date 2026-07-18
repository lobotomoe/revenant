//! About dialog: app name, version, author, license.

use eframe::egui;
use revenant_sign_core::constants::VERSION;

use crate::i18n::Localizer;

/// Returns `true` when the dialog should close.
pub(crate) fn show(ctx: &egui::Context, l10n: &Localizer) -> bool {
    let response = egui::Modal::new(egui::Id::new("about_dialog")).show(ctx, |ui| {
        ui.set_width(320.0);
        ui.vertical_centered(|ui| {
            ui.heading("Revenant");
            ui.label(l10n.tf("gui.version_version", &[("version", VERSION)]));
            ui.add_space(6.0);
            ui.label(l10n.t("gui.author_aleksandr_kraiz"));
            ui.label(l10n.t("gui.license_apache_2_0"));
        });
    });
    response.should_close()
}
