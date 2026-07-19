//! About dialog: app name, version, tagline, author, license, and project links.

use eframe::egui;
use revenant_sign_core::constants::VERSION;

use crate::i18n::Localizer;
use crate::theme;

/// Project URLs, mirrored from the Python client's About dialog.
const REPO_URL: &str = "https://github.com/lobotomoe/revenant";
const ISSUES_URL: &str = "https://github.com/lobotomoe/revenant/issues";
const TELEGRAM_URL: &str = "https://t.me/m_surf";

const DIALOG_WIDTH: f32 = 340.0;

/// Returns `true` when the dialog should close.
pub(crate) fn show(ctx: &egui::Context, l10n: &Localizer) -> bool {
    let mut ok_clicked = false;
    let response = egui::Modal::new(egui::Id::new("about_dialog")).show(ctx, |ui| {
        ui.set_width(DIALOG_WIDTH);
        ui.vertical_centered(|ui| {
            ui.heading("Revenant");
            ui.label(l10n.tf("gui.version_version", &[("version", VERSION)]));
            ui.add_space(8.0);
            ui.label(l10n.t("gui.cross_platform_client_for_arx_cosign_electronic_signatures"));
            ui.add_space(8.0);
            ui.label(egui::RichText::new(l10n.t("gui.author_aleksandr_kraiz")).color(theme::MUTED));
            ui.label(egui::RichText::new(l10n.t("gui.license_apache_2_0")).color(theme::MUTED));

            ui.add_space(12.0);
            // A plain `horizontal` inside `vertical_centered` stays left-aligned
            // (it claims the full row width); a left-to-right layout with a
            // centered main axis packs the links in the middle instead.
            ui.allocate_ui_with_layout(
                egui::vec2(ui.available_width(), 0.0),
                egui::Layout::left_to_right(egui::Align::Center)
                    .with_main_align(egui::Align::Center),
                |ui| {
                    ui.hyperlink_to(l10n.t("gui.github"), REPO_URL);
                    ui.hyperlink_to(l10n.t("gui.report_a_bug"), ISSUES_URL);
                    ui.hyperlink_to(l10n.t("gui.telegram"), TELEGRAM_URL);
                },
            );

            ui.add_space(12.0);
            if ui.button(l10n.t("gui.ok_upper")).clicked() {
                ok_clicked = true;
            }
        });
    });
    ok_clicked || response.should_close()
}
