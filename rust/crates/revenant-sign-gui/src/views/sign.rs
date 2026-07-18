//! Sign tab. Its content follows the config layer, mirroring the Python client:
//! prompt to connect, prompt to log in, or the signing form.
//!
//! The full signing form (file drop, appearance options, background signing)
//! lands in a later step; for now the configured layers show their prompt.

use eframe::egui;
use revenant_sign_core::config::ConfigLayer;

use crate::i18n::Localizer;

/// What the app should do after rendering the tab.
pub(crate) enum SignAction {
    None,
    /// Open the connect dialog.
    Connect,
}

pub(crate) fn show(ui: &mut egui::Ui, l10n: &Localizer, layer: ConfigLayer) -> SignAction {
    let mut action = SignAction::None;
    ui.vertical_centered(|ui| {
        ui.add_space(32.0);
        match layer {
            ConfigLayer::Unconfigured => {
                ui.label(l10n.t("gui.connect_to_a_server_to_sign_documents"));
                ui.add_space(12.0);
                if ui.button(l10n.t("gui.connect")).clicked() {
                    action = SignAction::Connect;
                }
            }
            ConfigLayer::ServerConfigured => {
                ui.label(l10n.t("gui.server_connected_log_in_to_sign_documents"));
            }
            ConfigLayer::FullyConfigured => {
                ui.heading(l10n.t("gui.sign_pdf"));
            }
        }
    });
    action
}
