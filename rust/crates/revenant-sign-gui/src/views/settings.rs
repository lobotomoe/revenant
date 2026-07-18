//! Settings dialog: choose the UI language. The selection persists through the
//! shared config, so it is remembered across launches and shared with the CLI.

use eframe::egui;
use revenant_sign_core::config::ConfigStore;

use crate::i18n::{self, Localizer, SUPPORTED_LOCALES, SYSTEM_LANGUAGE};

/// What the app should do after rendering the dialog.
pub(crate) enum SettingsAction {
    None,
    Close,
    /// Persist and apply a new language setting (a locale code or `"system"`).
    SetLanguage(String),
}

pub(crate) fn show(ctx: &egui::Context, l10n: &Localizer, store: &ConfigStore) -> SettingsAction {
    let mut action = SettingsAction::None;
    let current = store.language();

    let response = egui::Modal::new(egui::Id::new("settings_dialog")).show(ctx, |ui| {
        ui.set_width(320.0);
        ui.heading(l10n.t("gui.settings"));
        ui.separator();

        ui.horizontal(|ui| {
            ui.label(l10n.t("gui.language_label"));
            let selected_text = if current == SYSTEM_LANGUAGE {
                l10n.t("gui.system")
            } else {
                i18n::endonym(&current)
            };
            egui::ComboBox::from_id_salt("settings_language")
                .selected_text(selected_text)
                .show_ui(ui, |ui| {
                    if ui
                        .selectable_label(current == SYSTEM_LANGUAGE, l10n.t("gui.system"))
                        .clicked()
                    {
                        action = SettingsAction::SetLanguage(SYSTEM_LANGUAGE.to_owned());
                    }
                    for (code, name) in SUPPORTED_LOCALES {
                        if ui.selectable_label(current == *code, *name).clicked() {
                            action = SettingsAction::SetLanguage((*code).to_owned());
                        }
                    }
                });
        });
    });

    if response.should_close() {
        action = SettingsAction::Close;
    }
    action
}
