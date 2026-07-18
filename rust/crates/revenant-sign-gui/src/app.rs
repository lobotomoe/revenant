//! Top-level application state and the egui update loop.
//!
//! The main window mirrors the Python client's configuration "layers":
//! nothing configured -> server configured -> fully configured (can sign). This
//! scaffold renders that state plus a live language switcher to prove the core
//! and localization wiring; the interactive views are built on top in later
//! phases.

use eframe::egui;
use revenant_sign_core::config::ConfigStore;

use crate::i18n::{Localizer, SUPPORTED_LOCALES};

/// The running GUI application. Owns the persisted [`ConfigStore`] and the
/// active [`Localizer`]; later phases add the shared transport and
/// background-worker channels.
pub(crate) struct RevenantApp {
    store: ConfigStore,
    localizer: Localizer,
}

impl RevenantApp {
    pub(crate) fn new(cc: &eframe::CreationContext<'_>) -> Self {
        crate::fonts::install(&cc.egui_ctx);
        let store = ConfigStore::new();
        let localizer = Localizer::new(&store.language());
        Self { store, localizer }
    }

    /// Persist and apply a new UI language, rebuilding the active catalog.
    fn set_language(&mut self, code: &str) {
        if let Err(err) = self.store.save_language(code) {
            log::error!("failed to persist language '{code}': {err}");
        }
        self.localizer = Localizer::new(code);
    }

    fn language_selector(&mut self, ui: &mut egui::Ui) {
        let current = self.localizer.code().to_owned();
        let selected_name = endonym(&current);
        let mut chosen: Option<String> = None;

        egui::ComboBox::from_id_salt("language")
            .selected_text(selected_name)
            .show_ui(ui, |ui| {
                for (code, name) in SUPPORTED_LOCALES {
                    if ui.selectable_label(current == *code, *name).clicked() {
                        chosen = Some((*code).to_owned());
                    }
                }
            });

        if let Some(code) = chosen {
            if code != current {
                self.set_language(&code);
            }
        }
    }
}

impl eframe::App for RevenantApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::TopBottomPanel::top("top_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("Revenant");
                ui.separator();
                ui.label(self.localizer.t("gui.language_label"));
                self.language_selector(ui);
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            let rtl = self.localizer.is_rtl();
            let layout = if rtl {
                egui::Layout::top_down(egui::Align::Max)
            } else {
                egui::Layout::top_down(egui::Align::Min)
            };
            ui.with_layout(layout, |ui| {
                let layer = self.store.config_layer();
                ui.label(format!("layer: {layer:?} (level {})", layer.as_u8()));
                match self.store.active_profile() {
                    Some(profile) => {
                        ui.label(format!("{} ({})", profile.display_name, profile.url));
                    }
                    None => {
                        ui.label(self.localizer.t("gui.no_server_configured"));
                    }
                }
                ui.separator();

                // Translation smoke test: a few real keys, one interpolated.
                ui.label(self.localizer.t("gui.about_revenant"));
                ui.label(self.localizer.t("gui.account"));
                ui.label(self.localizer.t("gui.browse_ellipsis"));
                ui.label(
                    self.localizer
                        .tf("gui.authentication_failed_error", &[("error", "demo")]),
                );
            });
        });
    }
}

/// The endonym (self-name) for a locale code, or the code itself if unknown.
fn endonym(code: &str) -> &str {
    SUPPORTED_LOCALES
        .iter()
        .find(|(c, _)| *c == code)
        .map_or(code, |(_, name)| name)
}
