//! Top-level application state and the egui update loop.
//!
//! The window mirrors the Python client's configuration "layers": nothing
//! configured -> server configured -> fully configured (can sign). The shell
//! (a server bar, Sign/Verify tabs, and a footer) stays constant; the Sign tab
//! swaps content by layer. Long-running work runs on the [`Worker`] and its
//! results are folded back in on the UI thread.

use std::sync::Arc;
use std::time::Duration;

use eframe::egui;
use revenant_sign_core::config::{
    register_active_profile_tls, register_profile_tls_mode, ConfigLayer, ConfigStore, ServerProfile,
};
use revenant_sign_core::net::{ping_server, PingOutcome, Transport};

use crate::i18n::Localizer;
use crate::views::{self, ConnectAction, ConnectState, SettingsAction, SignAction};
use crate::worker::{Worker, WorkerMsg};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Sign,
    Verify,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Dialog {
    Connect,
    Settings,
    About,
}

/// The running GUI application.
pub(crate) struct RevenantApp {
    store: ConfigStore,
    transport: Arc<Transport>,
    l10n: Localizer,
    worker: Worker,
    tab: Tab,
    dialog: Option<Dialog>,
    connect: ConnectState,
}

impl RevenantApp {
    pub(crate) fn new(cc: &eframe::CreationContext<'_>) -> Self {
        crate::fonts::install(&cc.egui_ctx);
        let store = ConfigStore::new();
        let l10n = Localizer::new(&store.language());
        let transport = Arc::new(Transport::new());
        // Register the saved profile's TLS mode so pings and signing use the
        // right stack (EKENG needs the legacy TLS 1.0 path).
        register_active_profile_tls(&transport, &store);
        let worker = Worker::new(cc.egui_ctx.clone());
        Self {
            store,
            transport,
            l10n,
            worker,
            tab: Tab::Sign,
            dialog: None,
            connect: ConnectState::new(),
        }
    }

    /// Persist and apply a new UI language, rebuilding the active catalog.
    fn set_language(&mut self, code: &str) {
        if let Err(err) = self.store.save_language(code) {
            log::error!("failed to persist language '{code}': {err}");
        }
        self.l10n = Localizer::new(code);
    }

    /// Fold completed background jobs back into the UI state.
    fn process_worker_results(&mut self) {
        for msg in self.worker.drain() {
            match msg {
                WorkerMsg::Ping { ok, detail } => self.on_ping_result(ok, &detail),
            }
        }
    }

    fn on_ping_result(&mut self, ok: bool, detail: &str) {
        if !ok {
            self.connect.on_ping_failed(detail);
            return;
        }
        match self.store.save_server_config(&self.connect.pending) {
            Ok(()) => {
                register_active_profile_tls(&self.transport, &self.store);
                self.dialog = None;
            }
            Err(err) => self.connect.on_ping_failed(&err.to_string()),
        }
    }

    /// Register the profile's TLS mode and ping it in the background.
    fn start_ping(&mut self, profile: ServerProfile) {
        register_profile_tls_mode(&self.transport, &profile);
        let transport = Arc::clone(&self.transport);
        let url = profile.url.clone();
        let timeout = Duration::from_secs(u64::from(profile.timeout));
        self.connect.begin_ping(profile);
        self.worker.spawn(move || {
            let (ok, detail) = match ping_server(&transport, &url, timeout) {
                PingOutcome::Ok(detail) => (true, detail),
                PingOutcome::Failed(detail) => (false, detail),
            };
            WorkerMsg::Ping { ok, detail }
        });
    }

    fn top_bar(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("server_bar").show(ctx, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.heading("Revenant");
                ui.separator();
                if self.store.config_layer() == ConfigLayer::Unconfigured {
                    ui.label(self.l10n.t("gui.no_server_configured"));
                    if ui.button(self.l10n.t("gui.connect")).clicked() {
                        self.dialog = Some(Dialog::Connect);
                    }
                } else {
                    let name = self
                        .store
                        .active_profile()
                        .map(|p| p.display_name)
                        .unwrap_or_default();
                    ui.label(name);
                    if ui.button(self.l10n.t("gui.disconnect")).clicked() {
                        if let Err(err) = self.store.reset_all() {
                            log::error!("failed to reset config: {err}");
                        }
                    }
                }
            });
            ui.add_space(4.0);
        });
    }

    fn footer(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::bottom("footer").show(ctx, |ui| {
            ui.add_space(2.0);
            ui.horizontal(|ui| {
                if ui.button(self.l10n.t("gui.settings")).clicked() {
                    self.dialog = Some(Dialog::Settings);
                }
                if ui.button(self.l10n.t("gui.about_revenant")).clicked() {
                    self.dialog = Some(Dialog::About);
                }
            });
            ui.add_space(2.0);
        });
    }

    fn central(&mut self, ctx: &egui::Context) {
        // Right-align content for right-to-left locales (e.g. Persian). Full
        // widget mirroring is a later polish step; this matches the previous
        // client's right-aligned RTL treatment.
        let align = if self.l10n.is_rtl() {
            egui::Align::Max
        } else {
            egui::Align::Min
        };
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.with_layout(egui::Layout::top_down(align), |ui| {
                ui.horizontal(|ui| {
                    ui.selectable_value(&mut self.tab, Tab::Sign, self.l10n.t("gui.sign"));
                    ui.selectable_value(&mut self.tab, Tab::Verify, self.l10n.t("gui.verify"));
                });
                ui.separator();
                match self.tab {
                    Tab::Sign => {
                        let layer = self.store.config_layer();
                        if let SignAction::Connect = views::sign::show(ui, &self.l10n, layer) {
                            self.dialog = Some(Dialog::Connect);
                        }
                    }
                    Tab::Verify => views::verify::show(ui, &self.l10n),
                }
            });
        });
    }

    fn dialogs(&mut self, ctx: &egui::Context) {
        let Some(dialog) = self.dialog else {
            return;
        };
        match dialog {
            Dialog::Connect => match views::connect::show(ctx, &self.l10n, &mut self.connect) {
                ConnectAction::Cancel => self.dialog = None,
                ConnectAction::Ping(profile) => self.start_ping(*profile),
                ConnectAction::None => {}
            },
            Dialog::Settings => match views::settings::show(ctx, &self.l10n, &self.store) {
                SettingsAction::Close => self.dialog = None,
                SettingsAction::SetLanguage(code) => self.set_language(&code),
                SettingsAction::None => {}
            },
            Dialog::About => {
                if views::about::show(ctx, &self.l10n) {
                    self.dialog = None;
                }
            }
        }
    }
}

impl eframe::App for RevenantApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.process_worker_results();
        self.top_bar(ctx);
        self.footer(ctx);
        self.central(ctx);
        self.dialogs(ctx);
    }
}
