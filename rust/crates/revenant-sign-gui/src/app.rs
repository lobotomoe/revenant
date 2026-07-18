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
    register_active_profile_tls, register_profile_tls_mode, ConfigLayer, ConfigStore,
    ServerProfile, SignerInfo,
};
use revenant_sign_core::net::{ping_server, PingOutcome, SoapSigningTransport, Transport};
use revenant_sign_core::pki::{discover_identity_from_server, CertInfo};
use revenant_sign_core::RevenantError;

use crate::i18n::Localizer;
use crate::views::{
    self, ConnectAction, ConnectState, LoginAction, LoginState, SettingsAction, SignAction,
};
use crate::worker::{IdentityOutcome, Worker, WorkerMsg};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Sign,
    Verify,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Dialog {
    Connect,
    Login,
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
    /// Present only while the login wizard is open (needs the active profile).
    login: Option<LoginState>,
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
            login: None,
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
                WorkerMsg::Identity(outcome) => self.on_identity_result(outcome),
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

    /// Open the login wizard for the configured server (requires layer >= 1).
    fn open_login(&mut self) {
        let Some(profile) = self.store.active_profile() else {
            log::error!("cannot open login without a configured server");
            return;
        };
        let saved_username = self.store.saved_username();
        let storage_info = self.store.credential_storage_info();
        self.login = Some(LoginState::new(profile, saved_username, storage_info));
        self.dialog = Some(Dialog::Login);
    }

    /// Discover the signer identity in the background using the entered
    /// credentials against the active profile.
    fn start_discovery(&mut self) {
        let Some(login) = &self.login else { return };
        let Some(profile) = self.store.active_profile() else {
            log::error!("login discovery started without an active profile");
            return;
        };
        // EKENG needs its legacy TLS stack registered before the SOAP call.
        register_active_profile_tls(&self.transport, &self.store);
        let transport = Arc::clone(&self.transport);
        let url = profile.url.clone();
        let timeout = Duration::from_secs(u64::from(profile.timeout));
        let username = login.username().to_owned();
        let password = login.password().to_owned();
        self.worker.spawn(move || {
            let soap = SoapSigningTransport::new(transport, url);
            let outcome = match discover_identity_from_server(&soap, &username, &password, timeout)
            {
                Ok(info) => IdentityOutcome::Ok(Box::new(info)),
                Err(err) => categorize_identity_error(&err),
            };
            WorkerMsg::Identity(outcome)
        });
    }

    fn on_identity_result(&mut self, outcome: IdentityOutcome) {
        // Localize the status line first so the mutable `login` borrow below does
        // not overlap the immutable `l10n` borrow.
        let status = match &outcome {
            IdentityOutcome::Ok(_) => self
                .l10n
                .t("gui.could_not_determine_identity_from_server")
                .to_owned(),
            IdentityOutcome::AuthFailed(detail) => self
                .l10n
                .tf("gui.authentication_failed_error", &[("error", detail)]),
            IdentityOutcome::ServerError(detail) => {
                self.l10n.tf("gui.server_error_error", &[("error", detail)])
            }
            IdentityOutcome::OtherError(detail) => {
                self.l10n.tf("gui.error_error", &[("error", detail)])
            }
        };
        let Some(login) = &mut self.login else { return };
        match outcome {
            IdentityOutcome::Ok(info) => login.on_identity_found(*info, status),
            _ => login.on_discovery_failed(status),
        }
    }

    /// Persist the login result (signer identity + optional credentials) and
    /// close the wizard, advancing the config to the fully-configured layer.
    fn finish_login(&mut self) {
        let Some(login) = self.login.take() else {
            return;
        };
        self.dialog = None;

        if let Some(info) = login.identity() {
            let signer = signer_info_from_cert(info);
            if let Err(err) = self.store.save_signer_info(&signer) {
                log::error!("failed to save signer info: {err}");
            }
        }

        if login.should_save_credentials() {
            if let Err(err) = self
                .store
                .save_credentials(login.username(), login.password())
            {
                log::error!("failed to save credentials: {err}");
            }
        } else if let Err(err) = self.store.clear_credentials() {
            log::error!("failed to clear saved credentials: {err}");
        }

        // Keep the session credentials so signing works without a re-entry.
        self.store
            .set_session_credentials(login.username().to_owned(), login.password().to_owned());
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
                        match views::sign::show(ui, &self.l10n, layer) {
                            SignAction::Connect => self.dialog = Some(Dialog::Connect),
                            SignAction::Login => self.open_login(),
                            SignAction::None => {}
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
            Dialog::Login => {
                let Some(login) = &mut self.login else {
                    self.dialog = None;
                    return;
                };
                match views::login::show(ctx, &self.l10n, login) {
                    LoginAction::Cancel => {
                        self.dialog = None;
                        self.login = None;
                    }
                    LoginAction::Discover => self.start_discovery(),
                    LoginAction::Finish => self.finish_login(),
                    LoginAction::None => {}
                }
            }
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

/// Classify a discovery error so the UI thread can pick the localized message.
fn categorize_identity_error(err: &RevenantError) -> IdentityOutcome {
    let detail = err.to_string();
    match err {
        RevenantError::Auth(_) => IdentityOutcome::AuthFailed(detail),
        RevenantError::Tls { .. } => IdentityOutcome::ServerError(detail),
        _ => IdentityOutcome::OtherError(detail),
    }
}

/// Adapt a discovered certificate into the config store's signer record. Both
/// carry the same fields; the store owns the persisted view.
fn signer_info_from_cert(info: &CertInfo) -> SignerInfo {
    SignerInfo {
        name: info.name.clone(),
        email: info.email.clone(),
        organization: info.organization.clone(),
        dn: info.dn.clone(),
        not_before: info.not_before.clone(),
        not_after: info.not_after.clone(),
    }
}
