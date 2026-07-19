//! Top-level application state and the egui update loop.
//!
//! The window mirrors the Python client's configuration "layers": nothing
//! configured -> server configured -> fully configured (can sign). The shell
//! (a server bar, Sign/Verify tabs, and a footer) stays constant; the Sign tab
//! swaps content by layer. Long-running work runs on the [`Worker`] and its
//! results are folded back in on the UI thread.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use eframe::egui;
use revenant_sign_core::appearance::DEFAULT_FONT;
use revenant_sign_core::config::{
    register_active_profile_tls, register_profile_tls_mode, ConfigLayer, ConfigStore,
    ServerProfile, TrustAnchors,
};
use revenant_sign_core::net::{ping_server, PingOutcome, SoapSigningTransport, Transport};
use revenant_sign_core::pki::discover_identity_from_server;

use crate::i18n::Localizer;
use crate::jobs;
use crate::reveal;
use crate::theme;
use crate::views::{
    self, AccountAction, ConnectAction, ConnectState, LoginAction, LoginState, SettingsAction,
    SignAction, SignForm, VerifyAction, VerifyState,
};
use crate::worker::{IdentityOutcome, SignedOutcome, VerifyOutcome, Worker, WorkerMsg};

/// PDF extension accepted by the file picker and drag-and-drop.
const PDF_EXTENSION: &str = "pdf";

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

/// A destructive action awaiting confirmation.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Confirm {
    /// Reset all configuration (server, credentials, identity).
    Disconnect,
    /// Clear credentials and identity, keeping the server.
    LogOut,
}

/// The running GUI application.
pub(crate) struct RevenantApp {
    // Shared behind an `Arc` so background signing jobs can resolve credentials
    // and sign off the UI thread. `ConfigStore` is `Send + Sync`.
    store: Arc<ConfigStore>,
    transport: Arc<Transport>,
    l10n: Localizer,
    worker: Worker,
    tab: Tab,
    dialog: Option<Dialog>,
    connect: ConnectState,
    /// Present only while the login wizard is open (needs the active profile).
    login: Option<LoginState>,
    sign_form: SignForm,
    verify: VerifyState,
    /// A destructive action awaiting the user's confirmation, if any.
    confirm: Option<Confirm>,
    /// Set to request cancellation of the in-progress batch (checked between
    /// files by the worker).
    batch_cancel: Arc<AtomicBool>,
}

impl RevenantApp {
    pub(crate) fn new(cc: &eframe::CreationContext<'_>) -> Self {
        crate::fonts::install(&cc.egui_ctx);
        crate::style::install(&cc.egui_ctx);
        let store = Arc::new(ConfigStore::new());
        let l10n = Localizer::new(&store.language());
        let transport = Arc::new(Transport::new());
        // Register the saved profile's TLS mode so pings and signing use the
        // right stack (EKENG needs the legacy TLS 1.0 path).
        register_active_profile_tls(&transport, &store);
        let worker = Worker::new(cc.egui_ctx.clone());
        // Default the appearance font to the configured profile's font.
        let default_font = store
            .active_profile()
            .map_or_else(|| DEFAULT_FONT.to_owned(), |profile| profile.font);
        Self {
            store,
            transport,
            l10n,
            worker,
            tab: Tab::Sign,
            dialog: None,
            connect: ConnectState::new(),
            login: None,
            sign_form: SignForm::new(default_font),
            verify: VerifyState::new(),
            confirm: None,
            batch_cancel: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Persist and apply a new UI language, rebuilding the active catalog.
    fn set_language(&mut self, code: &str) {
        if let Err(err) = self.store.save_language(code) {
            log::error!("failed to persist language '{code}': {err}");
        }
        self.l10n = Localizer::new(code);
        // Drop any result line frozen in the previous language.
        self.sign_form.reset_result();
    }

    /// Fold completed background jobs back into the UI state.
    fn process_worker_results(&mut self) {
        for msg in self.worker.drain() {
            match msg {
                WorkerMsg::Ping { ok, detail } => self.on_ping_result(ok, &detail),
                WorkerMsg::Identity(outcome) => self.on_identity_result(outcome),
                WorkerMsg::SavedPassword(password) => self.on_saved_password(password),
                WorkerMsg::Signed(outcome) => self.on_signed(outcome),
                WorkerMsg::Verified(outcome) => self.on_verified(outcome),
                WorkerMsg::BatchProgress {
                    current,
                    total,
                    filename,
                } => self.sign_form.on_batch_progress(current, total, filename),
                WorkerMsg::BatchDone {
                    succeeded,
                    failed,
                    aborted,
                } => self.on_batch_done(succeeded, failed, aborted),
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
        let has_saved_credentials = saved_username.is_some();
        let storage_info = self.store.credential_storage_info();
        self.login = Some(LoginState::new(profile, saved_username, storage_info));
        self.dialog = Some(Dialog::Login);
        // Pre-fill the saved password in the background: keychain reads can
        // block or prompt, and the result only lands if the user has not begun
        // typing (see `LoginState::prefill_password`).
        if has_saved_credentials {
            let store = Arc::clone(&self.store);
            self.worker.spawn(move || {
                let password = store
                    .get_credentials()
                    .password
                    .map(|secret| secret.expose().to_owned());
                WorkerMsg::SavedPassword(password)
            });
        }
    }

    fn on_saved_password(&mut self, password: Option<String>) {
        if let (Some(login), Some(password)) = (self.login.as_mut(), password) {
            login.prefill_password(password);
        }
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
                Err(err) => jobs::categorize_identity_error(&err),
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
            let signer = jobs::signer_info_from_cert(info);
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

    /// Native picker for the input PDF(s) (blocking, on the UI thread as
    /// required). Multiple selections switch the form to batch mode.
    fn browse_pdf(&mut self) {
        if let Some(paths) = rfd::FileDialog::new()
            .add_filter(self.l10n.t("gui.pdf_files"), &[PDF_EXTENSION])
            .pick_files()
        {
            self.sign_form.set_files(paths);
        }
    }

    fn browse_image(&mut self) {
        if let Some(path) = rfd::FileDialog::new()
            .add_filter(self.l10n.t("gui.images"), &["png", "jpg", "jpeg"])
            .pick_file()
        {
            self.sign_form.set_image(&path);
        }
    }

    fn browse_output(&mut self) {
        let mut dialog = rfd::FileDialog::new();
        if let Some(default) = self.sign_form.default_output() {
            if let Some(name) = default.file_name() {
                dialog = dialog.set_file_name(name.to_string_lossy());
            }
            if let Some(dir) = default.parent() {
                dialog = dialog.set_directory(dir);
            }
        }
        if let Some(path) = dialog.save_file() {
            self.sign_form.set_output(&path);
        }
    }

    /// Accept PDFs dropped anywhere on the window (the drag-and-drop entry point
    /// the Python client lacks). Files load into the active tab's input; the
    /// Sign tab accepts several at once (batch), the Verify tab takes the first.
    fn handle_dropped_files(&mut self, ctx: &egui::Context) {
        let dropped: Vec<PathBuf> = ctx.input(|i| {
            i.raw
                .dropped_files
                .iter()
                .filter_map(|file| file.path.clone())
                .collect()
        });
        if dropped.is_empty() {
            return;
        }
        match self.tab {
            Tab::Sign => self.route_sign_drop(dropped),
            Tab::Verify => {
                if let Some(first) = dropped.iter().find(|path| is_pdf(path)) {
                    self.verify.set_pdf(first);
                }
            }
        }
    }

    /// Route files dropped on the Sign tab by type, not pointer position (macOS
    /// gives no cursor position during an external drag): an image becomes the
    /// stamp, PDFs become the input. Both can arrive in one drop.
    fn route_sign_drop(&mut self, dropped: Vec<PathBuf>) {
        if let Some(image) = dropped.iter().find(|path| is_image(path)) {
            self.sign_form.set_image(image);
        }
        let pdfs: Vec<PathBuf> = dropped.into_iter().filter(|path| is_pdf(path)).collect();
        if !pdfs.is_empty() {
            self.sign_form.set_files(pdfs);
        }
    }

    /// Validate the form and sign the PDF in the background.
    fn start_sign(&mut self) {
        if self.sign_form.pdf_path().is_empty() {
            let message = self.l10n.t("gui.please_select_a_pdf_file").to_owned();
            self.sign_form.on_signed_failed(message);
            return;
        }
        let Some(output) = self.sign_form.resolved_output() else {
            return;
        };
        let pdf_path = PathBuf::from(self.sign_form.pdf_path());
        let detached = self.sign_form.is_detached();
        let options = self.sign_form.embedded_options();
        // Localize the "no credentials" fallback here; the worker cannot.
        let no_creds = self
            .l10n
            .t("gui.server_connected_log_in_to_sign_documents")
            .to_owned();
        let store = Arc::clone(&self.store);
        let transport = Arc::clone(&self.transport);
        self.sign_form.begin_signing();
        self.worker.spawn(move || {
            let outcome = jobs::sign(
                &store, &transport, &pdf_path, &output, detached, options, no_creds,
            );
            WorkerMsg::Signed(outcome)
        });
    }

    fn on_signed(&mut self, outcome: SignedOutcome) {
        match outcome {
            SignedOutcome::Ok { path, size } => {
                let filename = path
                    .file_name()
                    .map(|name| name.to_string_lossy().into_owned())
                    .unwrap_or_default();
                let human = jobs::format_bytes(size);
                let message = self.l10n.tf(
                    "gui.signed_filename_size",
                    &[("filename", &filename), ("size", &human)],
                );
                self.sign_form.on_signed_ok(message);
                reveal::in_file_manager(&path);
            }
            SignedOutcome::Failed(detail) => {
                let message = crate::friendly::friendly(&self.l10n, &detail);
                self.sign_form.on_signed_failed(message);
            }
        }
    }

    /// Sign every queued file in the background, reporting per-file progress.
    fn start_batch(&mut self) {
        let files = self.sign_form.batch_files();
        if files.is_empty() {
            return;
        }
        let detached = self.sign_form.is_detached();
        let options = self.sign_form.embedded_options();
        let no_creds = self
            .l10n
            .t("gui.server_connected_log_in_to_sign_documents")
            .to_owned();
        let store = Arc::clone(&self.store);
        let transport = Arc::clone(&self.transport);
        self.batch_cancel.store(false, Ordering::Relaxed);
        let cancel = Arc::clone(&self.batch_cancel);
        self.sign_form.begin_batch();
        self.worker.spawn_batch(move |emit| {
            let ctx = jobs::BatchContext {
                store: &store,
                transport: &transport,
                detached,
                options: &options,
                no_credentials_message: &no_creds,
            };
            jobs::batch_sign(emit, &ctx, &files, &cancel);
        });
    }

    fn on_batch_done(&mut self, succeeded: usize, failed: usize, aborted: Option<String>) {
        let (message, ok) = match aborted {
            Some(reason) => (crate::friendly::friendly(&self.l10n, &reason), false),
            None => (
                self.l10n.tf(
                    "gui.batch_complete_succeeded_failed",
                    &[
                        ("succeeded", &succeeded.to_string()),
                        ("failed", &failed.to_string()),
                    ],
                ),
                failed == 0,
            ),
        };
        self.sign_form.on_batch_done(message, ok);
    }

    fn browse_verify_pdf(&mut self) {
        if let Some(path) = rfd::FileDialog::new()
            .add_filter(self.l10n.t("gui.pdf_files"), &[PDF_EXTENSION])
            .pick_file()
        {
            self.verify.set_pdf(&path);
        }
    }

    /// Verify the selected PDF offline, plus server-side when configured.
    fn start_verify(&mut self) {
        if self.verify.pdf_path().is_empty() {
            let message = self.l10n.t("gui.please_select_a_pdf_file").to_owned();
            self.verify.on_failed(message);
            return;
        }
        let pdf_path = PathBuf::from(self.verify.pdf_path());
        // Register the profile TLS mode so the (optional) server verify connects.
        register_active_profile_tls(&self.transport, &self.store);
        let trust = self
            .store
            .active_profile()
            .map_or(TrustAnchors::None, |profile| profile.trust);
        let server = self.store.server_config();
        let transport = Arc::clone(&self.transport);
        self.verify.begin();
        self.worker.spawn(move || {
            let outcome = jobs::verify(&transport, &pdf_path, &trust, server.as_ref());
            WorkerMsg::Verified(outcome)
        });
    }

    fn on_verified(&mut self, outcome: VerifyOutcome) {
        match outcome {
            VerifyOutcome::ReadError(message) => self.verify.on_failed(message),
            VerifyOutcome::Done { local, server } => self.verify.on_done(local, server),
        }
    }

    fn top_bar(&mut self, ui: &mut egui::Ui) {
        egui::Panel::top("server_bar").show_inside(ui, |ui| {
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
                        self.confirm = Some(Confirm::Disconnect);
                    }
                }
            });
            ui.add_space(4.0);
        });
    }

    fn footer(&mut self, ui: &mut egui::Ui) {
        egui::Panel::bottom("footer").show_inside(ui, |ui| {
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

    fn central(&mut self, ui: &mut egui::Ui) {
        // Right-align content for right-to-left locales (e.g. Persian). Full
        // widget mirroring is a later polish step; this matches the previous
        // client's right-aligned RTL treatment.
        let align = if self.l10n.is_rtl() {
            egui::Align::Max
        } else {
            egui::Align::Min
        };
        // Collect the tab intent and act on it after the panel closes, so a
        // blocking file dialog never runs mid-layout with a form borrowed.
        let mut sign_action = SignAction::None;
        let mut verify_action = VerifyAction::None;
        let mut account_action = AccountAction::None;
        egui::CentralPanel::default().show_inside(ui, |ui| {
            ui.with_layout(egui::Layout::top_down(align), |ui| {
                ui.horizontal(|ui| {
                    ui.selectable_value(&mut self.tab, Tab::Sign, self.l10n.t("gui.sign"));
                    ui.selectable_value(&mut self.tab, Tab::Verify, self.l10n.t("gui.verify"));
                });
                ui.separator();
                // Scroll when content (account panel + form, or long verify
                // results) exceeds the window, so nothing clips on small sizes.
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| match self.tab {
                        Tab::Sign => {
                            let layer = self.store.config_layer();
                            // The account panel is rendered inside the sign view
                            // (its right column) at the fully-configured layer.
                            let screen = views::sign::show(
                                ui,
                                &self.l10n,
                                layer,
                                &mut self.sign_form,
                                &self.store,
                            );
                            sign_action = screen.sign;
                            account_action = screen.account;
                        }
                        Tab::Verify => {
                            verify_action = views::verify::show(ui, &self.l10n, &mut self.verify);
                        }
                    });
            });
        });
        self.apply_account_action(&account_action);
        self.apply_sign_action(&sign_action);
        self.apply_verify_action(&verify_action);
    }

    fn apply_sign_action(&mut self, action: &SignAction) {
        match action {
            SignAction::None => {}
            SignAction::Connect => self.dialog = Some(Dialog::Connect),
            SignAction::Login => self.open_login(),
            SignAction::BrowsePdf => self.browse_pdf(),
            SignAction::BrowseImage => self.browse_image(),
            SignAction::BrowseOutput => self.browse_output(),
            SignAction::Sign => {
                if self.sign_form.is_batch() {
                    self.start_batch();
                } else {
                    self.start_sign();
                }
            }
            SignAction::CancelBatch => self.batch_cancel.store(true, Ordering::Relaxed),
        }
    }

    fn apply_account_action(&mut self, action: &AccountAction) {
        match action {
            AccountAction::None => {}
            AccountAction::LogOut => self.confirm = Some(Confirm::LogOut),
        }
    }

    fn apply_verify_action(&mut self, action: &VerifyAction) {
        match action {
            VerifyAction::None => {}
            VerifyAction::BrowsePdf => self.browse_verify_pdf(),
            VerifyAction::Verify => self.start_verify(),
        }
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

    /// Render the pending destructive-action confirmation, if any, and carry it
    /// out only when the user confirms.
    fn confirm_dialog(&mut self, ctx: &egui::Context) {
        let Some(kind) = self.confirm else {
            return;
        };
        let message = self.confirm_message(kind);
        let confirm_label = match kind {
            Confirm::Disconnect => self.l10n.t("gui.disconnect").to_owned(),
            Confirm::LogOut => self.l10n.t("gui.log_out").to_owned(),
        };
        let cancel_label = self.l10n.t("gui.cancel").to_owned();

        // `Some(true)` proceeds, `Some(false)` cancels.
        let mut decision = None;
        let response = egui::Modal::new(egui::Id::new("confirm_dialog")).show(ctx, |ui| {
            ui.set_width(360.0);
            ui.label(message);
            ui.add_space(12.0);
            ui.separator();
            ui.horizontal(|ui| {
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let confirm =
                        egui::Button::new(egui::RichText::new(&confirm_label).color(theme::ERROR));
                    if ui.add(confirm).clicked() {
                        decision = Some(true);
                    }
                    if ui.button(&cancel_label).clicked() {
                        decision = Some(false);
                    }
                });
            });
        });
        if response.should_close() {
            decision = Some(false);
        }
        if let Some(proceed) = decision {
            self.confirm = None;
            if proceed {
                self.run_confirmed(kind);
            }
        }
    }

    /// The confirmation prompt text for a destructive action.
    fn confirm_message(&self, kind: Confirm) -> String {
        match kind {
            Confirm::Disconnect => {
                let name = self
                    .store
                    .active_profile()
                    .map(|profile| profile.display_name)
                    .unwrap_or_default();
                let mut message = self.l10n.tf("gui.disconnect_from_name", &[("name", &name)]);
                // Disconnecting from a fully-configured profile also wipes the
                // saved identity, so warn about it.
                if self.store.config_layer() == ConfigLayer::FullyConfigured {
                    message.push_str("\n\n");
                    message.push_str(
                        self.l10n
                            .t("gui.this_will_also_remove_your_credentials_and_signer_identity"),
                    );
                }
                message
            }
            Confirm::LogOut => self
                .l10n
                .t("gui.log_out_server_connection_will_be_preserved")
                .to_owned(),
        }
    }

    /// Execute a confirmed destructive action.
    fn run_confirmed(&mut self, kind: Confirm) {
        let result = match kind {
            Confirm::Disconnect => self.store.reset_all(),
            Confirm::LogOut => self.store.logout(),
        };
        if let Err(err) = result {
            log::error!("confirmed action failed: {err}");
        }
    }
}

impl eframe::App for RevenantApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        // egui 0.34's UI-first entrypoint hands us the root `Ui`; panels attach
        // to it via `show_inside`. The context (cheap to clone -- it is an Arc)
        // still drives input polling and top-level dialogs.
        let ctx = ui.ctx().clone();
        self.process_worker_results();
        self.handle_dropped_files(&ctx);
        self.top_bar(ui);
        self.footer(ui);
        self.central(ui);
        self.dialogs(&ctx);
        self.confirm_dialog(&ctx);
    }
}

/// Whether a dropped/selected path looks like a PDF (case-insensitive extension).
fn is_pdf(path: &Path) -> bool {
    crate::style::path_has_extension(Some(path), crate::style::PDF_EXTS)
}

/// Whether a dropped path looks like a supported stamp image.
fn is_image(path: &Path) -> bool {
    crate::style::path_has_extension(Some(path), crate::style::IMAGE_EXTS)
}
