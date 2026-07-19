//! Login wizard: a three-step modal (credentials -> identity -> done) that takes
//! the app from a configured server (layer 1) to a full signing identity
//! (layer 2). Mirrors the Python client's `LoginDialog`.
//!
//! Discovery talks to the server and therefore runs on the background worker;
//! this view only renders state and reports intents. The app spawns discovery,
//! folds its result back via [`LoginState::on_identity_found`] /
//! [`LoginState::on_discovery_failed`], and persists everything on `Finish`.

use eframe::egui;
use revenant_sign_core::config::{IdentityMethod, ServerProfile};
use revenant_sign_core::pki::CertInfo;

use crate::i18n::Localizer;
use crate::theme;

const STEP_COUNT: &str = "3";

/// Which wizard page is showing.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Step {
    Credentials,
    Identity,
    Done,
}

/// Progress of background identity discovery.
enum Discovery {
    /// Not started yet.
    Idle,
    /// Running in the background.
    Running,
    /// An identity was obtained (from the server or entered manually).
    Resolved,
    /// Discovery failed; the string is an already-localized status line.
    Failed(String),
    /// The user is entering the identity by hand.
    Manual,
}

/// Manually entered identity fields (fallback when discovery is unavailable).
#[derive(Default)]
struct Manual {
    name: String,
    email: String,
    organization: String,
}

/// What the app should do after rendering the wizard.
pub(crate) enum LoginAction {
    None,
    Cancel,
    /// Run identity discovery in the background with the entered credentials.
    Discover,
    /// Persist credentials (if opted in) and the signer identity, then close.
    Finish,
}

/// Persistent state for the login wizard.
pub(crate) struct LoginState {
    step: Step,
    profile: ServerProfile,
    username: String,
    password: String,
    show_password: bool,
    save_credentials: bool,
    storage_info: String,
    discovery: Discovery,
    /// The identity to save: discovered from the server or built from `manual`.
    identity: Option<CertInfo>,
    manual: Manual,
    /// Inline validation warning for the current step, if any.
    warning: Option<String>,
}

impl LoginState {
    pub(crate) fn new(
        profile: ServerProfile,
        saved_username: Option<String>,
        storage_info: String,
    ) -> Self {
        Self {
            step: Step::Credentials,
            profile,
            username: saved_username.unwrap_or_default(),
            password: String::new(),
            show_password: false,
            save_credentials: true,
            storage_info,
            discovery: Discovery::Idle,
            identity: None,
            manual: Manual::default(),
            warning: None,
        }
    }

    /// The entered username, trimmed of incidental whitespace.
    pub(crate) fn username(&self) -> &str {
        self.username.trim()
    }

    /// The entered password, trimmed of incidental whitespace.
    pub(crate) fn password(&self) -> &str {
        self.password.trim()
    }

    /// Pre-fill the password from saved credentials read in the background. Only
    /// applies while the user is still on the credentials step and has not typed
    /// one, so a slow keychain read never clobbers live input.
    pub(crate) fn prefill_password(&mut self, password: String) {
        if self.step == Step::Credentials && self.password.is_empty() {
            self.password = password;
        }
    }

    pub(crate) fn should_save_credentials(&self) -> bool {
        self.save_credentials
    }

    pub(crate) fn identity(&self) -> Option<&CertInfo> {
        self.identity.as_ref()
    }

    /// Record that a discovery run has started (called by the app before spawn).
    pub(crate) fn begin_discovery(&mut self) {
        self.discovery = Discovery::Running;
        self.identity = None;
        self.warning = None;
    }

    /// Fold in a discovered certificate. A cert without a usable name is treated
    /// as a failure so the user can retry or enter the identity manually;
    /// `empty_status` is the localized line shown in that case.
    pub(crate) fn on_identity_found(&mut self, info: CertInfo, empty_status: String) {
        let has_name = info
            .name
            .as_deref()
            .is_some_and(|name| !name.trim().is_empty());
        if has_name {
            self.identity = Some(info);
            self.discovery = Discovery::Resolved;
        } else {
            self.discovery = Discovery::Failed(empty_status);
        }
    }

    /// Fold in a discovery failure (already localized).
    pub(crate) fn on_discovery_failed(&mut self, status: String) {
        self.discovery = Discovery::Failed(status);
    }

    fn discovery_supported(&self) -> bool {
        self.profile.has_identity_method(IdentityMethod::Server)
    }

    /// Manual entry is only meaningful for profiles without structured cert
    /// fields; those rely on regex extraction that won't match typed input.
    fn manual_supported(&self) -> bool {
        self.profile.cert_fields.is_empty()
    }

    fn step_title<'a>(&self, l10n: &'a Localizer) -> &'a str {
        match self.step {
            Step::Credentials => l10n.t("gui.credentials"),
            Step::Identity => l10n.t("gui.signer_identity"),
            Step::Done => l10n.t("gui.complete"),
        }
    }

    fn step_number(&self) -> u8 {
        match self.step {
            Step::Credentials => 1,
            Step::Identity => 2,
            Step::Done => 3,
        }
    }

    fn next_label<'a>(&self, l10n: &'a Localizer) -> &'a str {
        if self.step == Step::Done {
            l10n.t("gui.save")
        } else {
            l10n.t("gui.next")
        }
    }

    fn next_enabled(&self) -> bool {
        match self.step {
            Step::Credentials | Step::Done => true,
            Step::Identity => matches!(self.discovery, Discovery::Resolved | Discovery::Manual),
        }
    }

    fn build_manual_identity(&self) -> CertInfo {
        let clean = |value: &str| {
            let trimmed = value.trim();
            (!trimmed.is_empty()).then(|| trimmed.to_owned())
        };
        CertInfo {
            name: clean(&self.manual.name),
            email: clean(&self.manual.email),
            organization: clean(&self.manual.organization),
            ..CertInfo::default()
        }
    }

    /// Advance from the current step. May request discovery or finish.
    fn on_next(&mut self, l10n: &Localizer) -> LoginAction {
        match self.step {
            Step::Credentials => self.leave_credentials(l10n),
            Step::Identity => self.leave_identity(l10n),
            Step::Done => LoginAction::Finish,
        }
    }

    fn leave_credentials(&mut self, l10n: &Localizer) -> LoginAction {
        let user = self.username.trim();
        let pass = self.password.trim();
        if user.is_empty() || pass.is_empty() {
            self.warning = Some(l10n.t("gui.username_and_password_are_required").to_owned());
            return LoginAction::None;
        }
        if !user.is_ascii() || !pass.is_ascii() {
            self.warning = Some(
                l10n.t("gui.credentials_must_contain_only_latin_characters_ple_e9a0742d")
                    .to_owned(),
            );
            return LoginAction::None;
        }
        self.warning = None;
        self.step = Step::Identity;
        if self.discovery_supported() {
            self.begin_discovery();
            LoginAction::Discover
        } else {
            self.discovery = Discovery::Manual;
            LoginAction::None
        }
    }

    fn leave_identity(&mut self, l10n: &Localizer) -> LoginAction {
        if matches!(self.discovery, Discovery::Manual) {
            if self.manual.name.trim().is_empty() {
                self.warning = Some(l10n.t("gui.name_is_required").to_owned());
                return LoginAction::None;
            }
            self.identity = Some(self.build_manual_identity());
        }
        if self.identity.is_none() {
            let key = if self.manual_supported() {
                "gui.signer_identity_is_required_click_enter_manually_t_397d205e"
            } else {
                "gui.signer_identity_is_required_retry_the_connection_o_6eb0ccec"
            };
            self.warning = Some(l10n.t(key).to_owned());
            return LoginAction::None;
        }
        self.warning = None;
        self.step = Step::Done;
        LoginAction::None
    }

    fn on_back(&mut self) {
        self.warning = None;
        match self.step {
            Step::Credentials => {}
            Step::Identity => self.step = Step::Credentials,
            Step::Done => self.step = Step::Identity,
        }
    }

    fn body(&mut self, ui: &mut egui::Ui, l10n: &Localizer) -> LoginAction {
        match self.step {
            Step::Credentials => {
                self.credentials_ui(ui, l10n);
                LoginAction::None
            }
            Step::Identity => self.identity_ui(ui, l10n),
            Step::Done => {
                self.done_ui(ui, l10n);
                LoginAction::None
            }
        }
    }

    fn credentials_ui(&mut self, ui: &mut egui::Ui, l10n: &Localizer) {
        if self.profile.max_auth_attempts > 0 {
            let attempts = self.profile.max_auth_attempts.to_string();
            ui.colored_label(
                theme::WARNING,
                l10n.tf(
                    "gui.warning_account_locks_after_max_attempts_failed_attempts",
                    &[("max_attempts", &attempts)],
                ),
            );
            ui.add_space(4.0);
        }
        // A grid pins the label column to a fixed width (the wider of the two
        // labels), so both inputs start at the same x and line up.
        egui::Grid::new("login_credentials")
            .num_columns(2)
            .spacing([8.0, 6.0])
            .show(ui, |ui| {
                ui.label(l10n.t("gui.username_label"));
                ui.add(egui::TextEdit::singleline(&mut self.username).desired_width(f32::INFINITY));
                ui.end_row();

                ui.label(l10n.t("gui.password_label"));
                ui.add(
                    egui::TextEdit::singleline(&mut self.password)
                        .password(!self.show_password)
                        .desired_width(f32::INFINITY),
                );
                ui.end_row();
            });
        ui.checkbox(&mut self.show_password, l10n.t("gui.show_password"));
    }

    fn identity_ui(&mut self, ui: &mut egui::Ui, l10n: &Localizer) -> LoginAction {
        match &self.discovery {
            Discovery::Running => {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label(l10n.t("gui.discovering_signer_identity_ellipsis"));
                });
                return LoginAction::None;
            }
            Discovery::Resolved => {
                ui.colored_label(
                    theme::OK,
                    format!(
                        "{}  {}",
                        crate::icons::SUCCESS,
                        l10n.t("gui.signer_identity_found_label")
                    ),
                );
                if let Some(info) = &self.identity {
                    identity_summary(ui, info);
                }
                return LoginAction::None;
            }
            Discovery::Idle => return LoginAction::None,
            // Failed / Manual need mutable access below; drop the borrow first.
            Discovery::Failed(_) | Discovery::Manual => {}
        }

        if matches!(self.discovery, Discovery::Manual) {
            self.manual_ui(ui, l10n);
            return LoginAction::None;
        }

        // Failed: show the status line, then retry / manual-entry fallbacks.
        if let Discovery::Failed(status) = &self.discovery {
            let status = status.clone();
            ui.colored_label(theme::ERROR, status);
        }
        ui.add_space(6.0);
        let mut action = LoginAction::None;
        ui.horizontal(|ui| {
            if ui.button(l10n.t("gui.retry")).clicked() {
                self.begin_discovery();
                action = LoginAction::Discover;
            }
            if self.manual_supported() && ui.button(l10n.t("gui.enter_manually_ellipsis")).clicked()
            {
                self.discovery = Discovery::Manual;
            }
        });
        action
    }

    fn manual_ui(&mut self, ui: &mut egui::Ui, l10n: &Localizer) {
        ui.label(l10n.t("gui.enter_signer_identity_label"));
        ui.add_space(4.0);
        // Same fixed label column as the credentials step, so the fields align.
        egui::Grid::new("login_manual_identity")
            .num_columns(2)
            .spacing([8.0, 6.0])
            .show(ui, |ui| {
                for (label, value) in [
                    (l10n.t("gui.name_required_label"), &mut self.manual.name),
                    (l10n.t("gui.email_label"), &mut self.manual.email),
                    (
                        l10n.t("gui.organization_label"),
                        &mut self.manual.organization,
                    ),
                ] {
                    ui.label(label);
                    ui.add(egui::TextEdit::singleline(value).desired_width(f32::INFINITY));
                    ui.end_row();
                }
            });
    }

    fn done_ui(&mut self, ui: &mut egui::Ui, l10n: &Localizer) {
        ui.strong(l10n.t("gui.setup_complete_summary_label"));
        ui.add_space(4.0);
        if let Some(name) = self.identity.as_ref().and_then(|info| info.name.as_deref()) {
            ui.label(l10n.tf("gui.signer_name", &[("name", name)]));
        }
        ui.label(l10n.tf(
            "gui.username_username",
            &[("username", self.username.trim())],
        ));
        ui.add_space(4.0);
        ui.checkbox(
            &mut self.save_credentials,
            l10n.t("gui.save_credentials_username_password"),
        );
        ui.colored_label(
            theme::MUTED,
            l10n.tf("gui.storage_storage", &[("storage", &self.storage_info)]),
        );
    }
}

/// Render the discovered identity's fields, each prefixed with an icon (person,
/// envelope, building) in place of a text label.
fn identity_summary(ui: &mut egui::Ui, info: &CertInfo) {
    let mut row = |icon: &str, value: &Option<String>| {
        if let Some(value) = value {
            ui.label(format!("{icon}  {value}"));
        }
    };
    row(crate::icons::NAME, &info.name);
    row(crate::icons::EMAIL, &info.email);
    row(crate::icons::ORG, &info.organization);
}

pub(crate) fn show(ctx: &egui::Context, l10n: &Localizer, state: &mut LoginState) -> LoginAction {
    let mut action = LoginAction::None;

    let response = egui::Modal::new(egui::Id::new("login_dialog")).show(ctx, |ui| {
        ui.set_width(420.0);
        ui.horizontal(|ui| {
            ui.heading(state.step_title(l10n));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let current = state.step_number().to_string();
                ui.colored_label(
                    theme::MUTED,
                    l10n.tf(
                        "gui.step_current_of_total",
                        &[("current", &current), ("total", STEP_COUNT)],
                    ),
                );
            });
        });
        ui.separator();

        let body_action = state.body(ui, l10n);
        if !matches!(body_action, LoginAction::None) {
            action = body_action;
        }

        if let Some(warning) = &state.warning {
            ui.add_space(4.0);
            ui.colored_label(theme::WARNING, warning);
        }

        ui.separator();
        ui.horizontal(|ui| {
            let back_enabled = state.step != Step::Credentials;
            let back_label = format!("{}  {}", crate::icons::ARROW_LEFT, l10n.t("gui.back"));
            if ui
                .add_enabled(back_enabled, egui::Button::new(back_label))
                .clicked()
            {
                state.on_back();
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let next_label =
                    format!("{}  {}", state.next_label(l10n), crate::icons::ARROW_RIGHT);
                if ui
                    .add_enabled(
                        state.next_enabled(),
                        crate::style::primary_button(next_label),
                    )
                    .clicked()
                {
                    action = state.on_next(l10n);
                }
                if ui.button(l10n.t("gui.cancel")).clicked() {
                    action = LoginAction::Cancel;
                }
            });
        });
    });

    // Backdrop click / Escape dismisses, unless a step transition is in flight.
    if response.should_close() && !matches!(action, LoginAction::Discover | LoginAction::Finish) {
        action = LoginAction::Cancel;
    }
    action
}

#[cfg(test)]
mod tests {
    use super::{LoginState, Step};
    use revenant_sign_core::config::ServerProfile;

    fn state() -> LoginState {
        let profile = ServerProfile::builtin("ekeng").expect("ekeng profile");
        LoginState::new(profile, Some("user".to_owned()), "keychain".to_owned())
    }

    #[test]
    fn prefill_fills_empty_password_on_credentials_step() {
        let mut login = state();
        login.prefill_password("secret".to_owned());
        assert_eq!(login.password, "secret");
    }

    #[test]
    fn prefill_skips_when_user_already_typed() {
        let mut login = state();
        login.password = "typed".to_owned();
        login.prefill_password("secret".to_owned());
        assert_eq!(login.password, "typed");
    }

    #[test]
    fn prefill_skips_past_the_credentials_step() {
        let mut login = state();
        login.step = Step::Identity;
        login.prefill_password("secret".to_owned());
        assert!(login.password.is_empty());
    }
}
