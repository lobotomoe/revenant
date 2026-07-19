//! Connect dialog: pick a built-in profile or a custom URL, then ping the
//! server. On success the app persists the profile and the config advances to
//! the "server configured" layer.

use eframe::egui;
use revenant_sign_core::config::{ServerProfile, BUILTIN_PROFILES};

use crate::i18n::Localizer;
use crate::theme;

/// What the app should do after rendering the dialog.
pub(crate) enum ConnectAction {
    None,
    Cancel,
    /// Start pinging the given profile in the background. Boxed because a
    /// [`ServerProfile`] is much larger than the other variants.
    Ping(Box<ServerProfile>),
}

enum Status {
    Idle,
    Pinging,
    Failed(String),
}

/// Persistent state for the connect dialog.
pub(crate) struct ConnectState {
    builtins: Vec<ServerProfile>,
    /// Selected index into `builtins`, or `builtins.len()` for the custom entry.
    selected: usize,
    custom_url: String,
    status: Status,
    /// The profile a ping is running against; also what the app saves on success.
    pub(crate) pending: ServerProfile,
}

impl ConnectState {
    pub(crate) fn new() -> Self {
        let builtins: Vec<ServerProfile> = BUILTIN_PROFILES.values().cloned().collect();
        let pending = builtins
            .first()
            .cloned()
            .expect("at least one built-in profile is always defined");
        Self {
            builtins,
            selected: 0,
            custom_url: String::new(),
            status: Status::Idle,
            pending,
        }
    }

    /// Record that a ping has started against `profile`.
    pub(crate) fn begin_ping(&mut self, profile: ServerProfile) {
        self.pending = profile;
        self.status = Status::Pinging;
    }

    /// Apply a ping result. Success is handled by the app (save + close); this
    /// only needs to surface a failure reason.
    pub(crate) fn on_ping_failed(&mut self, detail: &str) {
        self.status = Status::Failed(detail.to_owned());
    }

    fn custom_index(&self) -> usize {
        self.builtins.len()
    }

    /// Resolve the current selection into a profile to ping, or set a failure
    /// status when the custom URL is invalid.
    fn resolve(&mut self) -> ConnectAction {
        if let Some(profile) = self.builtins.get(self.selected) {
            return ConnectAction::Ping(Box::new(profile.clone()));
        }
        match ServerProfile::custom_default(self.custom_url.trim()) {
            Ok(profile) => ConnectAction::Ping(Box::new(profile)),
            Err(err) => {
                self.status = Status::Failed(err.to_string());
                ConnectAction::None
            }
        }
    }
}

pub(crate) fn show(
    ctx: &egui::Context,
    l10n: &Localizer,
    state: &mut ConnectState,
) -> ConnectAction {
    let mut action = ConnectAction::None;

    let response = egui::Modal::new(egui::Id::new("connect_dialog")).show(ctx, |ui| {
        ui.set_width(360.0);
        ui.heading(l10n.t("gui.connect_to_server"));
        ui.separator();

        for (index, profile) in state.builtins.iter().enumerate() {
            ui.radio_value(&mut state.selected, index, &profile.display_name);
        }
        let custom_index = state.custom_index();
        ui.radio_value(
            &mut state.selected,
            custom_index,
            l10n.t("gui.custom_server"),
        );
        if state.selected == custom_index {
            ui.add(
                egui::TextEdit::singleline(&mut state.custom_url)
                    .hint_text("https://host:port/SAPIWS/DSS.asmx")
                    .desired_width(f32::INFINITY),
            );
        }

        ui.add_space(4.0);
        match &state.status {
            Status::Pinging => {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label(l10n.tf(
                        "gui.connecting_to_url_ellipsis",
                        &[("url", &state.pending.url)],
                    ));
                });
            }
            Status::Failed(detail) => {
                ui.colored_label(theme::ERROR, detail);
            }
            Status::Idle => {}
        }

        ui.separator();
        ui.horizontal(|ui| {
            let busy = matches!(state.status, Status::Pinging);
            let connect_label = format!("{}  {}", crate::icons::CONNECT, l10n.t("gui.connect"));
            if ui
                .add_enabled(!busy, crate::style::primary_button(connect_label))
                .clicked()
            {
                action = state.resolve();
            }
            if ui.button(l10n.t("gui.cancel")).clicked() {
                action = ConnectAction::Cancel;
            }
        });
    });

    // Backdrop click / Escape dismisses, unless a ping was just requested.
    if response.should_close() && !matches!(action, ConnectAction::Ping(_)) {
        action = ConnectAction::Cancel;
    }
    action
}
