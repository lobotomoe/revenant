//! Connect dialog: pick a built-in profile or a custom URL, then ping the
//! server. On success the app persists the profile and the config advances to
//! the "server configured" layer.

use eframe::egui;
use revenant_sign_core::config::{ServerProfile, BUILTIN_PROFILES};

use crate::i18n::Localizer;
use crate::theme;
use crate::worker::RequestId;

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
    /// A ping is in flight. The request and the profile it would save live in
    /// the same variant on purpose: a result can then never be matched against
    /// one and applied to the other.
    Pinging {
        request: RequestId,
        /// Boxed to keep [`Status`] small -- a [`ServerProfile`] dwarfs the
        /// other variants.
        profile: Box<ServerProfile>,
    },
    Failed(String),
}

/// Persistent state for the connect dialog.
pub(crate) struct ConnectState {
    builtins: Vec<ServerProfile>,
    /// Selected index into `builtins`, or `builtins.len()` for the custom entry.
    selected: usize,
    custom_url: String,
    status: Status,
}

impl ConnectState {
    pub(crate) fn new() -> Self {
        let builtins: Vec<ServerProfile> = BUILTIN_PROFILES.values().cloned().collect();
        Self {
            builtins,
            selected: 0,
            custom_url: String::new(),
            status: Status::Idle,
        }
    }

    /// Record that `request` has started pinging `profile`.
    pub(crate) fn begin_ping(&mut self, request: RequestId, profile: ServerProfile) {
        self.status = Status::Pinging {
            request,
            profile: Box::new(profile),
        };
    }

    /// Claim `request`'s result, yielding the profile it pinged.
    ///
    /// `None` means the dialog is no longer waiting for this request -- the user
    /// cancelled it, or a second attempt superseded it. Such a result must not
    /// be shown or persisted: the user already withdrew the question, so
    /// answering it would override their decision (GHSA-285g).
    pub(crate) fn claim_ping(&mut self, request: RequestId) -> Option<ServerProfile> {
        match std::mem::replace(&mut self.status, Status::Idle) {
            Status::Pinging {
                request: inflight,
                profile,
            } if inflight == request => Some(*profile),
            other => {
                self.status = other;
                None
            }
        }
    }

    /// Surface why the connection attempt failed. Only called for a ping already
    /// claimed by [`claim_ping`], so it needs no staleness check of its own.
    pub(crate) fn show_failure(&mut self, detail: &str) {
        self.status = Status::Failed(detail.to_owned());
    }

    /// Abandon any ping in flight, so its result is ignored when it lands.
    pub(crate) fn cancel(&mut self) {
        self.status = Status::Idle;
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
            Status::Pinging { profile, .. } => {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label(l10n.tf("gui.connecting_to_url_ellipsis", &[("url", &profile.url)]));
                });
            }
            Status::Failed(detail) => {
                ui.colored_label(theme::ERROR, detail);
            }
            Status::Idle => {}
        }

        ui.separator();
        ui.horizontal(|ui| {
            let busy = matches!(state.status, Status::Pinging { .. });
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

#[cfg(test)]
mod tests {
    use super::ConnectState;
    use crate::worker::RequestIds;
    use revenant_sign_core::config::ServerProfile;

    fn profile(url: &str) -> ServerProfile {
        ServerProfile::custom_default(url).expect("valid custom URL")
    }

    #[test]
    fn a_completed_ping_yields_the_profile_it_tested() {
        let mut state = ConnectState::new();
        let mut requests = RequestIds::default();
        let request = requests.issue();
        state.begin_ping(request, profile("https://server.example/SAPIWS/DSS.asmx"));

        let claimed = state.claim_ping(request).expect("own result must apply");

        assert_eq!(claimed.url, "https://server.example/SAPIWS/DSS.asmx");
    }

    /// GHSA-285g: the user cancels, then the endpoint's delayed success arrives.
    /// Nothing may come back, because the caller persists whatever it is handed.
    #[test]
    fn a_cancelled_ping_yields_nothing_when_it_finally_succeeds() {
        let mut state = ConnectState::new();
        let mut requests = RequestIds::default();
        let request = requests.issue();
        state.begin_ping(
            request,
            profile("https://attacker-controlled.example/SAPIWS/DSS.asmx"),
        );

        state.cancel();

        assert!(
            state.claim_ping(request).is_none(),
            "a server the user declined must never be persisted"
        );
    }

    /// A second attempt supersedes the first; the abandoned one must not win a
    /// race and save a profile the user moved on from.
    #[test]
    fn a_superseded_ping_yields_nothing() {
        let mut state = ConnectState::new();
        let mut requests = RequestIds::default();
        let first = requests.issue();
        state.begin_ping(first, profile("https://first.example/SAPIWS/DSS.asmx"));
        let second = requests.issue();
        state.begin_ping(second, profile("https://second.example/SAPIWS/DSS.asmx"));

        assert!(state.claim_ping(first).is_none());

        let claimed = state.claim_ping(second).expect("current result must apply");
        assert_eq!(claimed.url, "https://second.example/SAPIWS/DSS.asmx");
    }

    /// Claiming is one-shot: a duplicated message cannot re-save a profile after
    /// the dialog has moved on.
    #[test]
    fn a_ping_can_only_be_claimed_once() {
        let mut state = ConnectState::new();
        let mut requests = RequestIds::default();
        let request = requests.issue();
        state.begin_ping(request, profile("https://server.example/SAPIWS/DSS.asmx"));

        assert!(state.claim_ping(request).is_some());
        assert!(state.claim_ping(request).is_none());
    }
}
