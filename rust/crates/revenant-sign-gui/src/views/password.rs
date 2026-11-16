//! Change-password dialog: the new password entered twice, then the result.
//!
//! The current password is not asked for. It is the one the app already signs
//! with, and a retyped copy would only add a way to mistype it, which the
//! server counts toward the account lockout.

use eframe::egui;

use crate::dialog::{ButtonLayout, DialogButton, DialogFrame, Role};
use crate::form::Form;
use crate::i18n::Localizer;
use crate::theme;
use crate::worker::RequestId;

const DIALOG_WIDTH: f32 = 400.0;

/// What the app should do after rendering the dialog.
pub(crate) enum PasswordAction {
    None,
    Close,
    /// Send the entered password to the server.
    Submit,
}

/// How a finished change is presented.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Finish {
    /// The new password is in force and every stored copy follows it.
    Changed,
    /// The change ended in a state the user has to act on.
    NeedsAttention,
}

enum Status {
    Editing,
    /// The request is in flight. The dialog cannot be dismissed meanwhile: the
    /// answer says which password is valid, and the user must see it.
    Working(RequestId),
    Finished {
        message: String,
        finish: Finish,
    },
}

/// State of the change-password dialog.
pub(crate) struct PasswordState {
    /// The profile issues ASCII-only credentials (see `ServerProfile`).
    ascii_only: bool,
    new_password: String,
    repeat: String,
    show_password: bool,
    status: Status,
    /// Why the last attempt did not go through, shown under the form.
    error: Option<String>,
}

impl PasswordState {
    pub(crate) fn new(ascii_only: bool) -> Self {
        Self {
            ascii_only,
            new_password: String::new(),
            repeat: String::new(),
            show_password: false,
            status: Status::Editing,
            error: None,
        }
    }

    /// The entered password, trimmed the way the login form trims the one it
    /// reads, so what is sent is what can be typed back in.
    pub(crate) fn new_password(&self) -> &str {
        self.new_password.trim()
    }

    /// Record that `request` is carrying this dialog's password to the server.
    pub(crate) fn begin(&mut self, request: RequestId) {
        self.error = None;
        self.status = Status::Working(request);
    }

    /// Whether `request` is the one this dialog is waiting for.
    pub(crate) fn is_waiting_for(&self, request: RequestId) -> bool {
        matches!(self.status, Status::Working(inflight) if inflight == request)
    }

    /// The change did not happen: back to the form, with the reason.
    pub(crate) fn fail(&mut self, message: String) {
        self.status = Status::Editing;
        self.error = Some(message);
    }

    /// The change is over: drop the typed passwords and show the result.
    pub(crate) fn finish(&mut self, message: String, finish: Finish) {
        self.new_password.clear();
        self.repeat.clear();
        self.status = Status::Finished { message, finish };
    }

    /// Check what can be checked without the server. `None` means ready to send.
    fn problem<'a>(&self, l10n: &'a Localizer) -> Option<&'a str> {
        let new_password = self.new_password.trim();
        if new_password.is_empty() {
            return Some(l10n.t("gui.enter_a_new_password"));
        }
        if new_password != self.repeat.trim() {
            return Some(l10n.t("gui.the_two_passwords_do_not_match"));
        }
        if self.ascii_only && !new_password.is_ascii() {
            return Some(l10n.t("gui.new_password_latin_only"));
        }
        None
    }

    fn on_submit(&mut self, l10n: &Localizer) -> PasswordAction {
        if let Some(problem) = self.problem(l10n) {
            self.error = Some(problem.to_owned());
            return PasswordAction::None;
        }
        PasswordAction::Submit
    }

    fn form_ui(&mut self, ui: &mut egui::Ui, l10n: &Localizer) {
        let working = matches!(self.status, Status::Working(_));
        let new_label = l10n.t("gui.new_password_label");
        let repeat_label = l10n.t("gui.repeat_new_password_label");
        let form = Form::new(ui, &[new_label, repeat_label]);
        ui.add_enabled_ui(!working, |ui| {
            for (label, value) in [
                (new_label, &mut self.new_password),
                (repeat_label, &mut self.repeat),
            ] {
                form.row(ui, Some(label), |ui| {
                    ui.add(
                        egui::TextEdit::singleline(value)
                            .password(!self.show_password)
                            .desired_width(f32::INFINITY),
                    );
                });
            }
            form.row(ui, None, |ui| {
                crate::style::checkbox(ui, &mut self.show_password, l10n.t("gui.show_password"));
            });
        });
        if working {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(l10n.t("gui.changing_password_ellipsis"));
            });
        } else if let Some(error) = &self.error {
            ui.colored_label(theme::ERROR, error);
        }
    }
}

#[derive(Clone, Copy)]
enum Choice {
    Submit,
    Close,
}

pub(crate) fn show(
    ctx: &egui::Context,
    l10n: &Localizer,
    state: &mut PasswordState,
    layout: ButtonLayout,
) -> PasswordAction {
    let buttons = match state.status {
        Status::Editing | Status::Working(_) => {
            let idle = matches!(state.status, Status::Editing);
            vec![
                DialogButton::new(l10n.t("gui.change_password"), Role::Default, Choice::Submit)
                    .enabled(idle),
                DialogButton::new(l10n.t("gui.cancel"), Role::Cancel, Choice::Close).enabled(idle),
            ]
        }
        Status::Finished { .. } => vec![DialogButton::new(
            l10n.t("gui.close"),
            Role::Default,
            Choice::Close,
        )],
    };

    let ((), choice) = DialogFrame::new("password_dialog", DIALOG_WIDTH, layout)
        .title(l10n.t("gui.change_password"))
        .show(ctx, &buttons, |ui| match &state.status {
            Status::Finished { message, finish } => {
                let color = match finish {
                    Finish::Changed => theme::OK,
                    Finish::NeedsAttention => theme::WARNING,
                };
                ui.colored_label(color, message);
            }
            Status::Editing | Status::Working(_) => state.form_ui(ui, l10n),
        });

    match choice {
        Some(Choice::Submit) => state.on_submit(l10n),
        Some(Choice::Close) => PasswordAction::Close,
        None => PasswordAction::None,
    }
}

#[cfg(test)]
mod tests {
    use super::{Finish, PasswordAction, PasswordState, Status};
    use crate::i18n::Localizer;
    use crate::worker::RequestIds;

    fn typed(ascii_only: bool, new_password: &str, repeat: &str) -> PasswordState {
        let mut state = PasswordState::new(ascii_only);
        state.new_password = new_password.to_owned();
        state.repeat = repeat.to_owned();
        state
    }

    fn submit(state: &mut PasswordState) -> bool {
        let l10n = Localizer::new("en");
        matches!(state.on_submit(&l10n), PasswordAction::Submit)
    }

    #[test]
    fn matching_passwords_are_submitted_trimmed() {
        let mut state = typed(true, " Secret-123 ", "Secret-123");
        assert!(submit(&mut state));
        assert_eq!(state.new_password(), "Secret-123");
    }

    #[test]
    fn an_empty_or_mismatched_entry_is_not_submitted() {
        let mut empty = typed(false, "  ", "");
        assert!(!submit(&mut empty));
        assert!(empty.error.is_some());

        let mut mismatched = typed(false, "Secret-123", "Secret-124");
        assert!(!submit(&mut mismatched));
        assert!(mismatched.error.is_some());
    }

    /// The login form of an ASCII-only profile refuses non-ASCII credentials,
    /// so such a password would lock its owner out of the app.
    #[test]
    fn an_ascii_only_profile_refuses_a_non_ascii_password() {
        let mut state = typed(true, "пароль-123", "пароль-123");
        assert!(!submit(&mut state));

        let mut unrestricted = typed(false, "пароль-123", "пароль-123");
        assert!(submit(&mut unrestricted));
    }

    #[test]
    fn only_the_request_in_flight_is_awaited() {
        let mut requests = RequestIds::default();
        let earlier = requests.issue();
        let current = requests.issue();
        let mut state = typed(false, "Secret-123", "Secret-123");
        state.begin(current);

        assert!(state.is_waiting_for(current));
        assert!(!state.is_waiting_for(earlier));
    }

    #[test]
    fn a_failure_returns_to_the_form_and_keeps_what_was_typed() {
        let mut requests = RequestIds::default();
        let mut state = typed(false, "Secret-123", "Secret-123");
        state.begin(requests.issue());

        state.fail("refused".to_owned());

        assert!(matches!(state.status, Status::Editing));
        assert_eq!(state.error.as_deref(), Some("refused"));
        assert_eq!(state.new_password(), "Secret-123");
    }

    #[test]
    fn finishing_drops_the_typed_passwords() {
        let mut state = typed(false, "Secret-123", "Secret-123");
        state.finish("done".to_owned(), Finish::Changed);

        assert_eq!(state.new_password, "");
        assert_eq!(state.repeat, "");
    }
}
