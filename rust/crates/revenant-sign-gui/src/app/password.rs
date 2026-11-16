//! The change-password flow: open the dialog, send the new password in the
//! background, and present the answer.

use std::sync::Arc;

use eframe::egui;

use super::{Dialog, RevenantApp};
use crate::friendly::friendly;
use crate::jobs;
use crate::views::password::Finish;
use crate::views::{self, PasswordAction, PasswordState};
use crate::worker::{PasswordChangeOutcome, RequestId, WorkerMsg};

impl RevenantApp {
    pub(super) fn open_change_password(&mut self) {
        let ascii_only = self
            .store
            .active_profile()
            .is_some_and(|profile| profile.ascii_credentials_only);
        self.password = Some(PasswordState::new(ascii_only));
        self.dialog = Some(Dialog::ChangePassword);
    }

    pub(super) fn change_password_dialog(&mut self, ctx: &egui::Context) {
        let Some(state) = &mut self.password else {
            self.dialog = None;
            return;
        };
        let layout = self.window_style.dialog_buttons;
        match views::password::show(ctx, &self.l10n, state, layout) {
            PasswordAction::Close => {
                self.dialog = None;
                self.password = None;
            }
            PasswordAction::Submit => self.start_password_change(),
            PasswordAction::None => {}
        }
    }

    fn start_password_change(&mut self) {
        let request = self.requests.issue();
        let Some(state) = &mut self.password else {
            return;
        };
        state.begin(request);
        let new_password = state.new_password().to_owned();
        let store = Arc::clone(&self.store);
        let transport = Arc::clone(&self.transport);
        self.worker.spawn(move || {
            let outcome = jobs::change_password(&store, &transport, &new_password);
            WorkerMsg::PasswordChanged { request, outcome }
        });
    }

    pub(super) fn on_password_changed(
        &mut self,
        request: RequestId,
        outcome: &PasswordChangeOutcome,
    ) {
        let presentation = self.present_password_outcome(outcome);
        let Some(state) = &mut self.password else {
            // The dialog cannot be closed while a change is in flight, so this
            // is unreachable through the UI. The stored credentials were
            // already updated by the job itself.
            log::error!("a password change finished with no dialog to report it to");
            return;
        };
        if !state.is_waiting_for(request) {
            log::error!("a password change finished for a request the dialog is not waiting for");
            return;
        }
        match presentation {
            Presentation::Finished(message, finish) => state.finish(message, finish),
            Presentation::Failed(message) => state.fail(message),
        }
    }

    fn present_password_outcome(&self, outcome: &PasswordChangeOutcome) -> Presentation {
        let l10n = &self.l10n;
        match outcome {
            PasswordChangeOutcome::Changed => {
                Presentation::Finished(l10n.t("gui.password_changed").to_owned(), Finish::Changed)
            }
            PasswordChangeOutcome::ChangedNotSaved(detail) => Presentation::Finished(
                l10n.tf("gui.password_changed_but_not_saved", &[("error", detail)]),
                Finish::NeedsAttention,
            ),
            PasswordChangeOutcome::Unconfirmed(detail) => {
                let reason = friendly(l10n, detail);
                Presentation::Finished(
                    l10n.tf("gui.password_change_unconfirmed", &[("error", &reason)]),
                    Finish::NeedsAttention,
                )
            }
            PasswordChangeOutcome::NoCredentials => {
                Presentation::Failed(l10n.t("gui.log_in_to_change_the_password").to_owned())
            }
            PasswordChangeOutcome::Invalid(problem) => {
                Presentation::Failed(l10n.t(new_password_problem_key(*problem)).to_owned())
            }
            PasswordChangeOutcome::AuthFailed(detail) => self.present_auth_failure(detail),
            PasswordChangeOutcome::Refused {
                detail,
                shorter_than: None,
            } => Presentation::Failed(
                l10n.tf("gui.server_refused_the_new_password", &[("error", detail)]),
            ),
            PasswordChangeOutcome::Refused {
                detail,
                shorter_than: Some(minimum),
            } => {
                let minimum = minimum.to_string();
                Presentation::Failed(l10n.tf(
                    "gui.server_refused_a_short_password",
                    &[("min_length", &minimum), ("error", detail)],
                ))
            }
            PasswordChangeOutcome::Failed(detail) => Presentation::Failed(friendly(l10n, detail)),
        }
    }

    /// The server refused the current password. Say so, with the lockout
    /// warning where the profile has one, as the login form does.
    fn present_auth_failure(&self, detail: &str) -> Presentation {
        let mut message = self
            .l10n
            .tf("gui.authentication_failed_error", &[("error", detail)]);
        let max_attempts = self
            .store
            .active_profile()
            .map_or(0, |profile| profile.max_auth_attempts);
        if max_attempts > 0 {
            let attempts = max_attempts.to_string();
            let warning = self.l10n.tf(
                "gui.warning_account_locks_after_max_attempts_failed_attempts",
                &[("max_attempts", &attempts)],
            );
            message = format!("{message}\n{warning}");
        }
        Presentation::Failed(message)
    }
}

/// How an outcome is shown in the dialog.
enum Presentation {
    /// The change is over; only Close remains.
    Finished(String, Finish),
    /// The change did not happen; back to the form with this message.
    Failed(String),
}

fn new_password_problem_key(
    problem: revenant_sign_core::password::NewPasswordProblem,
) -> &'static str {
    use revenant_sign_core::password::NewPasswordProblem;
    match problem {
        NewPasswordProblem::Empty | NewPasswordProblem::SurroundingWhitespace => {
            "gui.enter_a_new_password"
        }
        NewPasswordProblem::SameAsCurrent => "gui.new_password_same_as_current",
        NewPasswordProblem::NonAscii => "gui.new_password_latin_only",
    }
}
