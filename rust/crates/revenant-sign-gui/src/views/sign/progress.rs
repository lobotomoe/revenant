//! The full-window overlay shown while a signing job runs.

use eframe::egui;

use super::{SignAction, SignForm, SignStatus};
use crate::i18n::Localizer;

const OVERLAY_WIDTH: f32 = 300.0;
const OVERLAY_INNER_PAD: f32 = 24.0;
const OVERLAY_SPINNER_SIZE: f32 = 32.0;

impl SignForm {
    /// A full-window modal shown while a signing job runs, so the busy state is
    /// unmistakable and never clipped by the form layout. A batch run also gets a
    /// progress bar, the current file, and a Cancel button; single signing just
    /// shows a spinner. Returns [`SignAction::CancelBatch`] if the user cancels.
    pub(super) fn progress_overlay(&self, ctx: &egui::Context, l10n: &Localizer) -> SignAction {
        let signing = matches!(self.status, SignStatus::Signing);
        if !signing && self.batch_progress.is_none() {
            return SignAction::None;
        }
        let mut action = SignAction::None;
        egui::Modal::new(egui::Id::new("signing_overlay")).show(ctx, |ui| {
            ui.set_width(OVERLAY_WIDTH);
            ui.vertical_centered(|ui| {
                ui.add_space(10.0);
                ui.add(egui::Spinner::new().size(OVERLAY_SPINNER_SIZE));
                ui.add_space(12.0);
                if let Some(progress) = &self.batch_progress {
                    // `u16::from` is lossless, sidestepping the float-cast lint.
                    let done =
                        u16::try_from(progress.current.saturating_sub(1)).unwrap_or(u16::MAX);
                    let total = u16::try_from(progress.total).unwrap_or(u16::MAX);
                    let fraction = if total == 0 {
                        0.0
                    } else {
                        f32::from(done) / f32::from(total)
                    };
                    ui.add(
                        egui::ProgressBar::new(fraction)
                            .show_percentage()
                            .desired_width(OVERLAY_WIDTH - OVERLAY_INNER_PAD),
                    );
                    ui.add_space(6.0);
                    ui.label(l10n.tf(
                        "gui.signing_n_of_total_filename",
                        &[
                            ("n", &progress.current.to_string()),
                            ("total", &progress.total.to_string()),
                            ("filename", &progress.filename),
                        ],
                    ));
                    ui.add_space(12.0);
                    if ui.button(l10n.t("gui.cancel")).clicked() {
                        action = SignAction::CancelBatch;
                    }
                } else {
                    ui.label(l10n.t("gui.signing_ellipsis"));
                }
                ui.add_space(10.0);
            });
        });
        action
    }
}
