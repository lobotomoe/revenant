//! Verify tab: check a PDF's signatures offline and, when a server is
//! configured, against the appliance too. Mirrors the Python client's
//! VerifyPanel. Available at every config layer (offline verification needs no
//! server).
//!
//! Like the sign form, this is pure UI state; reading files and running the
//! (blocking, possibly networked) verification are side effects the app performs
//! in response to the returned [`VerifyAction`].

use std::path::Path;

use eframe::egui;
use revenant_sign_core::net::ServerVerifyResult;
use revenant_sign_core::pdf::VerificationResult;

use crate::i18n::Localizer;
use crate::theme;

mod report;

use report::Report;

/// What the app should do after rendering the tab.
pub(crate) enum VerifyAction {
    None,
    /// Open a native picker to choose the PDF to verify.
    BrowsePdf,
    /// Start verifying the current file.
    Verify,
}

enum Status {
    Idle,
    Running,
    Done(Report),
    Failed(String),
}

/// Persistent state of the verify panel.
pub(crate) struct VerifyState {
    pdf_path: String,
    status: Status,
}

impl VerifyState {
    pub(crate) fn new() -> Self {
        Self {
            pdf_path: String::new(),
            status: Status::Idle,
        }
    }

    pub(crate) fn set_pdf(&mut self, path: &Path) {
        self.pdf_path = path.to_string_lossy().into_owned();
        self.status = Status::Idle;
    }

    pub(crate) fn pdf_path(&self) -> &str {
        self.pdf_path.trim()
    }

    pub(crate) fn begin(&mut self) {
        self.status = Status::Running;
    }

    pub(crate) fn on_failed(&mut self, message: String) {
        self.status = Status::Failed(message);
    }

    pub(crate) fn on_done(
        &mut self,
        local: Result<Vec<VerificationResult>, String>,
        server: Option<ServerVerifyResult>,
    ) {
        self.status = Status::Done(Report { local, server });
    }
}

pub(crate) fn show(ui: &mut egui::Ui, l10n: &Localizer, state: &mut VerifyState) -> VerifyAction {
    let mut action = VerifyAction::None;
    ui.add_space(8.0);

    let title = crate::style::zone_title(l10n.t("gui.pdf_file_label"));
    let name = crate::style::zone_basename(&state.pdf_path);
    let zone = crate::style::drop_zone(
        ui,
        crate::icons::PDF,
        &title,
        name.as_deref(),
        l10n.t("gui.drop_pdf_hint"),
        crate::style::PDF_EXTS,
    );
    if zone.clicked {
        action = VerifyAction::BrowsePdf;
    }

    ui.add_space(12.0);
    let busy = matches!(state.status, Status::Running);
    let ready = !busy && !state.pdf_path.trim().is_empty();
    let verify_label = format!(
        "{}  {}",
        crate::icons::VERIFY,
        l10n.t("gui.verify_signature")
    );
    // The primary action at the trailing edge, as on the Sign tab.
    let row = egui::vec2(ui.available_width(), 0.0);
    ui.allocate_ui_with_layout(
        row,
        egui::Layout::right_to_left(egui::Align::Center),
        |ui| {
            if ui
                .add_enabled(ready, crate::style::primary_button(verify_label))
                .clicked()
            {
                action = VerifyAction::Verify;
            }
        },
    );

    ui.add_space(12.0);
    match &state.status {
        Status::Idle => {
            ui.weak(l10n.t("gui.select_a_pdf_file_and_click_verify_to_check_signat_8fbc47f0"));
        }
        Status::Running => {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(l10n.t("gui.verifying_embedded_signatures_ellipsis"));
            });
        }
        Status::Failed(message) => {
            ui.colored_label(theme::ERROR, message);
        }
        Status::Done(report) => report::show(ui, l10n, report),
    }
    action
}
