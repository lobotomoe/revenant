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
use revenant_sign_core::pki::TrustStatus;

use crate::i18n::Localizer;
use crate::theme;

/// What the app should do after rendering the tab.
pub(crate) enum VerifyAction {
    None,
    /// Open a native picker to choose the PDF to verify.
    BrowsePdf,
    /// Start verifying the current file.
    Verify,
}

/// The result of a completed verification, kept for rendering each frame.
struct Report {
    /// Offline per-signature results, or an error (e.g. no embedded signatures).
    local: Result<Vec<VerificationResult>, String>,
    /// Server-side verdict, when a server was configured.
    server: Option<ServerVerifyResult>,
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

    ui.horizontal(|ui| {
        ui.label(l10n.t("gui.pdf_file_label"));
        ui.text_edit_singleline(&mut state.pdf_path);
        if ui.button(l10n.t("gui.browse_ellipsis")).clicked() {
            action = VerifyAction::BrowsePdf;
        }
    });

    ui.add_space(6.0);
    let busy = matches!(state.status, Status::Running);
    let ready = !busy && !state.pdf_path.trim().is_empty();
    if ui
        .add_enabled(ready, egui::Button::new(l10n.t("gui.verify_signature")))
        .clicked()
    {
        action = VerifyAction::Verify;
    }

    ui.add_space(8.0);
    ui.separator();
    match &state.status {
        Status::Idle => {
            ui.colored_label(
                theme::MUTED,
                l10n.t("gui.select_a_pdf_file_and_click_verify_to_check_signat_8fbc47f0"),
            );
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
        Status::Done(report) => render_report(ui, l10n, report),
    }
    action
}

fn render_report(ui: &mut egui::Ui, l10n: &Localizer, report: &Report) {
    egui::ScrollArea::vertical().show(ui, |ui| {
        match &report.local {
            Ok(results) => {
                let total = results.len();
                for (index, result) in results.iter().enumerate() {
                    render_signature(ui, l10n, result, index + 1, total);
                    ui.add_space(6.0);
                }
            }
            Err(message) => {
                ui.colored_label(theme::MUTED, message);
            }
        }

        if let Some(server) = &report.server {
            ui.add_space(4.0);
            ui.separator();
            ui.strong(l10n.t("gui.server_verification"));
            render_server(ui, l10n, server);
        }
    });
}

fn render_signature(
    ui: &mut egui::Ui,
    l10n: &Localizer,
    result: &VerificationResult,
    current: usize,
    total: usize,
) {
    let signer = result
        .signer
        .as_ref()
        .and_then(|cert| cert.name.as_deref())
        .unwrap_or("?");
    ui.strong(l10n.tf(
        "gui.signature_current_total_signer",
        &[
            ("current", &current.to_string()),
            ("total", &total.to_string()),
            ("signer", signer),
        ],
    ));

    // Signature verdict.
    let (verdict_key, verdict_color) = if result.signature.is_valid() {
        ("gui.signature_valid", theme::OK)
    } else {
        ("gui.signature_failed", theme::ERROR)
    };
    labeled(ui, l10n.t("gui.verify_signature_label"), |ui| {
        ui.colored_label(verdict_color, l10n.t(verdict_key));
    });

    // Integrity.
    let (integrity_key, integrity_color) = if result.integrity_ok() {
        ("gui.verify_integrity_ok", theme::OK)
    } else {
        ("gui.verify_integrity_failed", theme::ERROR)
    };
    ui.colored_label(integrity_color, l10n.t(integrity_key));

    // Organization (when present).
    if let Some(org) = result
        .signer
        .as_ref()
        .and_then(|cert| cert.organization.as_deref())
    {
        labeled(ui, l10n.t("gui.verify_org_label"), |ui| {
            ui.label(org);
        });
    }

    // Trust.
    labeled(ui, l10n.t("gui.verify_trust_label"), |ui| {
        ui.label(trust_text(l10n, result));
    });

    // Technical details.
    if !result.details.is_empty() {
        ui.collapsing(l10n.t("gui.verify_details_header"), |ui| {
            for line in &result.details {
                ui.label(line);
            }
        });
    }
}

fn render_server(ui: &mut egui::Ui, l10n: &Localizer, server: &ServerVerifyResult) {
    match server {
        ServerVerifyResult::Verified {
            signer_name,
            certificate_status,
            ..
        } => {
            ui.colored_label(theme::OK, l10n.t("gui.signature_valid"));
            if let Some(name) = signer_name {
                labeled(ui, l10n.t("gui.verify_signer_label"), |ui| {
                    ui.label(name);
                });
            }
            if let Some(status) = certificate_status {
                ui.label(l10n.tf("gui.certificate_status", &[("status", status)]));
            }
        }
        ServerVerifyResult::Failed(reason) => {
            ui.colored_label(theme::MUTED, reason);
        }
    }
}

/// The localized trust line for a result's chain verdict.
fn trust_text(l10n: &Localizer, result: &VerificationResult) -> String {
    let anchor = result.trust_anchor.as_deref().unwrap_or_default();
    match result.trust_status {
        Some(TrustStatus::Trusted) => l10n.tf("gui.verify_trust_trusted", &[("anchor", anchor)]),
        Some(TrustStatus::Untrusted) => l10n.t("gui.verify_trust_not_trusted").to_owned(),
        Some(TrustStatus::Indeterminate) if !anchor.is_empty() => {
            l10n.tf("gui.verify_trust_partial", &[("anchor", anchor)])
        }
        Some(TrustStatus::Indeterminate) | None => {
            l10n.t("gui.verify_trust_not_checked").to_owned()
        }
    }
}

/// A label followed by inline content on the same row.
fn labeled(ui: &mut egui::Ui, label: &str, content: impl FnOnce(&mut egui::Ui)) {
    ui.horizontal(|ui| {
        ui.label(label);
        content(ui);
    });
}
