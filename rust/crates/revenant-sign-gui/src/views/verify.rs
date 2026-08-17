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

    ui.add_space(8.0);
    let busy = matches!(state.status, Status::Running);
    let ready = !busy && !state.pdf_path.trim().is_empty();
    let verify_label = format!(
        "{}  {}",
        crate::icons::VERIFY,
        l10n.t("gui.verify_signature")
    );
    if ui
        .add_enabled(ready, crate::style::primary_button(verify_label))
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

/// What the verify view says about one signature.
struct Verdict {
    label: &'static str,
    color: egui::Color32,
    /// Whether the embedded signer identity and chain trust may be presented as
    /// applying to this document.
    identity_applies: bool,
}

/// Decide the primary verdict for one signature.
///
/// The verdict is [`VerificationResult::valid`] and never the bare CMS signature
/// status. Those differ precisely in the tampered-document case: an attacker can
/// alter bytes the ByteRange covers while leaving the CMS object intact, so the
/// signer's signature over the signed attributes still verifies while the
/// document digest no longer matches. Reading only the CMS status rendered a
/// green "Signature VALID" above a red integrity line, and showed the embedded
/// certificate as the signer of bytes it never signed (GHSA-m267).
///
/// Trust is deliberately not part of this: a genuine signature from a
/// certificate outside the profile's anchors is still a genuine signature, and
/// the trust row says so on its own.
fn verdict_for(result: &VerificationResult) -> Verdict {
    if result.valid() {
        Verdict {
            label: "gui.signature_valid",
            color: theme::OK,
            identity_applies: true,
        }
    } else {
        Verdict {
            label: "gui.signature_failed",
            color: theme::ERROR,
            identity_applies: false,
        }
    }
}

fn render_signature(
    ui: &mut egui::Ui,
    l10n: &Localizer,
    result: &VerificationResult,
    current: usize,
    total: usize,
) {
    let verdict = verdict_for(result);
    // An unnamed signer for a failed signature, rather than a name the failure
    // means we cannot attribute. The certificate is still in the details below.
    let signer = result
        .signer
        .as_ref()
        .filter(|_| verdict.identity_applies)
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
    labeled(ui, l10n.t("gui.verify_signature_label"), |ui| {
        ui.colored_label(verdict.color, l10n.t(verdict.label));
    });

    // Integrity, as the subordinate line saying which half failed.
    let (integrity_key, integrity_color) = if result.integrity_ok() {
        ("gui.verify_integrity_ok", theme::OK)
    } else {
        ("gui.verify_integrity_failed", theme::ERROR)
    };
    ui.colored_label(integrity_color, l10n.t(integrity_key));

    // Organization and trust describe the embedded certificate. For a signature
    // that did not verify, neither is a statement about this document, so they
    // are left to the details rather than shown as findings.
    if verdict.identity_applies {
        if let Some(org) = result
            .signer
            .as_ref()
            .and_then(|cert| cert.organization.as_deref())
        {
            labeled(ui, l10n.t("gui.verify_org_label"), |ui| {
                ui.label(org);
            });
        }

        labeled(ui, l10n.t("gui.verify_trust_label"), |ui| {
            ui.label(trust_text(l10n, result));
        });
    }

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

#[cfg(test)]
mod tests {
    use revenant_sign_core::cms::ByteRangeCoverage;
    use revenant_sign_core::cms::SignatureStatus;
    use revenant_sign_core::pki::CertInfo;

    use super::*;

    /// A result whose CMS signature verifies and whose document is intact.
    fn genuine() -> VerificationResult {
        VerificationResult {
            structure_ok: true,
            hash_ok: true,
            signature: SignatureStatus::Valid,
            coverage: ByteRangeCoverage::default(),
            ltv_enabled: false,
            details: Vec::new(),
            signer: Some(CertInfo {
                name: Some("Victim Signer".to_owned()),
                organization: Some("Victim Org".to_owned()),
                ..CertInfo::default()
            }),
            trust_anchor: Some("Example Trusted CA".to_owned()),
            trust_status: Some(TrustStatus::Trusted),
        }
    }

    #[test]
    fn a_tampered_document_is_not_reported_valid() {
        // The state the report describes: bytes the ByteRange covers were
        // altered while the CMS object was left intact, so the signature over
        // the signed attributes still verifies and only the digest disagrees.
        let mut result = genuine();
        result.hash_ok = false;

        assert!(
            result.signature.is_valid(),
            "precondition: CMS still verifies"
        );
        assert!(
            !result.integrity_ok(),
            "precondition: the document does not"
        );

        let verdict = verdict_for(&result);
        assert_eq!(verdict.label, "gui.signature_failed");
        assert_eq!(verdict.color, theme::ERROR);
    }

    #[test]
    fn a_failed_signature_does_not_name_a_signer_or_a_trust_anchor() {
        // The certificate is trusted and carries a name, but neither is a
        // statement about a document the signature does not cover.
        let mut result = genuine();
        result.hash_ok = false;

        assert!(!verdict_for(&result).identity_applies);
    }

    #[test]
    fn a_genuine_signature_still_presents_its_signer() {
        let verdict = verdict_for(&genuine());
        assert_eq!(verdict.label, "gui.signature_valid");
        assert_eq!(verdict.color, theme::OK);
        assert!(verdict.identity_applies);
    }

    #[test]
    fn an_untrusted_chain_does_not_invalidate_a_genuine_signature() {
        // Trust is reported on its own line; a real signature from a
        // certificate outside the profile's anchors is still a real signature.
        let mut result = genuine();
        result.trust_status = Some(TrustStatus::Untrusted);
        result.trust_anchor = None;

        let verdict = verdict_for(&result);
        assert_eq!(verdict.label, "gui.signature_valid");
        assert!(verdict.identity_applies);
    }

    #[test]
    fn an_unverifiable_signature_is_a_failure_not_a_pass() {
        let mut result = genuine();
        result.signature = SignatureStatus::Unverifiable("no signer certificate");

        let verdict = verdict_for(&result);
        assert_eq!(verdict.label, "gui.signature_failed");
        assert!(!verdict.identity_applies);
    }
}
