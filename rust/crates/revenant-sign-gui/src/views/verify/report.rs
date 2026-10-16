//! A finished verification: a banner with the verdict on the whole document,
//! then a card per signature and one for the server's own check.

use eframe::egui::{self, Color32, RichText, Ui};
use revenant_sign_core::net::ServerVerifyResult;
use revenant_sign_core::pdf::VerificationResult;
use revenant_sign_core::pki::TrustStatus;

use crate::form::Form;
use crate::i18n::Localizer;
use crate::{icons, theme};

const BANNER_ICON_SIZE: f32 = 28.0;
const BANNER_TITLE_SIZE: f32 = 18.0;
const CARD_GAP: f32 = 12.0;

/// The result of a completed verification, kept for rendering each frame.
pub(super) struct Report {
    /// Offline per-signature results, or an error (e.g. no embedded signatures).
    pub(super) local: Result<Vec<VerificationResult>, String>,
    /// Server-side verdict, when a server was configured.
    pub(super) server: Option<ServerVerifyResult>,
}

pub(super) fn show(ui: &mut Ui, l10n: &Localizer, report: &Report) {
    egui::ScrollArea::vertical().show(ui, |ui| {
        banner(ui, l10n, report);
        if let Ok(results) = &report.local {
            let total = results.len();
            for (index, result) in results.iter().enumerate() {
                ui.add_space(CARD_GAP);
                signature_card(ui, l10n, result, index + 1, total);
            }
        }
        if let Some(server) = &report.server {
            ui.add_space(CARD_GAP);
            server_card(ui, l10n, server);
        }
    });
}

/// How the banner colours the verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tone {
    /// Every signature is valid and chains to a trusted anchor.
    Good,
    /// Every signature is valid, but not every signer is known to be trusted.
    Caution,
    /// At least one signature does not cover this document.
    Bad,
    /// Nothing to judge (no signatures, or the file could not be read).
    Neutral,
}

impl Tone {
    fn color(self) -> Color32 {
        match self {
            Tone::Good => theme::OK,
            Tone::Caution => theme::WARNING,
            Tone::Bad => theme::ERROR,
            Tone::Neutral => theme::MUTED,
        }
    }

    fn icon(self) -> &'static str {
        match self {
            Tone::Good => icons::SUCCESS,
            Tone::Caution => icons::CAUTION,
            Tone::Bad => icons::FAILURE,
            Tone::Neutral => icons::ABOUT,
        }
    }
}

/// The verdict on the whole document. Validity decides between good and bad
/// exactly as each signature's own verdict does ([`verdict_for`]); trust only
/// softens a valid result to caution, it never turns a failure into a pass.
fn overall_tone(results: &[VerificationResult]) -> Tone {
    if results.is_empty() {
        Tone::Neutral
    } else if results
        .iter()
        .any(|result| !verdict_for(result).identity_applies)
    {
        Tone::Bad
    } else if results
        .iter()
        .all(|result| result.trust_status == Some(TrustStatus::Trusted))
    {
        Tone::Good
    } else {
        Tone::Caution
    }
}

fn banner(ui: &mut Ui, l10n: &Localizer, report: &Report) {
    let (tone, title, subtitle) = match &report.local {
        Err(message) => (Tone::Neutral, message.clone(), Vec::new()),
        Ok(results) => {
            let tone = overall_tone(results);
            let title = match tone {
                Tone::Bad => l10n.t("gui.signature_failed"),
                Tone::Good | Tone::Caution | Tone::Neutral => l10n.t("gui.signature_valid"),
            };
            // With one signature, say whose it is and how far it is trusted
            // right in the verdict; with several, the cards below do.
            let subtitle = match results.as_slice() {
                [only] if tone != Tone::Bad => single_signer_summary(l10n, only),
                _ => Vec::new(),
            };
            (tone, title.to_owned(), subtitle)
        }
    };

    let color = tone.color();
    egui::Frame::new()
        .fill(color.gamma_multiply(0.12))
        .stroke(egui::Stroke::new(1.0_f32, color.gamma_multiply(0.6)))
        .corner_radius(8)
        .inner_margin(16)
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(tone.icon())
                        .size(BANNER_ICON_SIZE)
                        .color(color),
                );
                ui.vertical(|ui| {
                    ui.label(
                        RichText::new(title)
                            .size(BANNER_TITLE_SIZE)
                            .strong()
                            .color(color),
                    );
                    for line in subtitle {
                        ui.label(line);
                    }
                });
            });
        });
}

/// The signer's name and how far they are trusted, for the banner of a
/// one-signature document.
fn single_signer_summary(l10n: &Localizer, result: &VerificationResult) -> Vec<String> {
    let name = result.signer.as_ref().and_then(|cert| cert.name.clone());
    name.into_iter()
        .chain(std::iter::once(trust_text(l10n, result)))
        .collect()
}

/// What the verify view says about one signature.
struct Verdict {
    label: &'static str,
    color: Color32,
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

fn signature_card(
    ui: &mut Ui,
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
    let form = Form::new(
        ui,
        &[
            l10n.t("gui.verify_signature_label"),
            l10n.t("gui.verify_integrity_label"),
            l10n.t("gui.verify_org_label"),
            l10n.t("gui.verify_trust_label"),
        ],
    );

    card(ui, |ui| {
        ui.strong(l10n.tf(
            "gui.signature_current_total_signer",
            &[
                ("current", &current.to_string()),
                ("total", &total.to_string()),
                ("signer", signer),
            ],
        ));

        form.row(ui, Some(l10n.t("gui.verify_signature_label")), |ui| {
            ui.colored_label(verdict.color, l10n.t(verdict.label));
        });
        // Integrity, as the subordinate row saying which half failed.
        form.row(ui, Some(l10n.t("gui.verify_integrity_label")), |ui| {
            if result.integrity_ok() {
                ui.colored_label(theme::OK, l10n.t("gui.verify_integrity_ok"));
            } else {
                ui.colored_label(theme::ERROR, l10n.t("gui.verify_integrity_failed_value"));
            }
        });

        // Organization and trust describe the embedded certificate. For a
        // signature that did not verify, neither is a statement about this
        // document, so they are left to the details rather than shown as
        // findings.
        if verdict.identity_applies {
            if let Some(org) = result
                .signer
                .as_ref()
                .and_then(|cert| cert.organization.as_deref())
            {
                form.row(ui, Some(l10n.t("gui.verify_org_label")), |ui| {
                    ui.label(org);
                });
            }
            form.row(ui, Some(l10n.t("gui.verify_trust_label")), |ui| {
                ui.label(trust_text(l10n, result));
            });
        }

        if !result.details.is_empty() {
            ui.collapsing(l10n.t("gui.verify_details_header"), |ui| {
                for line in &result.details {
                    ui.label(line);
                }
            });
        }
    });
}

fn server_card(ui: &mut Ui, l10n: &Localizer, server: &ServerVerifyResult) {
    let form = Form::new(
        ui,
        &[
            l10n.t("gui.verify_signature_label"),
            l10n.t("gui.verify_signer_label"),
            l10n.t("gui.verify_certificate_label"),
        ],
    );
    card(ui, |ui| {
        ui.strong(l10n.t("gui.server_verification"));
        match server {
            ServerVerifyResult::Verified {
                signer_name,
                certificate_status,
                ..
            } => {
                form.row(ui, Some(l10n.t("gui.verify_signature_label")), |ui| {
                    ui.colored_label(theme::OK, l10n.t("gui.signature_valid"));
                });
                if let Some(name) = signer_name {
                    form.row(ui, Some(l10n.t("gui.verify_signer_label")), |ui| {
                        ui.label(name);
                    });
                }
                if let Some(status) = certificate_status {
                    form.row(ui, Some(l10n.t("gui.verify_certificate_label")), |ui| {
                        ui.label(status);
                    });
                }
            }
            ServerVerifyResult::Failed(reason) => {
                ui.colored_label(theme::MUTED, reason);
            }
        }
    });
}

fn card(ui: &mut Ui, content: impl FnOnce(&mut Ui)) {
    crate::style::card(ui).show(ui, |ui| {
        ui.set_width(ui.available_width());
        content(ui);
    });
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

    fn tampered() -> VerificationResult {
        let mut result = genuine();
        result.hash_ok = false;
        result
    }

    #[test]
    fn a_tampered_document_is_not_reported_valid() {
        // The state the report describes: bytes the ByteRange covers were
        // altered while the CMS object was left intact, so the signature over
        // the signed attributes still verifies and only the digest disagrees.
        let result = tampered();

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
        assert!(!verdict_for(&tampered()).identity_applies);
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
        // Trust is reported on its own row; a real signature from a
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

    #[test]
    fn the_banner_is_bad_when_any_signature_fails() {
        // One genuine and one tampered signature: the document as a whole is
        // not what its signers signed, whatever the first signature says.
        assert_eq!(overall_tone(&[genuine(), tampered()]), Tone::Bad);
    }

    #[test]
    fn an_untrusted_signer_only_softens_a_valid_banner() {
        let mut untrusted = genuine();
        untrusted.trust_status = Some(TrustStatus::Untrusted);
        assert_eq!(overall_tone(&[genuine(), untrusted]), Tone::Caution);
        assert_eq!(overall_tone(&[genuine()]), Tone::Good);
    }

    #[test]
    fn no_signatures_is_no_verdict() {
        assert_eq!(overall_tone(&[]), Tone::Neutral);
    }
}
