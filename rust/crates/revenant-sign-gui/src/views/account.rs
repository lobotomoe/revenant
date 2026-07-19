//! Account panel shown atop the Sign tab once fully configured.
//!
//! It surfaces who is signing and whether their certificate is still valid --
//! the signer's cert fields (or a name/org/email fallback), a colored validity
//! line, where credentials are stored, and a log-out button. This mirrors the
//! Python client's right-column account info.

use eframe::egui;
use revenant_sign_core::appearance::extract_cert_fields;
use revenant_sign_core::config::{ConfigStore, ServerProfile, SignerInfo};
use revenant_sign_core::pki::{days_remaining, expiry_status, ExpiryStatus, EXPIRY_WARNING_DAYS};

use crate::i18n::Localizer;
use crate::jobs;
use crate::theme;

/// What the app should do after rendering the account panel.
pub(crate) enum AccountAction {
    None,
    /// Clear credentials and identity, dropping back to the login step.
    LogOut,
}

pub(crate) fn show(ui: &mut egui::Ui, l10n: &Localizer, store: &ConfigStore) -> AccountAction {
    let mut action = AccountAction::None;
    let signer = store.signer_info();
    let profile = store.active_profile();

    crate::style::card(ui).show(ui, |ui| {
        let rows = identity_rows(profile.as_ref(), &signer, l10n);
        if rows.is_empty() {
            ui.label(egui::RichText::new(l10n.t("gui.no_signer")).color(theme::MUTED));
        } else {
            egui::Grid::new("account_identity")
                .num_columns(2)
                .spacing([8.0, 2.0])
                .show(ui, |ui| {
                    for (label, value) in rows {
                        ui.label(egui::RichText::new(format!("{label}:")).color(theme::MUTED));
                        ui.label(value);
                        ui.end_row();
                    }
                });
        }

        if signer.not_after.is_some() {
            let (text, color) = format_cert_validity(
                l10n,
                signer.not_before.as_deref(),
                signer.not_after.as_deref(),
            );
            ui.label(egui::RichText::new(text).color(color));
        }

        ui.label(egui::RichText::new(store.credential_storage_info()).color(theme::MUTED));

        let log_out = format!("{}  {}", crate::icons::LOG_OUT, l10n.t("gui.log_out"));
        if ui.button(log_out).clicked() {
            action = AccountAction::LogOut;
        }
    });
    action
}

/// The identity rows to show: extracted cert fields when the profile defines
/// them (e.g. EKENG splits name from the ID number), else name/org/email.
fn identity_rows(
    profile: Option<&ServerProfile>,
    signer: &SignerInfo,
    l10n: &Localizer,
) -> Vec<(String, String)> {
    let mut rows = Vec::new();

    if let Some(profile) = profile {
        if !profile.cert_fields.is_empty() {
            let cert = jobs::cert_info_from_signer(signer);
            let extracted = extract_cert_fields(&profile.cert_fields, &cert);
            for field in &profile.cert_fields {
                if let Some(value) = extracted.get(&field.id) {
                    rows.push((field.label.clone(), value.clone()));
                }
            }
            return rows;
        }
    }

    for (value, key) in [
        (signer.name.as_deref(), "gui.name"),
        (signer.organization.as_deref(), "gui.org"),
        (signer.email.as_deref(), "gui.email"),
    ] {
        if let Some(text) = value {
            if !text.is_empty() {
                rows.push((l10n.t(key).to_owned(), text.to_owned()));
            }
        }
    }
    rows
}

/// Format the certificate validity window with a color cue, matching the Python
/// client's `format_cert_validity`: gray when valid, orange when expiring soon,
/// red when expired, gray when the window is unknown or unparsable.
fn format_cert_validity(
    l10n: &Localizer,
    not_before: Option<&str>,
    not_after: Option<&str>,
) -> (String, egui::Color32) {
    let Some(na) = not_after else {
        return (l10n.t("gui.cert_validity_unknown").to_owned(), theme::MUTED);
    };
    let (Some(remaining), Some(status)) =
        (days_remaining(na), expiry_status(na, EXPIRY_WARNING_DAYS))
    else {
        return (l10n.t("gui.cert_validity_unknown").to_owned(), theme::MUTED);
    };

    let start = not_before.map(ymd).unwrap_or_default();
    let end = ymd(na);
    let (key, days, color) = match status {
        ExpiryStatus::Expired => ("gui.cert_expired_range", remaining.abs(), theme::ERROR),
        ExpiryStatus::ExpiringSoon => ("gui.cert_expiring_soon_range", remaining, theme::WARNING),
        ExpiryStatus::Valid | ExpiryStatus::NotYetValid => {
            ("gui.cert_valid_range", remaining, theme::MUTED)
        }
    };
    let text = l10n.tf(
        key,
        &[
            ("start", &start),
            ("end", &end),
            ("days", &days.to_string()),
        ],
    );
    (text, color)
}

/// The date portion of an ISO-8601 timestamp. Every form the core persists
/// (RFC 3339 or a naive `YYYY-MM-DDThh:mm:ss`) begins with a fixed-width
/// `YYYY-MM-DD`, so the first ten bytes are the date.
fn ymd(iso: &str) -> String {
    iso.get(..10).unwrap_or(iso).to_owned()
}

#[cfg(test)]
mod tests {
    use super::ymd;

    #[test]
    fn ymd_takes_date_prefix() {
        assert_eq!(ymd("2027-01-15T00:00:00Z"), "2027-01-15");
        assert_eq!(ymd("2027-01-15T00:00:00.123456"), "2027-01-15");
    }

    #[test]
    fn ymd_returns_short_input_unchanged() {
        assert_eq!(ymd("2027"), "2027");
    }
}
