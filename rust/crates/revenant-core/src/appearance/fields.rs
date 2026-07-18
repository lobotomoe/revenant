//! Display-field extraction for PDF signature appearances.
//!
//! Resolves signer identity (name, email, org, DN) plus the auto date into the
//! ordered display strings a signature appearance renders, driven by the server
//! profile's field definitions.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::hash::BuildHasher;

use chrono::{Datelike, Local, Offset, Timelike};

use crate::config::{CertField, CertFieldSource, SigAuto, SigField, SigFieldValue};
use crate::pki::CertInfo;

/// Locale-independent English month abbreviations, indexed 1..=12.
///
/// `strftime("%b")` depends on `LC_TIME` and yields non-ASCII output under
/// Armenian and other locales, which the PDF fonts may not cover; a fixed table
/// keeps the rendered date stable everywhere.
const MONTH_ABBR: [&str; 13] = [
    "", "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// Format a UTC offset cleanly: `+0400` -> `UTC+4`, `+0530` -> `UTC+5:30`,
/// `+0000` -> `UTC`.
#[must_use]
pub fn format_utc_offset(offset_seconds: i32) -> String {
    let total_minutes = offset_seconds / 60;
    let hours = total_minutes / 60;
    let minutes = (total_minutes % 60).abs();
    if hours == 0 && minutes == 0 {
        return "UTC".to_owned();
    }
    let sign = if offset_seconds < 0 { '-' } else { '+' };
    let mut out = format!("UTC{sign}{}", hours.abs());
    if minutes != 0 {
        let _ = write!(out, ":{minutes:02}");
    }
    out
}

/// Generate a human-friendly local date string with UTC offset.
///
/// Example: `7 Feb 2026, 09:51:42 UTC+4`. Uses the machine's local time zone via
/// `chrono::Local` and the fixed month table for locale independence.
#[must_use]
pub fn make_date_str() -> String {
    let now = Local::now();
    let offset_seconds = now.offset().fix().local_minus_utc();
    let month = MONTH_ABBR[now.month() as usize];
    format!(
        "{} {} {}, {:02}:{:02}:{:02} {}",
        now.day(),
        month,
        now.year(),
        now.hour(),
        now.minute(),
        now.second(),
        format_utc_offset(offset_seconds),
    )
}

/// Read the signer-info value a [`CertField`] draws from.
fn source_value(source: CertFieldSource, signer: &CertInfo) -> Option<&str> {
    match source {
        CertFieldSource::Name => signer.name.as_deref(),
        CertFieldSource::Dn => signer.dn.as_deref(),
        CertFieldSource::Organization => signer.organization.as_deref(),
        CertFieldSource::Email => signer.email.as_deref(),
    }
}

/// Extract values from signer info using certificate field definitions.
///
/// For each [`CertField`]: read the source value, apply the extraction regex
/// (capture group 1) when present, and skip fields whose value is empty or whose
/// regex does not match. Returns a map of field id to extracted value.
#[must_use]
pub fn extract_cert_fields(
    cert_fields: &[CertField],
    signer: &CertInfo,
) -> HashMap<String, String> {
    let mut result = HashMap::new();
    for field in cert_fields {
        let raw = source_value(field.source, signer).unwrap_or("");
        if raw.is_empty() {
            continue;
        }

        match &field.regex {
            Some(pattern) => match regex::Regex::new(pattern) {
                Ok(re) => {
                    if let Some(group1) = re.captures(raw).and_then(|c| c.get(1)) {
                        if !group1.as_str().is_empty() {
                            result.insert(field.id.clone(), group1.as_str().to_owned());
                        }
                    }
                }
                Err(e) => {
                    log::warn!("Invalid regex {pattern:?} in field {:?}: {e}", field.id);
                }
            },
            None => {
                result.insert(field.id.clone(), raw.to_owned());
            }
        }
    }
    result
}

/// Build the ordered display strings for the signature appearance.
///
/// For each [`SigField`]: an auto date field renders the current date with its
/// label (default `Date`); a certificate-reference field looks its value up in
/// `cert_values` and is skipped when absent.
#[must_use]
pub fn extract_display_fields<S: BuildHasher>(
    sig_fields: &[SigField],
    cert_values: &HashMap<String, String, S>,
) -> Vec<String> {
    let mut result = Vec::new();
    for field in sig_fields {
        match &field.value {
            SigFieldValue::Auto(SigAuto::Date) => {
                let date_str = make_date_str();
                result.push(labeled(field.label.as_deref(), &date_str, "Date"));
            }
            SigFieldValue::Cert(cert_field) => {
                if let Some(raw) = cert_values.get(cert_field) {
                    if !raw.is_empty() {
                        result.push(labeled(field.label.as_deref(), raw, ""));
                    }
                }
            }
        }
    }
    result
}

/// Prefix `value` with `label:` when a non-empty label is set; otherwise use
/// `default_label:` if given, else `value` alone.
fn labeled(label: Option<&str>, value: &str, default_label: &str) -> String {
    match label {
        Some(l) if !l.is_empty() => format!("{l}: {value}"),
        _ if !default_label.is_empty() => format!("{default_label}: {value}"),
        _ => value.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_offset_formatting() {
        assert_eq!(format_utc_offset(0), "UTC");
        assert_eq!(format_utc_offset(4 * 3600), "UTC+4");
        assert_eq!(format_utc_offset(5 * 3600 + 30 * 60), "UTC+5:30");
        assert_eq!(format_utc_offset(-(5 * 3600 + 30 * 60)), "UTC-5:30");
        assert_eq!(format_utc_offset(-4 * 3600), "UTC-4");
        assert_eq!(format_utc_offset(30 * 60), "UTC+0:30");
    }

    #[test]
    fn date_str_has_expected_shape() {
        let s = make_date_str();
        // e.g. "7 Feb 2026, 09:51:42 UTC+4"
        assert!(s.contains("UTC"), "{s}");
        assert!(s.contains(", "), "{s}");
        let month_ok = MONTH_ABBR[1..].iter().any(|m| s.contains(m));
        assert!(month_ok, "no month in {s}");
    }

    fn signer() -> CertInfo {
        CertInfo {
            name: Some("John Doe".to_owned()),
            email: Some("john@example.com".to_owned()),
            organization: Some("ACME".to_owned()),
            dn: Some("SERIALNUMBER=1234567890, CN=John Doe".to_owned()),
            not_before: None,
            not_after: None,
        }
    }

    #[test]
    fn extracts_plain_and_regex_fields() {
        let fields = vec![
            CertField {
                id: "name".to_owned(),
                label: "Name".to_owned(),
                source: CertFieldSource::Name,
                regex: None,
            },
            CertField {
                id: "ssn".to_owned(),
                label: "SSN".to_owned(),
                source: CertFieldSource::Dn,
                regex: Some(r"SERIALNUMBER=(\d+)".to_owned()),
            },
        ];
        let values = extract_cert_fields(&fields, &signer());
        assert_eq!(values.get("name").map(String::as_str), Some("John Doe"));
        assert_eq!(values.get("ssn").map(String::as_str), Some("1234567890"));
    }

    #[test]
    fn skips_empty_and_non_matching() {
        let empty_signer = CertInfo {
            name: None,
            email: None,
            organization: None,
            dn: Some("CN=x".to_owned()),
            not_before: None,
            not_after: None,
        };
        let fields = vec![
            CertField {
                id: "name".to_owned(),
                label: "Name".to_owned(),
                source: CertFieldSource::Name,
                regex: None,
            },
            CertField {
                id: "ssn".to_owned(),
                label: "SSN".to_owned(),
                source: CertFieldSource::Dn,
                regex: Some(r"SERIALNUMBER=(\d+)".to_owned()),
            },
        ];
        let values = extract_cert_fields(&fields, &empty_signer);
        assert!(values.is_empty());
    }

    #[test]
    fn builds_display_fields_with_labels() {
        let mut cert_values = HashMap::new();
        cert_values.insert("name".to_owned(), "John Doe".to_owned());
        cert_values.insert("ssn".to_owned(), "1234567890".to_owned());

        let sig_fields = vec![
            SigField {
                value: SigFieldValue::Cert("name".to_owned()),
                label: None,
            },
            SigField {
                value: SigFieldValue::Cert("ssn".to_owned()),
                label: Some("SSN".to_owned()),
            },
            SigField {
                value: SigFieldValue::Auto(SigAuto::Date),
                label: None,
            },
        ];
        let display = extract_display_fields(&sig_fields, &cert_values);
        assert_eq!(display.len(), 3);
        assert_eq!(display[0], "John Doe");
        assert_eq!(display[1], "SSN: 1234567890");
        assert!(display[2].starts_with("Date: "), "{}", display[2]);
    }

    #[test]
    fn display_field_skips_missing_cert_value() {
        let cert_values = HashMap::new();
        let sig_fields = vec![SigField {
            value: SigFieldValue::Cert("missing".to_owned()),
            label: None,
        }];
        assert!(extract_display_fields(&sig_fields, &cert_values).is_empty());
    }
}
