//! Certificate expiration utilities.
//!
//! Pure functions for days-remaining, expiry status, and validity-period
//! formatting. No I/O.
//!
//! Certificate validity timestamps flow through the system as ISO 8601 strings
//! (that is how [`crate::config::SignerInfo`] persists them). These helpers
//! parse both offset-qualified (`...+00:00` / `...Z`) and naive timestamps;
//! a naive timestamp is treated as UTC.

use time::format_description::well_known::Rfc3339;
use time::macros::format_description;
use time::{OffsetDateTime, PrimitiveDateTime};

/// Days-before-expiry at or below which a certificate is "expiring soon".
pub const EXPIRY_WARNING_DAYS: i64 = 30;

const SECS_PER_DAY: i64 = 86_400;

/// Expiration state of a certificate relative to now.
///
/// [`expiry_status`] only ever yields `Valid`, `ExpiringSoon`, or `Expired`;
/// `NotYetValid` is reported separately by [`not_yet_valid`]. The variant is
/// kept for completeness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpiryStatus {
    Valid,
    ExpiringSoon,
    Expired,
    NotYetValid,
}

impl ExpiryStatus {
    /// The snake_case wire string used by the reference clients and CLI output.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ExpiryStatus::Valid => "valid",
            ExpiryStatus::ExpiringSoon => "expiring_soon",
            ExpiryStatus::Expired => "expired",
            ExpiryStatus::NotYetValid => "not_yet_valid",
        }
    }
}

/// Parse an ISO 8601 timestamp, treating a naive (offset-less) value as UTC.
fn parse_iso(s: &str) -> Option<OffsetDateTime> {
    if let Ok(dt) = OffsetDateTime::parse(s, &Rfc3339) {
        return Some(dt);
    }
    // Persisted timestamps may carry fractional seconds; accept both a
    // fractional-second naive form and a whole-second one.
    let with_subsecond =
        format_description!("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond]");
    if let Ok(dt) = PrimitiveDateTime::parse(s, &with_subsecond) {
        return Some(dt.assume_utc());
    }
    let whole_second = format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]");
    if let Ok(dt) = PrimitiveDateTime::parse(s, &whole_second) {
        return Some(dt.assume_utc());
    }
    None
}

/// Whole days from now until `target`, flooring toward negative infinity so a
/// certificate 10.5 days expired reads as -11, not -10 (floor division, not
/// truncation toward zero).
fn days_until(target: OffsetDateTime) -> i64 {
    let delta = target - OffsetDateTime::now_utc();
    delta.whole_seconds().div_euclid(SECS_PER_DAY)
}

fn format_ymd(dt: OffsetDateTime) -> String {
    let fmt = format_description!("[year]-[month]-[day]");
    dt.format(&fmt).unwrap_or_else(|_| "?".to_owned())
}

/// Days until a certificate expires, or `None` if `not_after_iso` is unparsable.
///
/// Negative when the certificate has already expired.
#[must_use]
pub fn days_remaining(not_after_iso: &str) -> Option<i64> {
    parse_iso(not_after_iso).map(days_until)
}

/// Classify a certificate by how close it is to expiry.
///
/// `warn_days` is the threshold for `ExpiringSoon` (use [`EXPIRY_WARNING_DAYS`]
/// for the default). Returns `None` if the timestamp cannot be parsed. Never
/// returns [`ExpiryStatus::NotYetValid`] -- use [`not_yet_valid`] for that.
#[must_use]
pub fn expiry_status(not_after_iso: &str, warn_days: i64) -> Option<ExpiryStatus> {
    let remaining = days_remaining(not_after_iso)?;
    if remaining < 0 {
        Some(ExpiryStatus::Expired)
    } else if remaining <= warn_days {
        Some(ExpiryStatus::ExpiringSoon)
    } else {
        Some(ExpiryStatus::Valid)
    }
}

/// Whether a certificate's validity period has not started yet, or `None` if
/// `not_before_iso` is unparsable.
#[must_use]
pub fn not_yet_valid(not_before_iso: &str) -> Option<bool> {
    parse_iso(not_before_iso).map(|not_before| OffsetDateTime::now_utc() < not_before)
}

/// Human-readable validity window, e.g. `2024-01-15 - 2027-01-15 (347 days
/// remaining)`. Missing or unparsable endpoints render as `?`; both absent
/// renders as `Unknown`.
#[must_use]
pub fn format_validity_period(not_before: Option<&str>, not_after: Option<&str>) -> String {
    if not_before.is_none() && not_after.is_none() {
        return "Unknown".to_owned();
    }

    let before = not_before
        .and_then(parse_iso)
        .map_or_else(|| "?".to_owned(), format_ymd);
    let mut out = format!("{before} - ");

    match not_after.and_then(parse_iso) {
        Some(dt) => {
            out.push_str(&format_ymd(dt));
            out.push_str(&remaining_suffix(days_until(dt)));
        }
        None => out.push('?'),
    }
    out
}

/// The ` (... remaining)` / ` (expired ...)` tail of a validity string.
fn remaining_suffix(remaining: i64) -> String {
    if remaining < 0 {
        format!(" (expired {} days ago)", remaining.abs())
    } else if remaining == 0 {
        " (expires today)".to_owned()
    } else if remaining == 1 {
        " (1 day remaining)".to_owned()
    } else {
        format!(" ({remaining} days remaining)")
    }
}

/// Short expiry summary for display, e.g. `Valid (347 days)`,
/// `Expiring soon (12 days)`, `EXPIRED (5 days ago)`, or `Unknown`.
#[must_use]
pub fn format_expiry_summary(not_after: Option<&str>) -> String {
    let Some(iso) = not_after else {
        return "Unknown".to_owned();
    };
    let (Some(remaining), Some(status)) =
        (days_remaining(iso), expiry_status(iso, EXPIRY_WARNING_DAYS))
    else {
        return "Unknown".to_owned();
    };

    match status {
        ExpiryStatus::Expired => format!("EXPIRED ({} days ago)", remaining.abs()),
        ExpiryStatus::ExpiringSoon => format!("Expiring soon ({remaining} days)"),
        ExpiryStatus::Valid | ExpiryStatus::NotYetValid => format!("Valid ({remaining} days)"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::Duration;

    /// ISO 8601 timestamp offset from now by `delta_days` (offset-qualified).
    fn iso(delta_days: i64) -> String {
        let dt = OffsetDateTime::now_utc() + Duration::days(delta_days);
        dt.format(&Rfc3339).expect("format now")
    }

    #[test]
    fn days_remaining_future() {
        let result = days_remaining(&iso(100)).unwrap();
        assert!((99..=100).contains(&result), "got {result}");
    }

    #[test]
    fn days_remaining_past() {
        let result = days_remaining(&iso(-10)).unwrap();
        assert!((-11..=-10).contains(&result), "got {result}");
    }

    #[test]
    fn days_remaining_today() {
        let result = days_remaining(&iso(0)).unwrap();
        assert!((-1..=0).contains(&result), "got {result}");
    }

    #[test]
    fn days_remaining_naive_timestamp_treated_as_utc() {
        // A naive (offset-less) timestamp with microseconds.
        let dt = OffsetDateTime::now_utc() + Duration::days(50);
        let fmt = format_description!("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond]");
        let naive = dt.format(&fmt).unwrap();
        let result = days_remaining(&naive).unwrap();
        assert!((49..=50).contains(&result), "got {result}");
    }

    #[test]
    fn days_remaining_unparsable_is_none() {
        assert_eq!(days_remaining("not a date"), None);
    }

    #[test]
    fn expiry_status_valid() {
        assert_eq!(
            expiry_status(&iso(365), EXPIRY_WARNING_DAYS),
            Some(ExpiryStatus::Valid)
        );
    }

    #[test]
    fn expiry_status_expiring_soon() {
        assert_eq!(
            expiry_status(&iso(15), EXPIRY_WARNING_DAYS),
            Some(ExpiryStatus::ExpiringSoon)
        );
    }

    #[test]
    fn expiry_status_expired() {
        assert_eq!(
            expiry_status(&iso(-5), EXPIRY_WARNING_DAYS),
            Some(ExpiryStatus::Expired)
        );
    }

    #[test]
    fn expiry_status_custom_warn_days() {
        assert_eq!(expiry_status(&iso(45), 30), Some(ExpiryStatus::Valid));
        assert_eq!(
            expiry_status(&iso(45), 60),
            Some(ExpiryStatus::ExpiringSoon)
        );
    }

    #[test]
    fn expiry_status_boundary_at_warn_days() {
        assert_eq!(
            expiry_status(&iso(30), EXPIRY_WARNING_DAYS),
            Some(ExpiryStatus::ExpiringSoon)
        );
    }

    #[test]
    fn not_yet_valid_future() {
        assert_eq!(not_yet_valid(&iso(10)), Some(true));
    }

    #[test]
    fn not_yet_valid_past() {
        assert_eq!(not_yet_valid(&iso(-10)), Some(false));
    }

    #[test]
    fn format_validity_period_both_dates() {
        let result = format_validity_period(Some("2024-01-15T00:00:00+00:00"), Some(&iso(100)));
        assert!(result.contains("2024-01-15"), "got {result}");
        assert!(result.contains("days remaining"), "got {result}");
    }

    #[test]
    fn format_validity_period_expired() {
        let result = format_validity_period(
            Some("2020-01-01T00:00:00+00:00"),
            Some("2023-01-01T00:00:00+00:00"),
        );
        assert!(result.contains("2020-01-01"));
        assert!(result.contains("expired"));
        assert!(result.contains("days ago"));
    }

    #[test]
    fn format_validity_period_none_both() {
        assert_eq!(format_validity_period(None, None), "Unknown");
    }

    #[test]
    fn format_validity_period_none_before() {
        let result = format_validity_period(None, Some(&iso(100)));
        assert!(result.starts_with('?'), "got {result}");
        assert!(result.contains("days remaining"));
    }

    #[test]
    fn format_validity_period_none_after() {
        let result = format_validity_period(Some("2024-01-15T00:00:00+00:00"), None);
        assert!(result.contains("2024-01-15"));
        assert!(result.ends_with('?'), "got {result}");
    }

    #[test]
    fn format_validity_period_one_day() {
        let dt = OffsetDateTime::now_utc() + Duration::days(1) + Duration::hours(12);
        let result = format_validity_period(
            Some("2024-01-01T00:00:00+00:00"),
            Some(&dt.format(&Rfc3339).unwrap()),
        );
        assert!(result.contains("1 day remaining"), "got {result}");
    }

    #[test]
    fn format_validity_period_expires_today() {
        let dt = OffsetDateTime::now_utc() + Duration::hours(6);
        let result = format_validity_period(
            Some("2024-01-01T00:00:00+00:00"),
            Some(&dt.format(&Rfc3339).unwrap()),
        );
        assert!(result.contains("expires today"), "got {result}");
    }

    #[test]
    fn format_expiry_summary_valid() {
        let result = format_expiry_summary(Some(&iso(200)));
        assert!(result.starts_with("Valid ("), "got {result}");
        assert!(result.contains("days)"));
    }

    #[test]
    fn format_expiry_summary_expiring_soon() {
        let result = format_expiry_summary(Some(&iso(10)));
        assert!(result.starts_with("Expiring soon ("), "got {result}");
    }

    #[test]
    fn format_expiry_summary_expired() {
        let result = format_expiry_summary(Some(&iso(-5)));
        assert!(result.starts_with("EXPIRED ("), "got {result}");
        assert!(result.contains("days ago)"));
    }

    #[test]
    fn format_expiry_summary_none() {
        assert_eq!(format_expiry_summary(None), "Unknown");
    }
}
