//! Low-level X.509 accessors shared by identity extraction and chain building.
//!
//! Thin, allocation-light helpers over `x509-cert`'s [`Certificate`] that pull
//! out exactly what the certificate/chain logic needs: subject fields, a
//! human-readable DN, validity as ISO 8601, and the SKI / AKI / AIA extensions.
//!
//! The one subtlety is directory-string decoding. EKENG's CA encodes the CN and
//! O of its DNs as **BMPString** (UCS-2), which `x509-cert`'s own `Display`
//! hex-dumps, and its `emailAddress` as a PrintableString containing `@` -- a
//! character outside the PrintableString charset, which the strict
//! `PrintableStringRef` rejects. These helpers decode BMPString explicitly and
//! fall back to a lenient latin-1 read of the raw octets when the strict decoder
//! refuses, recovering the real text -- the same lenient decoding `asn1crypto`
//! performs, which EKENG's real-world certificates require.

use cms::cert::CertificateChoices;
use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use const_oid::{AssociatedOid, ObjectIdentifier};
use der::asn1::{BmpString, Ia5StringRef, PrintableStringRef, TeletexStringRef, Utf8StringRef};
use der::{Any, Decode, Encode, Tag, Tagged};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use x509_cert::attr::AttributeTypeAndValue;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{
    AuthorityInfoAccessSyntax, AuthorityKeyIdentifier, SubjectKeyIdentifier,
};
use x509_cert::name::RdnSequence;
use x509_cert::time::Time;
use x509_cert::Certificate;

use crate::{Result, RevenantError};

// Object identifiers for the subject fields and extensions we read.
const OID_CN: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");
const OID_EMAIL: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.1");
const OID_ORG: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.10");
/// `id-ad-caIssuers`: the AIA access method whose location is an issuer cert URL.
const OID_CA_ISSUERS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.2");

/// Parse a DER-encoded X.509 certificate.
///
/// # Errors
///
/// Returns [`RevenantError::Certificate`] if the bytes are not a valid cert.
pub(crate) fn parse_der(der: &[u8]) -> Result<Certificate> {
    Certificate::from_der(der)
        .map_err(|e| RevenantError::Certificate(format!("Failed to parse X.509 certificate: {e}")))
}

/// Every X.509 certificate embedded in a CMS/PKCS#7 SignedData blob, in the
/// order they appear in the `certificates` set.
///
/// Returns an empty vector when the SignedData carries no `certificates`
/// element. Non-X.509 `CertificateChoices` variants (attribute certs, other
/// formats) are skipped.
///
/// # Errors
///
/// Returns [`RevenantError::Certificate`] if the bytes are not a parseable CMS
/// SignedData structure.
pub(crate) fn all_certs_from_cms(cms_der: &[u8]) -> Result<Vec<Certificate>> {
    let content_info = ContentInfo::from_der(cms_der)
        .map_err(|e| RevenantError::Certificate(format!("Failed to parse CMS/PKCS#7 blob: {e}")))?;
    let signed_data: SignedData = content_info
        .content
        .decode_as()
        .map_err(|e| RevenantError::Certificate(format!("Failed to parse CMS SignedData: {e}")))?;

    let Some(certs) = signed_data.certificates else {
        return Ok(Vec::new());
    };
    Ok(certs
        .0
        .into_vec()
        .into_iter()
        .filter_map(|choice| match choice {
            CertificateChoices::Certificate(cert) => Some(cert),
            CertificateChoices::Other(_) => None,
        })
        .collect())
}

/// The Common Name (CN) of the subject, if present.
pub(crate) fn common_name(cert: &Certificate) -> Option<String> {
    subject_field(cert, OID_CN)
}

/// The emailAddress of the subject, if present.
pub(crate) fn email(cert: &Certificate) -> Option<String> {
    subject_field(cert, OID_EMAIL)
}

/// The Organization (O) of the subject, if present.
pub(crate) fn organization(cert: &Certificate) -> Option<String> {
    subject_field(cert, OID_ORG)
}

/// Human-readable subject DN, e.g. `CN=Jane Doe, O=Acme`.
pub(crate) fn subject_dn(cert: &Certificate) -> String {
    format_dn(&cert.tbs_certificate.subject)
}

/// Human-readable issuer DN.
pub(crate) fn issuer_dn(cert: &Certificate) -> String {
    format_dn(&cert.tbs_certificate.issuer)
}

/// The certificate serial number as a base-10 string.
///
/// Renders the DER INTEGER's magnitude in decimal. Serials routinely exceed 64
/// bits, so this converts the big-endian bytes directly rather than through an
/// integer type.
pub(crate) fn serial_decimal(cert: &Certificate) -> String {
    bytes_to_decimal(cert.tbs_certificate.serial_number.as_bytes())
}

/// Render a big-endian, unsigned magnitude as a base-10 string via repeated
/// division by ten. Leading zero bytes (including DER's positive-sign pad) are
/// ignored; an all-zero or empty input renders as `"0"`.
fn bytes_to_decimal(bytes: &[u8]) -> String {
    let mut buf: Vec<u8> = bytes.iter().skip_while(|&&b| b == 0).copied().collect();
    if buf.is_empty() {
        return "0".to_owned();
    }
    let mut digits = Vec::new();
    while buf.iter().any(|&b| b != 0) {
        let mut remainder: u32 = 0;
        for byte in &mut buf {
            let acc = (remainder << 8) | u32::from(*byte);
            // acc / 10 <= 255, so the conversion never truncates.
            *byte = u8::try_from(acc / 10).unwrap_or(u8::MAX);
            remainder = acc % 10;
        }
        digits.push(char::from_digit(remainder, 10).unwrap_or('0'));
    }
    digits.iter().rev().collect()
}

/// The `notBefore` validity bound as an ISO 8601 (RFC 3339) UTC string.
pub(crate) fn not_before_iso(cert: &Certificate) -> Option<String> {
    time_to_iso(cert.tbs_certificate.validity.not_before)
}

/// The `notAfter` validity bound as an ISO 8601 (RFC 3339) UTC string.
pub(crate) fn not_after_iso(cert: &Certificate) -> Option<String> {
    time_to_iso(cert.tbs_certificate.validity.not_after)
}

/// The Subject Key Identifier (SKI) extension value, if present.
pub(crate) fn subject_key_identifier(cert: &Certificate) -> Option<Vec<u8>> {
    let ski = find_extension::<SubjectKeyIdentifier>(cert)?;
    Some(ski.0.as_bytes().to_vec())
}

/// The Authority Key Identifier's `keyIdentifier`, if present.
pub(crate) fn authority_key_id(cert: &Certificate) -> Option<Vec<u8>> {
    let aki = find_extension::<AuthorityKeyIdentifier>(cert)?;
    Some(aki.key_identifier?.as_bytes().to_vec())
}

/// CA-issuer URLs from the Authority Information Access (AIA) extension.
pub(crate) fn aia_ca_issuer_urls(cert: &Certificate) -> Vec<String> {
    let Some(aia) = find_extension::<AuthorityInfoAccessSyntax>(cert) else {
        return Vec::new();
    };
    aia.0
        .iter()
        .filter(|desc| desc.access_method == OID_CA_ISSUERS)
        .filter_map(|desc| match &desc.access_location {
            GeneralName::UniformResourceIdentifier(uri) => Some(uri.as_str().to_owned()),
            _ => None,
        })
        .collect()
}

/// Whether `now` falls within the certificate's validity window.
pub(crate) fn is_currently_valid(cert: &Certificate) -> bool {
    let validity = &cert.tbs_certificate.validity;
    let (Some(not_before), Some(not_after)) = (
        time_to_offset(validity.not_before),
        time_to_offset(validity.not_after),
    ) else {
        // A validity bound outside the representable range (impossible for a
        // real cert): bias toward "invalid".
        return false;
    };
    let now = OffsetDateTime::now_utc();
    now >= not_before && now <= not_after
}

/// Whether the certificate is (structurally) self-signed: issuer equals subject.
///
/// A name-equality test only, with no signature check -- the same criterion
/// `asn1crypto` reports as its `"maybe"` self-signed status. That is sufficient
/// here: its only role is to stop chain building at a root.
pub(crate) fn is_self_signed(cert: &Certificate) -> bool {
    cert.tbs_certificate.issuer == cert.tbs_certificate.subject
}

// ── internals ────────────────────────────────────────────────────────

/// First subject attribute value for `oid`, decoding any directory-string form.
fn subject_field(cert: &Certificate, oid: ObjectIdentifier) -> Option<String> {
    cert.tbs_certificate
        .subject
        .0
        .iter()
        .flat_map(|rdn| rdn.0.iter())
        .find(|atv| atv.oid == oid)
        .and_then(atv_to_string)
}

/// Decode an attribute value to text across the directory-string encodings,
/// including BMPString (which `x509-cert` would otherwise hex-dump).
///
/// When the strict, charset-checked decoder rejects a value, a lenient fallback
/// decodes the raw octets. This matters for real-world DNs that violate the
/// letter of X.680: EKENG's CA, for instance, encodes the `emailAddress` as a
/// PrintableString containing `@`, which is not in the PrintableString charset,
/// so `PrintableStringRef` rejects it. `asn1crypto` decodes it anyway as
/// latin-1, and mirroring that leniency lets the same certificates parse.
fn atv_to_string(atv: &AttributeTypeAndValue) -> Option<String> {
    let value = &atv.value;
    let tag = value.tag();
    let strict = match tag {
        Tag::Utf8String => Utf8StringRef::try_from(value)
            .ok()
            .map(|s| s.as_str().to_owned()),
        Tag::PrintableString => PrintableStringRef::try_from(value)
            .ok()
            .map(|s| s.as_str().to_owned()),
        Tag::Ia5String => Ia5StringRef::try_from(value)
            .ok()
            .map(|s| s.as_str().to_owned()),
        Tag::TeletexString => TeletexStringRef::try_from(value)
            .ok()
            .map(|s| s.as_str().to_owned()),
        Tag::BmpString => value.decode_as::<BmpString>().ok().map(|s| s.to_string()),
        _ => None,
    };
    strict.or_else(|| decode_lenient(value, tag))
}

/// Lenient recovery of a string value the strict typed decoder rejected.
///
/// For the byte-oriented directory-string encodings, `asn1crypto` decodes the
/// content octets as latin-1 -- a total mapping that never fails and recovers
/// values a stricter charset check discards (e.g. an `@` in a PrintableString).
/// UTF8String is deliberately excluded: malformed UTF-8 has no faithful latin-1
/// reading, so it falls through to the hex dump, matching `asn1crypto`, which
/// keeps UTF8String strict.
fn decode_lenient(value: &Any, tag: Tag) -> Option<String> {
    match tag {
        Tag::PrintableString | Tag::Ia5String | Tag::TeletexString => {
            Some(value.value().iter().map(|&b| b as char).collect())
        }
        _ => None,
    }
}

/// Format a Name as `TYPE=value, TYPE=value` with uppercase short attribute
/// types, decoding BMPString values and falling back to a hex dump only for
/// genuinely unknown value encodings.
fn format_dn(name: &RdnSequence) -> String {
    name.0
        .iter()
        .flat_map(|rdn| rdn.0.iter())
        .map(|atv| {
            let key = attr_short_name(&atv.oid);
            let value = atv_to_string(atv).unwrap_or_else(|| hex_value(atv));
            format!("{key}={value}")
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// Short display name for a DN attribute type, or the dotted OID if unknown.
fn attr_short_name(oid: &ObjectIdentifier) -> String {
    let short = match *oid {
        OID_CN => "CN",
        OID_ORG => "O",
        OID_EMAIL => "E",
        _ => match oid.to_string().as_str() {
            "2.5.4.11" => "OU",
            "2.5.4.6" => "C",
            "2.5.4.7" => "L",
            "2.5.4.8" => "ST",
            "2.5.4.4" => "SN",
            "2.5.4.42" => "GN",
            "2.5.4.5" => "SERIALNUMBER",
            _ => return oid.to_string(),
        },
    };
    short.to_owned()
}

/// Hex of an attribute's raw DER value -- the last-resort rendering for an
/// encoding we do not decode (matches `x509-cert`'s own `Display` fallback).
fn hex_value(atv: &AttributeTypeAndValue) -> String {
    use std::fmt::Write as _;
    let Ok(der) = atv.value.to_der() else {
        return String::new();
    };
    let mut out = String::with_capacity(der.len() * 2);
    for byte in der {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Decode a typed extension by its associated OID, or `None` if absent/malformed.
fn find_extension<'a, T: AssociatedOid + Decode<'a>>(cert: &'a Certificate) -> Option<T> {
    let extensions = cert.tbs_certificate.extensions.as_ref()?;
    let ext = extensions.iter().find(|e| e.extn_id == T::OID)?;
    T::from_der(ext.extn_value.as_bytes()).ok()
}

/// Convert an X.509 `Time` to an [`OffsetDateTime`], or `None` if it falls
/// outside the representable range.
fn time_to_offset(time: Time) -> Option<OffsetDateTime> {
    let secs = i64::try_from(time.to_unix_duration().as_secs()).ok()?;
    OffsetDateTime::from_unix_timestamp(secs).ok()
}

/// Convert an X.509 `Time` to an RFC 3339 UTC string.
fn time_to_iso(time: Time) -> Option<String> {
    time_to_offset(time).and_then(|dt| dt.format(&Rfc3339).ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    // A self-signed "Test CA 1" certificate (the one used across the TSL
    // fixtures). Simple RSA cert: subject == issuer, BasicConstraints CA, no SKI.
    const TEST_CA_B64: &str = "MIICyTCCAbGgAwIBAgIUc+D/OLA1d/dW5cFrQg2HviXUFzowDQYJKoZIhvcNAQELBQAwFDESMBAGA1UEAwwJVGVzdCBDQSAxMB4XDTI0MDEwMTAwMDAwMFoXDTI1MDEwMTAwMDAwMFowFDESMBAGA1UEAwwJVGVzdCBDQSAxMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwNzyFsFN8OAvo2l99sjHg/PXt7OoGpDCywCFRq+NGcDhX7VemYoNESXNooYR2kU8rCOcKEOqi/l3ez87UKF9C2HDgs4+j/L9tuTUzGOcUTfBidSH99psSGJvUefg9pqq1j+D22wIL37JMBnW8ZxfkvXTlETCguURSaEkbm9tHMwx5l1Kd0PYiYLv+oU+ThQSa05Y8+Hd4bImolAZzA8WNqR469KF2SePq/rV6G8U1l6pYBEKdEAOXVNFq6sT/p0dN/CPwyant7bZXRcqejyG9UZrkuTniOJlL1LGxSI/J0JKkvAJgsAdqJOCk4mVneMmU3aYUM4UdoL0ZPQP3IqcpwIDAQABoxMwETAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAIyXXHFwIszwMoxYTe3SCOdtlE6bAwOEqaZBODLVXjNqgV16QvwVV2eL2Jox3Ya7ErVk7NsnRW2N8l1+mO5vF8a5aUxXdyyJ+Ht0PNkr3rmc739OgUzZgLikFVwJxpbADNuYC3gkWEDmBn4V08HW8x/yfFCPMLSTl9qpqUmjEpWPvJsMN9D1Vp9WaI1vAT5PSU8zzLeCQfRVFH6rrnsBRE2PUnmfx+r22M8yZl3cAlyciMyobdQtRy/KFru8/LXpWXKut/ZqC8aMoAuZJwJhhHFH2QrvIkav6Aqus8LBf6KNfhT96gnfI4N8/4UrmY/kEzapJPz414vJTb6S2bviK6";

    fn test_ca() -> Certificate {
        let der = base64::engine::general_purpose::STANDARD
            .decode(TEST_CA_B64)
            .expect("valid base64");
        parse_der(&der).expect("valid cert")
    }

    #[test]
    fn parses_and_reads_common_name() {
        let cert = test_ca();
        assert_eq!(common_name(&cert).as_deref(), Some("Test CA 1"));
    }

    #[test]
    fn subject_dn_contains_cn() {
        let cert = test_ca();
        assert_eq!(subject_dn(&cert), "CN=Test CA 1");
    }

    #[test]
    fn illegal_printablestring_email_decodes_leniently() {
        // '@' is outside the PrintableString charset, so the strict decoder
        // rejects it; the latin-1 fallback recovers the value (asn1crypto does
        // the same). This is exactly what EKENG's emailAddress looks like.
        let value = Any::new(Tag::PrintableString, b"selfsurfer@gmail.com".to_vec())
            .expect("any construction");
        let atv = AttributeTypeAndValue {
            oid: OID_EMAIL,
            value,
        };
        assert_eq!(atv_to_string(&atv).as_deref(), Some("selfsurfer@gmail.com"));
    }

    #[test]
    fn valid_printablestring_uses_strict_decoder() {
        // A charset-legal value still goes through the strict path unchanged.
        let value = Any::new(Tag::PrintableString, b"Test CA 1".to_vec()).unwrap();
        let atv = AttributeTypeAndValue { oid: OID_CN, value };
        assert_eq!(atv_to_string(&atv).as_deref(), Some("Test CA 1"));
    }

    #[test]
    fn self_signed_ca_reports_self_signed() {
        let cert = test_ca();
        assert!(is_self_signed(&cert));
        // Issuer and subject DN are identical for a self-signed cert.
        assert_eq!(subject_dn(&cert), issuer_dn(&cert));
    }

    #[test]
    fn validity_is_iso_utc() {
        let cert = test_ca();
        assert_eq!(
            not_before_iso(&cert).as_deref(),
            Some("2024-01-01T00:00:00Z")
        );
        assert_eq!(
            not_after_iso(&cert).as_deref(),
            Some("2025-01-01T00:00:00Z")
        );
    }

    #[test]
    fn bytes_to_decimal_matches_known_values() {
        assert_eq!(bytes_to_decimal(&[]), "0");
        assert_eq!(bytes_to_decimal(&[0x00]), "0");
        assert_eq!(bytes_to_decimal(&[0x00, 0x00]), "0");
        assert_eq!(bytes_to_decimal(&[0xFF]), "255");
        assert_eq!(bytes_to_decimal(&[0x01, 0x00]), "256");
        // Leading sign-pad byte is ignored (positive INTEGER, high bit set).
        assert_eq!(bytes_to_decimal(&[0x00, 0xFF]), "255");
        // 2^64 = 18446744073709551616 -- exceeds u64, exercising bignum path.
        assert_eq!(
            bytes_to_decimal(&[0x01, 0, 0, 0, 0, 0, 0, 0, 0]),
            "18446744073709551616"
        );
    }

    #[test]
    fn serial_decimal_reads_certificate_serial() {
        // The fixture's serial is 0x73E0FF38B03577F756E5C16B420D87BE25D4173A.
        let cert = test_ca();
        assert_eq!(
            serial_decimal(&cert),
            "661551538492159303500604373203265997316050655034"
        );
    }

    #[test]
    fn absent_extensions_are_none() {
        // This fixture carries only BasicConstraints -- no SKI/AKI/AIA.
        let cert = test_ca();
        assert_eq!(subject_key_identifier(&cert), None);
        assert_eq!(authority_key_id(&cert), None);
        assert!(aia_ca_issuer_urls(&cert).is_empty());
    }

    #[test]
    fn reads_ski_and_aki_from_leaf() {
        let leaf = parse_der(include_bytes!("testdata/leaf.der")).unwrap();
        assert_eq!(subject_key_identifier(&leaf).map(|v| v.len()), Some(20));
        assert_eq!(authority_key_id(&leaf).map(|v| v.len()), Some(20));
    }

    #[test]
    fn leaf_aki_matches_issuer_ski() {
        // The leaf's AKI keyIdentifier must equal the intermediate's SKI --
        // this is the link chain building follows.
        let leaf = parse_der(include_bytes!("testdata/leaf.der")).unwrap();
        let inter = parse_der(include_bytes!("testdata/intermediate.der")).unwrap();
        assert_eq!(authority_key_id(&leaf), subject_key_identifier(&inter));
    }

    #[test]
    fn reads_aia_ca_issuer_urls() {
        let leaf = parse_der(include_bytes!("testdata/leaf_aia.der")).unwrap();
        assert_eq!(aia_ca_issuer_urls(&leaf), ["http://example.com/inter.crt"]);
    }

    #[test]
    fn wide_window_cert_is_currently_valid() {
        let leaf = parse_der(include_bytes!("testdata/leaf.der")).unwrap();
        assert!(is_currently_valid(&leaf));
    }

    #[test]
    fn rejects_garbage_der() {
        assert!(parse_der(b"not a certificate").is_err());
    }
}
