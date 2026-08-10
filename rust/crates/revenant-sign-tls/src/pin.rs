//! Server key pinning.
//!
//! A pin is the SHA-256 digest of a certificate's `SubjectPublicKeyInfo`,
//! written as lowercase hex. Pinning the key rather than the whole certificate
//! lets a server be issued a fresh certificate for the same key without
//! invalidating the pin, and several pins may be given so a key rotation can
//! be staged.
//!
//! This is the only thing authenticating the peer on a legacy connection. The
//! appliances this crate exists for present a self-signed factory certificate
//! whose subject does not name the host it serves, so no certificate authority
//! vouches for it and no hostname check can succeed -- a pinned key is what
//! distinguishes the real appliance from anyone speaking for it.

use der::Encode;
use sha2::{Digest, Sha256};
use spki::SubjectPublicKeyInfoOwned;

use crate::error::TlsError;

/// The pin for a certificate's public key, as lowercase hex.
pub(crate) fn spki_fingerprint(spki: &SubjectPublicKeyInfoOwned) -> Result<String, TlsError> {
    let der = spki.to_der().map_err(|err| {
        TlsError::Certificate(format!("cannot re-encode server public key: {err}"))
    })?;
    Ok(hex_lower(&Sha256::digest(&der)))
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        // Writing to a String cannot fail.
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Strip the formatting operators write pins with, so comparison is on content.
fn normalise(pin: &str) -> String {
    pin.trim().to_ascii_lowercase().replace(':', "")
}

/// Verify that a server's key matches one of the configured pins.
///
/// An empty `pins` means the server has no declared identity, which is
/// refused rather than assumed benign.
///
/// # Errors
///
/// Returns [`TlsError::Pin`] if no pin was given, or none of them matches.
pub(crate) fn check<P: AsRef<str>>(
    spki: &SubjectPublicKeyInfoOwned,
    pins: &[P],
    host: &str,
    port: u16,
) -> Result<(), TlsError> {
    let actual = spki_fingerprint(spki)?;

    if pins.is_empty() {
        return Err(TlsError::Pin(format!(
            "no pinned key configured for {host}:{port}. Legacy TLS does not \
             authenticate the server on its own, so a pinned key is required \
             before anything is sent.\n\
             The server currently presents: {actual}\n\
             If that is your appliance, record it as the profile's tls_pins."
        )));
    }

    let normalised: Vec<String> = pins.iter().map(|p| normalise(p.as_ref())).collect();
    if normalised.contains(&actual) {
        log::debug!("server key for {host}:{port} matches a pinned key");
        return Ok(());
    }

    Err(TlsError::Pin(format!(
        "the key presented by {host}:{port} is not one of its pinned keys. \
         Refusing to continue.\n  \
         presented: {actual}\n  \
         pinned:    {}\n\
         Either the server's key changed, or this is not the server it claims to be.",
        normalised.join(", ")
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::Decode as _;
    use x509_cert::Certificate;

    const SIGNER_CERT: &[u8] =
        include_bytes!("../../revenant-sign-core/src/pki/testdata/test_signer_cert.der");
    const OTHER_CERT: &[u8] = include_bytes!("../../revenant-sign-core/src/pki/testdata/leaf.der");

    fn spki_of(der: &[u8]) -> SubjectPublicKeyInfoOwned {
        Certificate::from_der(der)
            .expect("fixture parses")
            .tbs_certificate
            .subject_public_key_info
    }

    fn pin_of(der: &[u8]) -> String {
        spki_fingerprint(&spki_of(der)).expect("fixture has a readable key")
    }

    #[test]
    fn fingerprint_is_stable_and_key_specific() {
        let pin = pin_of(SIGNER_CERT);
        assert_eq!(pin.len(), 64);
        assert_eq!(pin, pin_of(SIGNER_CERT));
        assert_ne!(pin, pin_of(OTHER_CERT));
    }

    #[test]
    fn matching_pin_is_accepted() {
        let spki = spki_of(SIGNER_CERT);
        check(&spki, &[pin_of(SIGNER_CERT)], "appliance.example", 8080)
            .expect("the pinned key must be accepted");
    }

    #[test]
    fn pin_matching_ignores_case_and_colons() {
        let pin = pin_of(SIGNER_CERT);
        let formatted: String = pin
            .as_bytes()
            .chunks(2)
            .map(|pair| String::from_utf8_lossy(pair).to_uppercase())
            .collect::<Vec<_>>()
            .join(":");
        check(
            &spki_of(SIGNER_CERT),
            &[formatted],
            "appliance.example",
            8080,
        )
        .expect("formatting must not change the comparison");
    }

    #[test]
    fn any_of_several_pins_may_match() {
        let pins = vec!["00".repeat(32), pin_of(SIGNER_CERT)];
        check(&spki_of(SIGNER_CERT), &pins, "appliance.example", 8080)
            .expect("a staged rotation must keep working");
    }

    #[test]
    fn a_different_key_is_refused_and_both_sides_are_named() {
        let err = check(
            &spki_of(OTHER_CERT),
            &[pin_of(SIGNER_CERT)],
            "appliance.example",
            8080,
        )
        .expect_err("someone else's key must be refused");
        let message = err.to_string();
        // Both sides are named so the operator can tell a rotation from an attack.
        assert!(message.contains(&pin_of(OTHER_CERT)));
        assert!(message.contains(&pin_of(SIGNER_CERT)));
    }

    #[test]
    fn no_pin_is_refused_and_reports_what_the_server_presented() {
        let empty: [String; 0] = [];
        let err = check(&spki_of(SIGNER_CERT), &empty, "appliance.example", 8080)
            .expect_err("an empty pin list is not 'any key'");
        let message = err.to_string();
        assert!(message.contains("no pinned key configured"));
        assert!(message.contains(&pin_of(SIGNER_CERT)));
    }
}
