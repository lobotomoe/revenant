//! Cryptographic verification of a CMS `SignerInfo` signature.
//!
//! Signature authenticity rests on two independent facts. First, the
//! `messageDigest` signed attribute must equal the hash of the document's signed
//! byte range -- checked in [`crate::pdf::verify`]. Second, the signer's RSA
//! signature over the DER-encoded signed attributes must verify against the
//! signer's certificate, proving the holder of that certificate's private key
//! produced it. This module supplies the second fact; together they establish
//! that the named signer signed exactly this document.
//!
//! Only RSA (PKCS#1 v1.5) signers are verified -- the CoSign appliance signs with
//! RSA. Any other algorithm, an absent signer certificate, missing signed
//! attributes, or an unparsable blob yields [`SignatureStatus::Unverifiable`]:
//! the check fails closed and never silently reports a signature as authentic.

use cms::cert::CertificateChoices;
use cms::signed_data::{SignedData, SignerIdentifier};
use const_oid::{AssociatedOid, ObjectIdentifier};
use der::referenced::OwnedToRef;
use der::{Decode, Encode};
use spki::AlgorithmIdentifierOwned;
use x509_cert::ext::pkix::SubjectKeyIdentifier;
use x509_cert::Certificate;
use x509_verify::{Signature, VerifyInfo, VerifyingKey};

use super::digest::DigestAlgorithm;
use super::signed_data_from_der;

/// Bare RSA key OID (`rsaEncryption`) -- CMS puts this in `signatureAlgorithm`
/// and carries the hash separately in `digestAlgorithm`.
const OID_RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const OID_SHA1_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.5");
const OID_SHA256_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const OID_SHA384_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12");
const OID_SHA512_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13");

/// The result of cryptographically verifying a `SignerInfo` signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureStatus {
    /// The signer's signature over the signed attributes verifies.
    Valid,
    /// The signature is present and well-formed but does not verify -- the
    /// document or the CMS was tampered with, or the certificate does not match.
    Invalid,
    /// Verification could not be performed. Fail-closed: never treated as valid.
    Unverifiable(&'static str),
}

impl SignatureStatus {
    /// Whether the signature cryptographically verified.
    #[must_use]
    pub fn is_valid(self) -> bool {
        matches!(self, Self::Valid)
    }

    /// A human-readable diagnostic line for the verification report.
    #[must_use]
    pub fn describe(self) -> String {
        match self {
            Self::Valid => "Signature OK -- signer signature verifies".to_owned(),
            Self::Invalid => {
                "Signature INVALID -- does not verify against the signer certificate".to_owned()
            }
            Self::Unverifiable(why) => format!("Signature not verified ({why})"),
        }
    }
}

/// Verify the first `SignerInfo`'s signature in a CMS/PKCS#7 blob.
#[must_use]
pub fn verify_signer_signature(cms_der: &[u8]) -> SignatureStatus {
    match signed_data_from_der(cms_der) {
        Ok(signed_data) => verify_from_signed_data(&signed_data),
        Err(_) => SignatureStatus::Unverifiable("CMS did not parse"),
    }
}

fn verify_from_signed_data(signed_data: &SignedData) -> SignatureStatus {
    let Some(signer_info) = signed_data.signer_infos.0.iter().next() else {
        return SignatureStatus::Unverifiable("no SignerInfo present");
    };
    let Some(digest_alg) = DigestAlgorithm::from_oid(&signer_info.digest_alg.oid) else {
        return SignatureStatus::Unverifiable("unrecognized digest algorithm");
    };
    if !is_rsa(&signer_info.signature_algorithm.oid) {
        return SignatureStatus::Unverifiable("non-RSA signer is unsupported");
    }

    let certs = embedded_certificates(signed_data);
    let Some(signer_cert) = find_signer_cert(&certs, &signer_info.sid) else {
        return SignatureStatus::Unverifiable("signer certificate not embedded");
    };

    // The signature is computed over the signed attributes re-encoded as an
    // EXPLICIT SET OF (RFC 5652 section 5.4): the [0] IMPLICIT tag under which
    // they appear in the SignerInfo is replaced by the universal SET OF tag.
    let Some(signed_attrs) = signer_info.signed_attrs.as_ref() else {
        return SignatureStatus::Unverifiable("no signed attributes");
    };
    let Ok(message) = signed_attrs.to_der() else {
        return SignatureStatus::Unverifiable("cannot re-encode signed attributes");
    };

    // x509-verify dispatches on the *signature* algorithm OID and hashes the
    // message itself, and it only understands the combined <hash>WithRSAEncryption
    // OIDs. CMS stores the bare rsaEncryption OID with the hash in a separate
    // field, so synthesize the combined identifier from the digest algorithm.
    let algorithm = AlgorithmIdentifierOwned {
        oid: rsa_with_hash_oid(digest_alg),
        parameters: None,
    };
    let signature = Signature::new(&algorithm, signer_info.signature.as_bytes());
    let spki = signer_cert
        .tbs_certificate
        .subject_public_key_info
        .owned_to_ref();
    let Ok(key) = VerifyingKey::try_from(spki) else {
        return SignatureStatus::Unverifiable("signer public key is unusable");
    };

    let verify_info = VerifyInfo::new(message.into(), signature);
    match key.verify(&verify_info) {
        Ok(()) => SignatureStatus::Valid,
        Err(_) => SignatureStatus::Invalid,
    }
}

/// The X.509 certificates carried in the SignedData, in order.
fn embedded_certificates(signed_data: &SignedData) -> Vec<Certificate> {
    match &signed_data.certificates {
        Some(set) => set
            .0
            .iter()
            .filter_map(|choice| match choice {
                CertificateChoices::Certificate(cert) => Some(cert.clone()),
                CertificateChoices::Other(_) => None,
            })
            .collect(),
        None => Vec::new(),
    }
}

/// Locate the signer's certificate among the embedded certs by its identifier.
fn find_signer_cert<'a>(
    certs: &'a [Certificate],
    signer_id: &SignerIdentifier,
) -> Option<&'a Certificate> {
    match signer_id {
        SignerIdentifier::IssuerAndSerialNumber(ias) => certs.iter().find(|cert| {
            cert.tbs_certificate.issuer == ias.issuer
                && cert.tbs_certificate.serial_number == ias.serial_number
        }),
        SignerIdentifier::SubjectKeyIdentifier(skid) => {
            let want = skid.0.as_bytes();
            certs
                .iter()
                .find(|cert| cert_ski(cert).as_deref() == Some(want))
        }
    }
}

/// The Subject Key Identifier extension value of a certificate, if present.
fn cert_ski(cert: &Certificate) -> Option<Vec<u8>> {
    let extensions = cert.tbs_certificate.extensions.as_ref()?;
    let ext = extensions
        .iter()
        .find(|e| e.extn_id == SubjectKeyIdentifier::OID)?;
    SubjectKeyIdentifier::from_der(ext.extn_value.as_bytes())
        .ok()
        .map(|ski| ski.0.as_bytes().to_vec())
}

/// Whether the signature-algorithm OID names an RSA signature.
fn is_rsa(oid: &ObjectIdentifier) -> bool {
    matches!(
        *oid,
        OID_RSA_ENCRYPTION | OID_SHA1_RSA | OID_SHA256_RSA | OID_SHA384_RSA | OID_SHA512_RSA
    )
}

/// The `<hash>WithRSAEncryption` OID matching a digest algorithm.
fn rsa_with_hash_oid(digest: DigestAlgorithm) -> ObjectIdentifier {
    match digest {
        DigestAlgorithm::Sha1 => OID_SHA1_RSA,
        DigestAlgorithm::Sha256 => OID_SHA256_RSA,
        DigestAlgorithm::Sha384 => OID_SHA384_RSA,
        DigestAlgorithm::Sha512 => OID_SHA512_RSA,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Real CMS fixtures generated with a known key (see generate_fixtures.py);
    // each carries a genuine RSA signature over its signed attributes.
    const CMS_LEAF_DIRECT: &[u8] = include_bytes!("../pki/testdata/cms_leaf_direct.der");
    const CMS_CHAIN3: &[u8] = include_bytes!("../pki/testdata/cms_chain3.der");

    #[test]
    fn valid_signature_verifies() {
        assert_eq!(
            verify_signer_signature(CMS_LEAF_DIRECT),
            SignatureStatus::Valid
        );
        assert_eq!(verify_signer_signature(CMS_CHAIN3), SignatureStatus::Valid);
    }

    #[test]
    fn tampered_signature_is_invalid() {
        // Flip a byte inside the SignerInfo signature: still a well-formed CMS,
        // but the signature no longer verifies -> Invalid, not Unverifiable.
        let mut tampered = CMS_LEAF_DIRECT.to_vec();
        let last = tampered.len() - 5;
        tampered[last] ^= 0xFF;
        assert_eq!(
            verify_signer_signature(&tampered),
            SignatureStatus::Invalid,
            "a tampered signature must be Invalid"
        );
    }

    #[test]
    fn garbage_is_unverifiable_not_valid() {
        assert!(matches!(
            verify_signer_signature(b"not a cms blob at all"),
            SignatureStatus::Unverifiable(_)
        ));
    }

    #[test]
    fn status_helpers() {
        assert!(SignatureStatus::Valid.is_valid());
        assert!(!SignatureStatus::Invalid.is_valid());
        assert!(!SignatureStatus::Unverifiable("x").is_valid());
        assert!(SignatureStatus::Invalid.describe().contains("INVALID"));
    }
}
