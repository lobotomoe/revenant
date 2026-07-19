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
use cms::signed_data::{SignedData, SignerIdentifier, SignerInfo};
use const_oid::{AssociatedOid, ObjectIdentifier};
use der::asn1::OctetStringRef;
use der::referenced::OwnedToRef;
use der::{AnyRef, Decode, Encode, Reader, SliceReader, Tag};
use spki::{AlgorithmIdentifierOwned, AlgorithmIdentifierRef};
use x509_cert::ext::pkix::SubjectKeyIdentifier;
use x509_cert::Certificate;
use x509_verify::{Signature, VerifyInfo, VerifyingKey};

use super::digest::DigestAlgorithm;
use super::signed_data_from_der;

/// The `contentType` signed attribute (RFC 5652 section 11.1). When signed
/// attributes are present it is mandatory and must equal `eContentType`.
const OID_CONTENT_TYPE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");

/// The ESS `signingCertificate` (v1) and `signingCertificateV2` signed
/// attributes (RFC 5035). Each carries the hash of the certificate the signer
/// intends to be verified with, binding the signature to that exact certificate
/// to defeat substitution attacks. v1 always hashes with SHA-1; v2 carries its
/// own hash algorithm (default SHA-256). EKENG CoSign emits the v1 form.
const OID_SIGNING_CERTIFICATE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.12");
const OID_SIGNING_CERTIFICATE_V2: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.47");

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
        // The signature is authentic. Before vouching for validity, assert the
        // signed attributes are conformant: an authentic signature over a
        // non-conformant attribute set is not a valid CMS signature, and
        // reporting it Valid would over-claim.
        Ok(()) => finalize_valid(signed_data, signer_info, signer_cert),
        // Only a genuine signature-verification failure means the bytes or the
        // certificate were tampered with. Any other error (unusable key,
        // unsupported OID, DER decode failure) means the check could not be
        // performed at all -- fail closed as Unverifiable rather than falsely
        // asserting the signature is forged.
        Err(x509_verify::Error::Verification | x509_verify::Error::InvalidSignature) => {
            SignatureStatus::Invalid
        }
        Err(_) => SignatureStatus::Unverifiable("signature could not be checked"),
    }
}

/// The signer's signature verified cryptographically. Promote it to `Valid` only
/// if the mandatory and binding signed attributes agree with what was verified;
/// otherwise fail closed. This keeps `Valid` meaning "authentic *and*
/// conformant", never merely "the RSA math checked out".
fn finalize_valid(
    signed_data: &SignedData,
    signer_info: &SignerInfo,
    signer_cert: &Certificate,
) -> SignatureStatus {
    if !content_type_ok(signed_data, signer_info) {
        return SignatureStatus::Unverifiable("contentType attribute missing or inconsistent");
    }
    match signing_cert_binding(signer_info, signer_cert) {
        SigningCertBinding::Absent | SigningCertBinding::Match => SignatureStatus::Valid,
        SigningCertBinding::Mismatch => SignatureStatus::Unverifiable(
            "signingCertificate attribute names a different certificate",
        ),
        SigningCertBinding::Unparsable => {
            SignatureStatus::Unverifiable("signingCertificate attribute could not be parsed")
        }
    }
}

/// Whether the `contentType` signed attribute is present and equals the
/// encapsulated `eContentType`.
///
/// RFC 5652 section 11.1 makes `contentType` mandatory whenever signed
/// attributes are present, and it must match `encapContentInfo.eContentType`.
/// A conformant CMS (including the CoSign appliance's output) always satisfies
/// this; a blob that omits or contradicts it is not something we should report
/// as a valid signature.
fn content_type_ok(signed_data: &SignedData, signer_info: &SignerInfo) -> bool {
    let Some(signed_attrs) = signer_info.signed_attrs.as_ref() else {
        return false;
    };
    signed_attrs
        .iter()
        .find(|attr| attr.oid == OID_CONTENT_TYPE)
        .and_then(|attr| attr.values.iter().next())
        .and_then(|value| value.decode_as::<ObjectIdentifier>().ok())
        .is_some_and(|oid| oid == signed_data.encap_content_info.econtent_type)
}

/// The outcome of checking the ESS `signingCertificate[V2]` binding.
enum SigningCertBinding {
    /// No `signingCertificate[V2]` attribute is present. Plain CMS omits it, so
    /// its absence is conformant and imposes no constraint.
    Absent,
    /// The attribute is present and its ESSCertID hash matches the certificate
    /// whose key verified the signature.
    Match,
    /// The attribute is present but binds a *different* certificate than the one
    /// that verified -- a substitution indicator.
    Mismatch,
    /// The attribute is present but could not be parsed -- fail closed.
    Unparsable,
}

/// Check the ESS `signingCertificate` (v1) / `signingCertificateV2` binding.
///
/// When present, the attribute pins the hash of the intended signer certificate
/// (RFC 5035). It must match the certificate whose key verified the signature,
/// otherwise an attacker could swap a different certificate into the CMS. The
/// attribute is optional, so its absence is reported as [`SigningCertBinding::Absent`]
/// and does not block a `Valid` verdict.
fn signing_cert_binding(signer_info: &SignerInfo, signer_cert: &Certificate) -> SigningCertBinding {
    let Some(signed_attrs) = signer_info.signed_attrs.as_ref() else {
        return SigningCertBinding::Absent;
    };

    let (attr, v2) = if let Some(attr) = signed_attrs
        .iter()
        .find(|a| a.oid == OID_SIGNING_CERTIFICATE)
    {
        (attr, false)
    } else if let Some(attr) = signed_attrs
        .iter()
        .find(|a| a.oid == OID_SIGNING_CERTIFICATE_V2)
    {
        (attr, true)
    } else {
        return SigningCertBinding::Absent;
    };

    let Some((algo, want_hash)) = attr
        .values
        .iter()
        .next()
        .and_then(|value| value.to_der().ok())
        .and_then(|der| ess_cert_hash(&der, v2))
    else {
        return SigningCertBinding::Unparsable;
    };

    // The hash is over the certificate's exact DER encoding. Re-encoding the
    // parsed certificate reproduces those bytes for any canonical-DER input
    // (which every conformant X.509 certificate is).
    let Ok(cert_der) = signer_cert.to_der() else {
        return SigningCertBinding::Unparsable;
    };
    if algo.hash(&cert_der) == want_hash {
        SigningCertBinding::Match
    } else {
        SigningCertBinding::Mismatch
    }
}

/// Extract the (hash algorithm, certHash) of the first `ESSCertID`/`ESSCertIDv2`
/// in a `SigningCertificate`/`SigningCertificateV2` attribute value.
///
/// Structure (RFC 5035), descending three nested SEQUENCE layers to the cert:
/// `SigningCertificate ::= SEQUENCE { certs SEQUENCE OF ESSCertID, ... }` and
/// `ESSCertID ::= SEQUENCE { certHash OCTET STRING, issuerSerial OPTIONAL }`.
/// v2 differs only in an optional leading `hashAlgorithm` (DEFAULT SHA-256).
/// Trailing optional fields are ignored; only the first cert's hash is needed.
fn ess_cert_hash(signing_cert_der: &[u8], v2: bool) -> Option<(DigestAlgorithm, Vec<u8>)> {
    let signing_cert_body = first_seq_content(signing_cert_der)?;
    let certs_body = first_seq_content(signing_cert_body)?;
    let ess_cert_id_body = first_seq_content(certs_body)?;

    let mut reader = SliceReader::new(ess_cert_id_body).ok()?;
    let algo = if v2 {
        // ESSCertIDv2 leads with an optional AlgorithmIdentifier (a SEQUENCE);
        // when the default SHA-256 is used it is omitted and certHash comes first.
        if reader.peek_header().ok()?.tag == Tag::Sequence {
            let alg = reader.decode::<AlgorithmIdentifierRef<'_>>().ok()?;
            DigestAlgorithm::from_oid(&alg.oid)?
        } else {
            DigestAlgorithm::Sha256
        }
    } else {
        DigestAlgorithm::Sha1
    };
    let cert_hash = reader.decode::<OctetStringRef<'_>>().ok()?;
    Some((algo, cert_hash.as_bytes().to_vec()))
}

/// Read the first TLV of `body`, require it to be a SEQUENCE, and return the
/// bytes of its content (what lies between the header and the end of the value).
fn first_seq_content(body: &[u8]) -> Option<&[u8]> {
    let mut reader = SliceReader::new(body).ok()?;
    if reader.peek_header().ok()?.tag != Tag::Sequence {
        return None;
    }
    let tlv = reader.tlv_bytes().ok()?;
    AnyRef::from_der(tlv).ok().map(AnyRef::value)
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

    // ── ESS signingCertificate parsing ──────────────────────────────────

    /// Wrap `content` in an ASN.1 TLV with `tag` (definite length, up to 3 bytes).
    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        let len = content.len();
        if len < 0x80 {
            out.push(u8::try_from(len).unwrap());
        } else if len < 0x100 {
            out.push(0x81);
            out.push(u8::try_from(len).unwrap());
        } else {
            out.push(0x82);
            out.push(u8::try_from(len >> 8).unwrap());
            out.push(u8::try_from(len & 0xff).unwrap());
        }
        out.extend_from_slice(content);
        out
    }

    /// Build a `SigningCertificate` (v1) value carrying one ESSCertID `cert_hash`.
    fn v1_signing_cert(cert_hash: &[u8]) -> Vec<u8> {
        let ess_cert_id = tlv(0x30, &tlv(0x04, cert_hash));
        tlv(0x30, &tlv(0x30, &ess_cert_id)) // SigningCertificate { certs { ESSCertID } }
    }

    /// Build a `SigningCertificateV2` value; `alg_id` is the optional leading
    /// hashAlgorithm AlgorithmIdentifier (absent => default SHA-256).
    fn v2_signing_cert(cert_hash: &[u8], alg_id: Option<&[u8]>) -> Vec<u8> {
        let mut ess_cert_id_body = Vec::new();
        if let Some(alg) = alg_id {
            ess_cert_id_body.extend_from_slice(alg);
        }
        ess_cert_id_body.extend_from_slice(&tlv(0x04, cert_hash));
        tlv(0x30, &tlv(0x30, &tlv(0x30, &ess_cert_id_body)))
    }

    #[test]
    fn ess_v1_parses_real_ekeng_structure() {
        // The exact SigningCertificate value from a genuine EKENG CoSign
        // signature: SEQ { SEQ { SEQ { OCTET STRING(20) } } }, SHA-1 certHash.
        let real = [
            0x30, 0x1A, 0x30, 0x18, 0x30, 0x16, 0x04, 0x14, 0x36, 0x36, 0x5A, 0x81, 0x69, 0x93,
            0x10, 0x6B, 0xCE, 0x0F, 0xCD, 0x46, 0xB9, 0x6B, 0xE1, 0x75, 0xB6, 0xC2, 0x3E, 0x64,
        ];
        let (algo, hash) = ess_cert_hash(&real, false).expect("v1 ESSCertID parses");
        assert_eq!(algo, DigestAlgorithm::Sha1);
        assert_eq!(hash, real[8..]);
    }

    #[test]
    fn ess_v1_recovers_certificate_hash() {
        // A signingCertificate built from a real certificate's SHA-1 parses back
        // to exactly that hash -- the equality the binding check relies on.
        let cert = Certificate::from_der(include_bytes!("../pki/testdata/leaf.der")).unwrap();
        let want = DigestAlgorithm::Sha1.hash(&cert.to_der().unwrap());
        let (algo, got) = ess_cert_hash(&v1_signing_cert(&want), false).unwrap();
        assert_eq!(algo, DigestAlgorithm::Sha1);
        assert_eq!(got, want);
        // A perturbed hash parses to a different value -> Mismatch would result.
        let mut wrong = want.clone();
        wrong[0] ^= 0x01;
        assert_ne!(
            ess_cert_hash(&v1_signing_cert(&wrong), false).unwrap().1,
            want
        );
    }

    #[test]
    fn ess_v2_default_algorithm_is_sha256() {
        let hash = [0xABu8; 32];
        let (algo, got) = ess_cert_hash(&v2_signing_cert(&hash, None), true).unwrap();
        assert_eq!(algo, DigestAlgorithm::Sha256);
        assert_eq!(got, hash);
    }

    #[test]
    fn ess_v2_explicit_algorithm_is_honored() {
        // AlgorithmIdentifier { id-sha384 } with no parameters.
        let sha384_alg = tlv(
            0x30,
            &[
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
            ],
        );
        let hash = [0xCDu8; 48];
        let (algo, got) = ess_cert_hash(&v2_signing_cert(&hash, Some(&sha384_alg)), true).unwrap();
        assert_eq!(algo, DigestAlgorithm::Sha384);
        assert_eq!(got, hash);
    }

    #[test]
    fn ess_rejects_malformed() {
        assert!(ess_cert_hash(b"", false).is_none());
        assert!(ess_cert_hash(&[0x30, 0x00], false).is_none()); // empty SigningCertificate
        assert!(ess_cert_hash(&[0x04, 0x01, 0xAA], false).is_none()); // not a SEQUENCE
    }
}
