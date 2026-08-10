//! Test-only helpers that produce genuine CMS signatures.
//!
//! The signing workflow refuses a response it cannot verify, so tests can no
//! longer stand filler bytes in for the appliance's answer -- they have to sign
//! for real, over data that only exists at test time (a prepared PDF's
//! ByteRange is computed during the call). A committed certificate and its
//! private key make that possible without a network or a keygen per test.
//!
//! Compiled under `cfg(test)` only; none of this reaches the shipped library.

use std::time::Duration;

use cms::builder::{SignedDataBuilder, SignerInfoBuilder};
use cms::cert::CertificateChoices;
use cms::signed_data::{EncapsulatedContentInfo, SignerIdentifier};
use const_oid::db::rfc5911::ID_DATA;
use const_oid::db::rfc5912::ID_SHA_256;
use der::{Decode, Encode};
use rsa::pkcs1v15::{Signature, SigningKey};
use rsa::pkcs8::DecodePrivateKey;
use rsa::RsaPrivateKey;
use sha2::{Digest, Sha256};
use spki::AlgorithmIdentifierOwned;
use x509_cert::Certificate;

use crate::net::SigningTransport;
use crate::Result;

const SIGNER_CERT_DER: &[u8] = include_bytes!("pki/testdata/test_signer_cert.der");
const SIGNER_KEY_DER: &[u8] = include_bytes!("pki/testdata/test_signer_key.der");

/// The certificate the test signer signs with.
#[must_use]
pub(crate) fn signer_certificate() -> Certificate {
    Certificate::from_der(SIGNER_CERT_DER).expect("committed test certificate must parse")
}

/// Build a detached CMS/PKCS#7 `SignedData` over `content`.
///
/// Detached in the same sense as the appliance's output: no `eContent`, and the
/// digest of the signed bytes travels in the `messageDigest` signed attribute.
/// SHA-256 rather than the appliance's SHA-1 -- verification auto-detects the
/// algorithm, and a test signer has no reason to reach for a weaker one.
///
/// # Panics
///
/// Panics if the committed key or certificate cannot be used, which would mean
/// the fixtures themselves are broken.
#[must_use]
pub(crate) fn sign_cms_detached(content: &[u8]) -> Vec<u8> {
    let private_key =
        RsaPrivateKey::from_pkcs8_der(SIGNER_KEY_DER).expect("committed test key must parse");
    let signing_key = SigningKey::<Sha256>::new(private_key);
    let certificate = signer_certificate();

    let sid = SignerIdentifier::IssuerAndSerialNumber(cms::cert::IssuerAndSerialNumber {
        issuer: certificate.tbs_certificate.issuer.clone(),
        serial_number: certificate.tbs_certificate.serial_number.clone(),
    });
    let digest_algorithm = AlgorithmIdentifierOwned {
        oid: ID_SHA_256,
        parameters: None,
    };
    let encap = EncapsulatedContentInfo {
        econtent_type: ID_DATA,
        econtent: None,
    };

    let message_digest = Sha256::digest(content);
    let signer_info = SignerInfoBuilder::new(
        &signing_key,
        sid,
        digest_algorithm.clone(),
        &encap,
        Some(&message_digest),
    )
    .expect("signer info builder must accept a detached digest");

    let content_info = SignedDataBuilder::new(&encap)
        .add_digest_algorithm(digest_algorithm)
        .expect("digest algorithm must be accepted")
        .add_certificate(CertificateChoices::Certificate(certificate))
        .expect("certificate must be accepted")
        .add_signer_info::<SigningKey<Sha256>, Signature>(signer_info)
        .expect("signing must succeed")
        .build()
        .expect("SignedData must assemble");

    content_info
        .to_der()
        .expect("assembled SignedData must encode")
}

/// A transport that signs whatever it is handed, the way an appliance does.
///
/// `sign_hash` signs the digest bytes as content rather than treating them as a
/// pre-computed digest -- matching what the production appliance was observed to
/// do, so tests exercise the shape callers actually receive.
pub(crate) struct TestSigner;

impl SigningTransport for TestSigner {
    fn sign_data(&self, data: &[u8], _: &str, _: &str, _: Duration) -> Result<Vec<u8>> {
        Ok(sign_cms_detached(data))
    }
    fn sign_hash(&self, hash: &[u8], _: &str, _: &str, _: Duration) -> Result<Vec<u8>> {
        Ok(sign_cms_detached(hash))
    }
    fn sign_pdf_detached(&self, pdf: &[u8], _: &str, _: &str, _: Duration) -> Result<Vec<u8>> {
        Ok(sign_cms_detached(pdf))
    }
}
