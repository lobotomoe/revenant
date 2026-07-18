//! Digest-algorithm identification and `messageDigest` extraction from a CMS
//! `SignerInfo`.
//!
//! CoSign has a quirk: it puts the *signature* algorithm OID
//! (`sha256WithRSAEncryption`) in the `digestAlgorithm` field instead of the
//! bare hash OID. [`DigestAlgorithm::from_oid`] therefore maps both the
//! plain-hash OIDs and the RSA-with-hash OIDs onto the same hash.

use const_oid::ObjectIdentifier;
use der::asn1::OctetString;

use super::signed_data_from_der;

/// A cryptographic hash used as a CMS message digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestAlgorithm {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

// Bare hash OIDs.
const OID_SHA1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.14.3.2.26");
const OID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
const OID_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");
const OID_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3");

// RSA-with-hash signature OIDs (the CoSign quirk: these appear in the
// digestAlgorithm field), mapped to their underlying hash.
const OID_SHA1_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.5");
const OID_SHA256_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const OID_SHA384_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12");
const OID_SHA512_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13");

/// OID for the `messageDigest` attribute in a CMS `SignerInfo`.
const OID_MESSAGE_DIGEST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");

impl DigestAlgorithm {
    /// Resolve a digest or RSA-with-hash algorithm OID to its hash, or `None`
    /// if the OID is not a recognized hash.
    #[must_use]
    pub fn from_oid(oid: &ObjectIdentifier) -> Option<Self> {
        match *oid {
            OID_SHA1 | OID_SHA1_RSA => Some(Self::Sha1),
            OID_SHA256 | OID_SHA256_RSA => Some(Self::Sha256),
            OID_SHA384 | OID_SHA384_RSA => Some(Self::Sha384),
            OID_SHA512 | OID_SHA512_RSA => Some(Self::Sha512),
            _ => None,
        }
    }

    /// The lowercase algorithm name (`"sha256"`), as shown in `info`/`cert`
    /// output.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
            Self::Sha384 => "sha384",
            Self::Sha512 => "sha512",
        }
    }

    /// The digest length in bytes.
    #[must_use]
    pub fn output_len(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    /// Compute this algorithm's digest of `data`.
    #[must_use]
    pub fn hash(self, data: &[u8]) -> Vec<u8> {
        use sha2::Digest as _;
        match self {
            Self::Sha1 => sha1::Sha1::digest(data).to_vec(),
            Self::Sha256 => sha2::Sha256::digest(data).to_vec(),
            Self::Sha384 => sha2::Sha384::digest(data).to_vec(),
            Self::Sha512 => sha2::Sha512::digest(data).to_vec(),
        }
    }
}

/// Extract the digest algorithm and `messageDigest` value from a CMS blob's
/// first `SignerInfo`.
///
/// Returns `None` (never an error) when the CMS does not parse, has no signer,
/// uses an unrecognized digest algorithm, or carries no signed `messageDigest`
/// attribute -- best-effort inspection.
#[must_use]
pub fn extract_digest_info(cms_der: &[u8]) -> Option<(DigestAlgorithm, Vec<u8>)> {
    let signed_data = signed_data_from_der(cms_der).ok()?;
    let signer_info = signed_data.signer_infos.0.iter().next()?;
    let algorithm = DigestAlgorithm::from_oid(&signer_info.digest_alg.oid)?;

    signer_info
        .signed_attrs
        .as_ref()?
        .iter()
        .find(|attr| attr.oid == OID_MESSAGE_DIGEST)
        .and_then(|attr| attr.values.iter().next())
        .and_then(|value| value.decode_as::<OctetString>().ok())
        .map(|digest| (algorithm, digest.into_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const CMS_LEAF_DIRECT: &[u8] = include_bytes!("../pki/testdata/cms_leaf_direct.der");
    // messageDigest = SHA-256("test data"), the encapsulated content of the fixtures.
    const EXPECTED_DIGEST: &str =
        "916f0027a575074ce72a331777c3478d6513f786a591bd892da1a577bf2335f9";

    #[test]
    fn maps_plain_and_rsa_oids() {
        assert_eq!(
            DigestAlgorithm::from_oid(&OID_SHA256),
            Some(DigestAlgorithm::Sha256)
        );
        assert_eq!(
            DigestAlgorithm::from_oid(&OID_SHA256_RSA),
            Some(DigestAlgorithm::Sha256)
        );
        assert_eq!(
            DigestAlgorithm::from_oid(&OID_SHA1_RSA),
            Some(DigestAlgorithm::Sha1)
        );
        let unknown = ObjectIdentifier::new_unwrap("1.2.3.4");
        assert_eq!(DigestAlgorithm::from_oid(&unknown), None);
    }

    #[test]
    fn names_and_lengths() {
        assert_eq!(DigestAlgorithm::Sha256.name(), "sha256");
        assert_eq!(DigestAlgorithm::Sha512.output_len(), 64);
    }

    #[test]
    fn extracts_sha256_message_digest() {
        let (algo, digest) = extract_digest_info(CMS_LEAF_DIRECT).unwrap();
        assert_eq!(algo, DigestAlgorithm::Sha256);
        assert_eq!(digest.len(), 32);
        assert_eq!(hex::encode(&digest), EXPECTED_DIGEST);
    }

    #[test]
    fn returns_none_on_garbage() {
        assert!(extract_digest_info(b"not a cms blob at all").is_none());
    }
}
