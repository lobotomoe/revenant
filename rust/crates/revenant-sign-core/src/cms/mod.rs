//! CMS/PKCS#7 reading: locating, extracting, and inspecting signatures.
//!
//! The read side of signing, gathered into one place: given a signed PDF (or a
//! bare CMS blob), it finds the signature, extracts the exact DER, and reports
//! the digest algorithm, signer identity, and LTV status. Certificate/chain
//! logic lives one layer up in [`crate::pki`]; PDF *construction* is a separate
//! layer.
//!
//! Everything here is best-effort and read-only: inspection helpers degrade to
//! `None`/all-false rather than aborting.

mod asn1;
mod digest;
mod extraction;
mod inspect;
mod ltv;
mod signature;

use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use der::Decode;

use crate::{Result, RevenantError};

pub use asn1::{ASN1_SEQUENCE_TAG, MIN_CMS_SIZE};
pub use digest::{extract_digest_info, DigestAlgorithm};
pub use extraction::{
    extract_cms_from_byterange, extract_signature_data, extract_signature_data_for,
    find_byteranges, ByteRange, BYTERANGE_PATTERN,
};
pub use inspect::{extract_signer_info, inspect_cms_blob, CmsInspection};
pub use ltv::{check_ltv_status, LtvStatus};
pub use signature::{verify_signer_signature, SignatureStatus};

/// Parse a DER-encoded CMS/PKCS#7 blob into its `SignedData`.
///
/// The single entry point for the reading helpers below `pki`. Certificate
/// extraction in [`crate::pki`] keeps its own parse so it can surface a
/// certificate-flavored error; this one is used by the digest/LTV scans.
///
/// # Errors
///
/// Returns [`RevenantError::Certificate`] if the bytes are not a parseable CMS
/// `ContentInfo` wrapping a `SignedData`.
pub(crate) fn signed_data_from_der(cms_der: &[u8]) -> Result<SignedData> {
    let content_info = ContentInfo::from_der(cms_der)
        .map_err(|e| RevenantError::Certificate(format!("Failed to parse CMS/PKCS#7 blob: {e}")))?;
    content_info
        .content
        .decode_as::<SignedData>()
        .map_err(|e| RevenantError::Certificate(format!("Failed to parse CMS SignedData: {e}")))
}
