//! Post-sign verification of embedded and detached PDF signatures.
//!
//! Extracts the ByteRange data and CMS blob, checks structural validity, and
//! verifies the ByteRange hash against either an expected value (the exact hash
//! sent to the appliance) or the algorithm and `messageDigest` declared in the
//! CMS.
//!
//! Certificate-chain validation needs a network transport (to fetch the Trust
//! Service List and intermediates), so it is *injected* as a closure rather than
//! called directly -- verification itself stays offline and pure. The signing
//! layer supplies a validator backed by a [`crate::net::Transport`]; passing
//! `None` skips the chain step (`trust_status` stays `Indeterminate`).

use super::reader::PdfReader;
use crate::cms::{
    check_ltv_status, extract_digest_info, extract_signature_data_for, extract_signer_info,
    find_byteranges, verify_signer_signature, ByteRange, DigestAlgorithm, SignatureStatus,
    ASN1_SEQUENCE_TAG, MIN_CMS_SIZE,
};
use crate::pki::{CertInfo, ChainResult, TrustStatus};
use crate::{Result, RevenantError};

/// A caller-supplied certificate-chain validator: given the CMS DER, it returns
/// a [`ChainResult`], or `None` when validation is unavailable.
pub type ChainValidator<'a> = dyn Fn(&[u8]) -> Option<ChainResult> + 'a;

/// The result of verifying a single signature.
#[derive(Debug, Clone)]
pub struct VerificationResult {
    /// The ByteRange and CMS structure are well-formed.
    pub structure_ok: bool,
    /// The ByteRange hash matches the expected/declared value.
    pub hash_ok: bool,
    /// Whether the signer's cryptographic signature over the CMS signed
    /// attributes verifies against the signer certificate.
    pub signature: SignatureStatus,
    /// The CMS embeds long-term-validation revocation data.
    pub ltv_enabled: bool,
    /// Human-readable diagnostic lines.
    pub details: Vec<String>,
    /// Signer identity from the CMS certificate, if extractable.
    pub signer: Option<CertInfo>,
    /// The matched trust-anchor service name, if any.
    pub trust_anchor: Option<String>,
    /// The chain trust verdict, or `None` when the structure could not even be
    /// extracted (so chain validation was never attempted).
    pub trust_status: Option<TrustStatus>,
}

impl VerificationResult {
    /// Structural integrity: the CMS parses and the ByteRange hash matches the
    /// expected or CMS-declared digest. This proves the signed bytes are intact
    /// but NOT that the named signer produced the signature -- use [`valid`] for
    /// the full cryptographic verdict. It is the right check for the post-sign
    /// self-test, which only asks "did the splice preserve the signed bytes?".
    ///
    /// [`valid`]: VerificationResult::valid
    #[must_use]
    pub fn integrity_ok(&self) -> bool {
        self.structure_ok && self.hash_ok
    }

    /// Full cryptographic validity: structurally sound, the hash matches, *and*
    /// the signer's signature verifies against its certificate. This is what a
    /// caller asking "is this a genuine signature?" wants. Trust in the signer's
    /// certificate chain is reported separately via [`trust_status`].
    ///
    /// [`trust_status`]: VerificationResult::trust_status
    #[must_use]
    pub fn valid(&self) -> bool {
        self.integrity_ok() && self.signature.is_valid()
    }

    /// The result for a signature whose structure could not even be extracted.
    fn structure_error(message: String) -> Self {
        Self {
            structure_ok: false,
            hash_ok: false,
            signature: SignatureStatus::Unverifiable("structure could not be extracted"),
            ltv_enabled: false,
            details: vec![message],
            signer: None,
            trust_anchor: None,
            trust_status: None,
        }
    }
}

/// Core verification for a single ByteRange.
fn verify_signature_match(
    pdf_bytes: &[u8],
    br: &ByteRange,
    expected_hash: Option<&[u8]>,
    validate_chain: Option<&ChainValidator<'_>>,
) -> VerificationResult {
    let mut details: Vec<String> = Vec::new();

    // 1. Extract the signed data and CMS blob.
    let (signed_data, cms_der) = match extract_signature_data_for(pdf_bytes, br) {
        Ok(pair) => pair,
        Err(e) => return VerificationResult::structure_error(format!("Structure error: {e}")),
    };
    details.push(format!(
        "ByteRange OK -- signed data: {} bytes",
        signed_data.len()
    ));
    details.push(format!("CMS blob: {} bytes", cms_der.len()));

    // 2. CMS structure check.
    let structure_ok = check_cms_structure(&cms_der, &mut details);

    // 3. Signer info.
    let signer = extract_signer_info(&cms_der);
    if let Some(name) = signer.as_ref().and_then(|s| s.name.as_ref()) {
        details.push(format!("Signer: {name}"));
    }

    // 4. Hash verification (messageDigest == hash of the signed bytes).
    let hash_ok = verify_hash(&signed_data, &cms_der, expected_hash, &mut details);

    // 5. Cryptographic signature verification (the signer's key signed the
    //    signed attributes). Together with the hash check this proves the named
    //    signer signed exactly these bytes.
    let signature = verify_signer_signature(&cms_der);
    details.push(signature.describe());

    // 6. LTV status.
    let ltv = check_ltv_status(&cms_der);
    let ltv_enabled = ltv.ltv_enabled();
    details.push(format!(
        "LTV: {}",
        if ltv_enabled {
            "LTV enabled"
        } else {
            "Not LTV enabled"
        }
    ));

    let mut result = VerificationResult {
        structure_ok,
        hash_ok,
        signature,
        ltv_enabled,
        details,
        signer,
        trust_anchor: None,
        trust_status: Some(TrustStatus::Indeterminate),
    };

    // 7. Chain validation (optional, injected, best-effort).
    apply_chain(&mut result, &cms_der, validate_chain);
    result
}

/// Check the CMS begins with an ASN.1 SEQUENCE and is not implausibly small.
fn check_cms_structure(cms_der: &[u8], details: &mut Vec<String>) -> bool {
    if cms_der.len() < MIN_CMS_SIZE {
        details.push(format!(
            "CMS too small ({} bytes) -- likely corrupt",
            cms_der.len()
        ));
        false
    } else if cms_der.first() != Some(&ASN1_SEQUENCE_TAG) {
        details.push("CMS does not start with ASN.1 SEQUENCE tag (0x30)".to_owned());
        false
    } else {
        details.push("CMS: valid ASN.1 structure".to_owned());
        true
    }
}

/// Verify the ByteRange hash, preferring an explicit expected value, else the
/// algorithm and `messageDigest` declared in the CMS.
fn verify_hash(
    signed_data: &[u8],
    cms_der: &[u8],
    expected_hash: Option<&[u8]>,
    details: &mut Vec<String>,
) -> bool {
    if let Some(expected) = expected_hash {
        // Post-sign path: the exact SHA-1 sent to the appliance is known.
        let actual = DigestAlgorithm::Sha1.hash(signed_data);
        if actual == expected {
            details.push(format!(
                "Hash OK -- SHA-1 matches expected: {}",
                hex::encode(&actual)
            ));
            return true;
        }
        details.push(format!(
            "Hash MISMATCH!\n  ByteRange SHA-1: {}\n  Expected:        {}",
            hex::encode(&actual),
            hex::encode(expected)
        ));
        return false;
    }

    if let Some((algo, cms_digest)) = extract_digest_info(cms_der) {
        let actual = algo.hash(signed_data);
        let algo_upper = algo.name().to_uppercase();
        if actual == cms_digest {
            details.push(format!(
                "Hash OK -- {algo_upper} matches CMS messageDigest: {}",
                hex::encode(&actual)
            ));
            return true;
        }
        details.push(format!(
            "Hash MISMATCH!\n  ByteRange {algo_upper}:   {}\n  CMS messageDigest:  {}",
            hex::encode(&actual),
            hex::encode(&cms_digest)
        ));
        return false;
    }

    if cms_der.len() >= MIN_CMS_SIZE && cms_der.first() == Some(&ASN1_SEQUENCE_TAG) {
        let actual = DigestAlgorithm::Sha1.hash(signed_data);
        details.push(format!(
            "Hash computed -- SHA-1: {} (CMS digest info not available -- cannot verify)",
            hex::encode(&actual)
        ));
    } else {
        details.push("Hash: cannot verify without expected hash and CMS is suspect".to_owned());
    }
    false
}

/// Fold an injected chain-validation result into the verification result.
fn apply_chain(
    result: &mut VerificationResult,
    cms_der: &[u8],
    validate_chain: Option<&ChainValidator<'_>>,
) {
    let Some(validate) = validate_chain else {
        return;
    };
    if let Some(chain) = validate(cms_der) {
        result.trust_status = Some(chain.trust);
        result.trust_anchor = chain.trust_anchor;
        result.details.extend(chain.details);
    } else {
        result
            .details
            .push("Chain: validation unavailable".to_owned());
    }
}

/// Append a best-effort structural note from an independent PDF parser.
fn parser_note(pdf_bytes: &[u8]) -> String {
    match PdfReader::open(pdf_bytes) {
        Ok(reader) => format!("parser: valid PDF, {} page(s)", reader.page_count()),
        Err(e) => format!("parser: structural warning -- {e}"),
    }
}

/// Verify the last embedded signature in a PDF.
///
/// Never fails on a *verification* problem -- it returns a result with
/// `structure_ok`/`hash_ok` set and diagnostics in `details`. Multi-signature
/// PDFs: only the last (most recent) signature is checked; use
/// [`verify_all_embedded_signatures`] for every one.
#[must_use]
pub fn verify_embedded_signature(
    pdf_bytes: &[u8],
    expected_hash: Option<&[u8]>,
    validate_chain: Option<&ChainValidator<'_>>,
) -> VerificationResult {
    let ranges = match find_byteranges(pdf_bytes) {
        Ok(ranges) => ranges,
        Err(e) => return VerificationResult::structure_error(format!("Structure error: {e}")),
    };
    let Some(br) = ranges.last() else {
        return VerificationResult::structure_error(
            "Structure error: No /ByteRange found in PDF -- not a signed PDF?".to_owned(),
        );
    };

    let mut result = verify_signature_match(pdf_bytes, br, expected_hash, validate_chain);
    result.details.push(parser_note(pdf_bytes));
    result
}

/// Verify every embedded signature, in document order.
///
/// # Errors
///
/// Returns [`RevenantError::Pdf`] if the PDF has no embedded signatures.
pub fn verify_all_embedded_signatures(
    pdf_bytes: &[u8],
    validate_chain: Option<&ChainValidator<'_>>,
) -> Result<Vec<VerificationResult>> {
    let ranges = find_byteranges(pdf_bytes)?;
    if ranges.is_empty() {
        return Err(RevenantError::Pdf(
            "No /ByteRange found in PDF -- not a signed PDF?".to_owned(),
        ));
    }

    let note = parser_note(pdf_bytes);
    let results = ranges
        .iter()
        .map(|br| {
            let mut result = verify_signature_match(pdf_bytes, br, None, validate_chain);
            result.details.push(note.clone());
            result
        })
        .collect();
    Ok(results)
}

/// Verify a detached CMS/PKCS#7 signature against the original data.
#[must_use]
pub fn verify_detached_signature(
    data_bytes: &[u8],
    cms_der: &[u8],
    validate_chain: Option<&ChainValidator<'_>>,
) -> VerificationResult {
    let mut details: Vec<String> = Vec::new();

    let structure_ok = if cms_der.len() < MIN_CMS_SIZE {
        details.push(format!(
            "CMS too small ({} bytes) -- likely corrupt",
            cms_der.len()
        ));
        false
    } else if cms_der.first() != Some(&ASN1_SEQUENCE_TAG) {
        details.push("CMS does not start with ASN.1 SEQUENCE tag (0x30)".to_owned());
        false
    } else {
        details.push(format!(
            "CMS blob: {} bytes, valid ASN.1 structure",
            cms_der.len()
        ));
        true
    };

    let signer = extract_signer_info(cms_der);
    if let Some(name) = signer.as_ref().and_then(|s| s.name.as_ref()) {
        details.push(format!("Signer: {name}"));
    }

    // Cryptographic signature verification (signer's key over the signed attrs).
    let signature = verify_signer_signature(cms_der);
    details.push(signature.describe());

    // Detached signatures are always verified against the CMS-declared digest.
    let hash_ok = if let Some((algo, cms_digest)) = extract_digest_info(cms_der) {
        let actual = algo.hash(data_bytes);
        let algo_upper = algo.name().to_uppercase();
        if actual == cms_digest {
            details.push(format!(
                "Hash OK -- {algo_upper} matches CMS messageDigest: {}",
                hex::encode(&actual)
            ));
            true
        } else {
            details.push(format!(
                "Hash MISMATCH!\n  Data {algo_upper}:        {}\n  CMS messageDigest:  {}",
                hex::encode(&actual),
                hex::encode(&cms_digest)
            ));
            false
        }
    } else {
        details.push("Could not extract digest info -- hash verification unavailable".to_owned());
        false
    };

    let ltv = check_ltv_status(cms_der);
    let ltv_enabled = ltv.ltv_enabled();
    details.push(format!(
        "LTV: {}",
        if ltv_enabled {
            "LTV enabled"
        } else {
            "Not LTV enabled"
        }
    ));

    let mut result = VerificationResult {
        structure_ok,
        hash_ok,
        signature,
        ltv_enabled,
        details,
        signer,
        trust_anchor: None,
        trust_status: Some(TrustStatus::Indeterminate),
    };
    apply_chain(&mut result, cms_der, validate_chain);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pdf::{
        compute_byterange_hash, insert_cms, prepare_pdf_with_sig_field, PrepareOptions, PreparedPdf,
    };

    const BLANK_LETTER: &[u8] = include_bytes!("testdata/blank_letter.pdf");
    const CMS_LEAF: &[u8] = include_bytes!("../pki/testdata/cms_leaf_direct.der");

    /// Prepare + fake-sign a PDF, returning (signed_pdf, sha1_of_byterange).
    fn prepare_and_fake_sign() -> (Vec<u8>, [u8; 20]) {
        let opts = PrepareOptions {
            name: Some("Verify Test"),
            ..Default::default()
        };
        let PreparedPdf {
            bytes: prepared,
            contents_hex_offset: hex_start,
            contents_hex_len: hex_len,
        } = prepare_pdf_with_sig_field(BLANK_LETTER, &opts).unwrap();
        let hash = compute_byterange_hash(&prepared, hex_start, hex_len).unwrap();
        let mut cms = vec![0x30, 0x81, 0xC8];
        cms.extend(std::iter::repeat_n(0xAB, 200));
        let signed = insert_cms(&prepared, hex_start, hex_len, &cms).unwrap();
        (signed, hash)
    }

    #[test]
    fn verifies_with_expected_hash() {
        let (signed, hash) = prepare_and_fake_sign();
        let result = verify_embedded_signature(&signed, Some(&hash), None);
        assert!(result.structure_ok, "{:?}", result.details);
        assert!(result.hash_ok, "{:?}", result.details);
        // The splice preserved the signed bytes: integrity holds.
        assert!(result.integrity_ok());
        // But the fake CMS carries no real signature, so full validity does not.
        assert!(!result.valid());
        assert!(matches!(
            result.signature,
            crate::cms::SignatureStatus::Unverifiable(_)
        ));
        assert!(result
            .details
            .iter()
            .any(|d| d.contains("Hash OK -- SHA-1")));
        // No chain validator supplied -> chain not attempted.
        assert_eq!(result.trust_status, Some(TrustStatus::Indeterminate));
    }

    #[test]
    fn detects_wrong_expected_hash() {
        let (signed, _hash) = prepare_and_fake_sign();
        let wrong = [0u8; 20];
        let result = verify_embedded_signature(&signed, Some(&wrong), None);
        assert!(result.structure_ok);
        assert!(!result.hash_ok);
        assert!(!result.valid());
        assert!(result.details.iter().any(|d| d.contains("Hash MISMATCH")));
    }

    #[test]
    fn unsigned_pdf_reports_no_byterange() {
        let result = verify_embedded_signature(BLANK_LETTER, None, None);
        assert!(!result.structure_ok);
        assert_eq!(result.trust_status, None);
        assert!(result
            .details
            .iter()
            .any(|d| d.contains("No /ByteRange found")));
    }

    #[test]
    fn all_signatures_requires_at_least_one() {
        assert!(verify_all_embedded_signatures(BLANK_LETTER, None).is_err());
        let (signed, _hash) = prepare_and_fake_sign();
        let results = verify_all_embedded_signatures(&signed, None).unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].structure_ok);
    }

    #[test]
    fn detached_signature_verifies_against_data() {
        // The committed CMS fixture signs SHA-256("test data") with a real key.
        let result = verify_detached_signature(b"test data", CMS_LEAF, None);
        assert!(result.structure_ok, "{:?}", result.details);
        assert!(result.hash_ok, "{:?}", result.details);
        // The signer's cryptographic signature verifies -> fully valid.
        assert_eq!(result.signature, crate::cms::SignatureStatus::Valid);
        assert!(result.valid(), "{:?}", result.details);
        // Wrong data -> hash mismatch, and no longer valid.
        let bad = verify_detached_signature(b"other data", CMS_LEAF, None);
        assert!(!bad.hash_ok);
        assert!(!bad.valid());
    }

    #[test]
    fn injected_chain_validator_is_applied() {
        let (signed, hash) = prepare_and_fake_sign();
        let validator = |_cms: &[u8]| {
            Some(ChainResult {
                trust: TrustStatus::Trusted,
                trust_anchor: Some("Test CA".to_owned()),
                chain_depth: 2,
                details: vec!["Chain: trusted anchor".to_owned()],
            })
        };
        let result = verify_embedded_signature(&signed, Some(&hash), Some(&validator));
        assert_eq!(result.trust_anchor.as_deref(), Some("Test CA"));
        assert_eq!(result.trust_status, Some(TrustStatus::Trusted));
        assert!(result.details.iter().any(|d| d.contains("trusted anchor")));
    }
}
