//! Core signing operations: detached CMS and embedded PDF signatures.
//!
//! Every function takes a [`SigningTransport`], so the signing logic stays
//! transport-agnostic -- the appliance holds the private key and returns a
//! CMS/PKCS#7 blob, and none of it is constructed client-side. The high-level,
//! config-resolving entry points (`sign`, `sign_detached`) live in
//! [`crate::api`].

use std::time::Duration;

use crate::appearance::{compute_optimal_height, compute_optimal_width, get_font};
use crate::constants::{PDF_MAGIC, SHA1_DIGEST_SIZE};
use crate::net::SigningTransport;
use crate::pdf::{
    compute_byterange_hash, insert_cms, prepare_pdf_with_sig_field, verify_embedded_signature,
    PageSpec, Position, PrepareOptions, PreparedPdf, SIG_HEIGHT, SIG_WIDTH,
};
use crate::{Result, RevenantError};

/// Placement and appearance options for an embedded PDF signature.
///
/// Bundles everything [`sign_pdf_embedded`] needs beyond the transport and
/// credentials. Construct from [`EmbeddedSignatureOptions::default`] and set the
/// fields that matter. `x`/`y`/`w`/`h` are `None` when unset: an unset `w`/`h`
/// auto-sizes to the display fields (visible signatures only), and `x`/`y` fall
/// back to the `position` preset unless *both* are given.
#[derive(Debug, Clone)]
pub struct EmbeddedSignatureOptions {
    /// The page to place the signature on.
    pub page: PageSpec,
    /// Placement preset, used unless both `x` and `y` are set.
    pub position: Position,
    /// Manual x-coordinate (PDF points, origin = bottom-left).
    pub x: Option<f64>,
    /// Manual y-coordinate (PDF points, origin = bottom-left).
    pub y: Option<f64>,
    /// Signature field width in PDF points; auto-sized when `None`.
    pub w: Option<f64>,
    /// Signature field height in PDF points; auto-sized when `None`.
    pub h: Option<f64>,
    /// The `/Reason` string.
    pub reason: String,
    /// Signer display name (for `/Name` and the default first field).
    pub name: Option<String>,
    /// Path to a PNG/JPEG signature image.
    pub image_path: Option<String>,
    /// Explicit ordered display strings; defaults to name + auto date.
    pub fields: Option<Vec<String>>,
    /// Whether the signature has a visual appearance.
    pub visible: bool,
    /// Font registry key (e.g. `"noto-sans"`, `"ghea-grapalat"`).
    pub font: Option<String>,
}

impl Default for EmbeddedSignatureOptions {
    fn default() -> Self {
        Self {
            page: PageSpec::Last,
            position: Position::BottomRight,
            x: None,
            y: None,
            w: None,
            h: None,
            reason: String::new(),
            name: None,
            image_path: None,
            fields: None,
            visible: true,
            font: None,
        }
    }
}

/// Reject input that does not look like a PDF (fail-loud, before the network).
fn validate_pdf(pdf: &[u8]) -> Result<()> {
    if pdf.is_empty() || !pdf.starts_with(PDF_MAGIC) {
        return Err(RevenantError::Pdf(
            "Input does not appear to be a PDF file.".to_owned(),
        ));
    }
    Ok(())
}

/// Sign a PDF and return a detached CMS/PKCS#7 signature.
///
/// # Errors
///
/// Returns [`RevenantError::Pdf`] if the input is not a PDF, or a transport
/// error (auth, server, TLS) from the signing service.
pub fn sign_pdf_detached(
    pdf: &[u8],
    transport: &dyn SigningTransport,
    username: &str,
    password: &str,
    timeout: Duration,
) -> Result<Vec<u8>> {
    validate_pdf(pdf)?;
    transport.sign_pdf_detached(pdf, username, password, timeout)
}

/// Sign a pre-computed 20-byte SHA-1 hash.
///
/// # Errors
///
/// Returns [`RevenantError::Other`] if the hash is not exactly
/// [`SHA1_DIGEST_SIZE`] bytes, or a transport error from the signing service.
pub fn sign_hash(
    hash: &[u8],
    transport: &dyn SigningTransport,
    username: &str,
    password: &str,
    timeout: Duration,
) -> Result<Vec<u8>> {
    if hash.len() != SHA1_DIGEST_SIZE {
        return Err(RevenantError::Other(format!(
            "Expected {SHA1_DIGEST_SIZE}-byte SHA-1 hash, got {} bytes.",
            hash.len()
        )));
    }
    transport.sign_hash(hash, username, password, timeout)
}

/// Sign arbitrary data; the server hashes it and returns a CMS/PKCS#7 signature.
///
/// # Errors
///
/// Returns [`RevenantError::Other`] on empty input, or a transport error from
/// the signing service.
pub fn sign_data(
    data: &[u8],
    transport: &dyn SigningTransport,
    username: &str,
    password: &str,
    timeout: Duration,
) -> Result<Vec<u8>> {
    if data.is_empty() {
        return Err(RevenantError::Other("Cannot sign empty data.".to_owned()));
    }
    transport.sign_data(data, username, password, timeout)
}

/// Sign a PDF with an embedded signature (hash-then-sign around the appliance).
///
/// The flow is: prepare the PDF with an empty signature field, extract the
/// ByteRange data (everything but the reserved `/Contents` hex), send it to the
/// transport for signing, splice the returned CMS back in, and verify the result
/// before returning it. A failed post-sign verification is an error -- a corrupt
/// signed PDF is never returned.
///
/// # Errors
///
/// Returns [`RevenantError::Pdf`] if the input is not a PDF, the geometry is
/// invalid, preparation/insertion fails, or post-sign verification fails; or a
/// transport error from the signing service.
pub fn sign_pdf_embedded(
    pdf: &[u8],
    transport: &dyn SigningTransport,
    username: &str,
    password: &str,
    timeout: Duration,
    options: &EmbeddedSignatureOptions,
) -> Result<Vec<u8>> {
    validate_pdf(pdf)?;

    let mut w = options.w.unwrap_or(SIG_WIDTH);
    let mut h = options.h.unwrap_or(SIG_HEIGHT);
    if w <= 0.0 || h <= 0.0 {
        return Err(RevenantError::Pdf(format!(
            "Signature dimensions must be positive, got w={w}, h={h}"
        )));
    }
    if let Some(x) = options.x.filter(|&x| x < 0.0) {
        return Err(RevenantError::Pdf(format!(
            "Signature x-coordinate must be non-negative, got {x}"
        )));
    }
    if let Some(y) = options.y.filter(|&y| y < 0.0) {
        return Err(RevenantError::Pdf(format!(
            "Signature y-coordinate must be non-negative, got {y}"
        )));
    }

    log::info!(
        "Signing PDF (embedded, {}): {} bytes, position={}",
        if options.visible {
            "visible"
        } else {
            "invisible"
        },
        pdf.len(),
        options.position.canonical_name(),
    );

    // Auto-size the field to the explicit display fields, for visible
    // signatures where the caller left the dimension unset.
    if options.visible {
        if let Some(fields) = options.fields.as_ref().filter(|f| !f.is_empty()) {
            let font = get_font(options.font.as_deref())?;
            let has_img = options.image_path.is_some();
            if options.w.is_none() {
                w = compute_optimal_width(fields, h, has_img, font);
                log::debug!("Adaptive signature width: {w:.1} pt");
            }
            if options.h.is_none() {
                h = compute_optimal_height(fields, w, has_img, font);
                log::debug!("Adaptive signature height: {h:.1} pt");
            }
        }
    }

    // Step 1: prepare the PDF with an empty signature field.
    let manual_xy = options.x.zip(options.y);
    let prepare_opts = PrepareOptions {
        page: options.page,
        position: options.position,
        manual_xy,
        size: (w, h),
        reason: &options.reason,
        name: options.name.as_deref(),
        image_path: options.image_path.as_deref(),
        fields: options.fields.clone(),
        visible: options.visible,
        font: options.font.as_deref(),
    };
    let PreparedPdf {
        bytes: prepared,
        contents_hex_offset: hex_start,
        contents_hex_len: hex_len,
    } = prepare_pdf_with_sig_field(pdf, &prepare_opts)?;

    // Step 2: extract the ByteRange data (everything except the hex placeholder;
    // +1 skips the closing '>').
    let mut br_data = Vec::with_capacity(prepared.len().saturating_sub(hex_len + 1));
    br_data.extend_from_slice(&prepared[..hex_start]);
    br_data.extend_from_slice(&prepared[hex_start + hex_len + 1..]);

    // Step 3: sign the ByteRange data.
    let cms_der = sign_data(&br_data, transport, username, password, timeout)?;

    // Step 4: splice the CMS into the reserved /Contents.
    let signed = insert_cms(&prepared, hex_start, hex_len, &cms_der)?;
    if signed.len() != prepared.len() {
        return Err(RevenantError::Pdf(format!(
            "insert_cms changed PDF size: {} -> {}",
            prepared.len(),
            signed.len()
        )));
    }

    // Step 5: verify before returning -- never emit a corrupt signed PDF.
    let br_hash = compute_byterange_hash(&prepared, hex_start, hex_len)?;
    let result = verify_embedded_signature(&signed, Some(&br_hash), None);
    if !result.valid() {
        let detail = result.details.join("\n  ");
        log::error!("Post-sign verification failed: {detail}");
        return Err(RevenantError::Pdf(format!(
            "Post-sign verification FAILED:\n  {detail}\nThe signed PDF may be corrupt -- not saved."
        )));
    }

    log::info!("Signed PDF complete: {} bytes", signed.len());
    Ok(signed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cms::{extract_signature_data, find_byteranges};

    const BLANK_LETTER: &[u8] = include_bytes!("pdf/testdata/blank_letter.pdf");

    fn timeout() -> Duration {
        Duration::from_secs(30)
    }

    /// A well-formed 203-byte DER SEQUENCE standing in for the appliance's CMS.
    fn fake_cms() -> Vec<u8> {
        let mut der = vec![0x30, 0x81, 0xC8];
        der.extend(std::iter::repeat_n(0xAB, 200));
        der
    }

    /// A transport that returns a scripted CMS for every signing call.
    struct FakeSigner {
        cms: Vec<u8>,
    }

    impl SigningTransport for FakeSigner {
        fn sign_data(&self, _: &[u8], _: &str, _: &str, _: Duration) -> Result<Vec<u8>> {
            Ok(self.cms.clone())
        }
        fn sign_hash(&self, _: &[u8], _: &str, _: &str, _: Duration) -> Result<Vec<u8>> {
            Ok(self.cms.clone())
        }
        fn sign_pdf_detached(&self, _: &[u8], _: &str, _: &str, _: Duration) -> Result<Vec<u8>> {
            Ok(self.cms.clone())
        }
    }

    fn signer() -> FakeSigner {
        FakeSigner { cms: fake_cms() }
    }

    #[test]
    fn embedded_visible_roundtrips() {
        let opts = EmbeddedSignatureOptions {
            name: Some("Jane Signer".to_owned()),
            reason: "Approved".to_owned(),
            ..Default::default()
        };
        let signed =
            sign_pdf_embedded(BLANK_LETTER, &signer(), "u", "p", timeout(), &opts).unwrap();
        // The returned PDF carries exactly one signature whose CMS round-trips.
        assert_eq!(find_byteranges(&signed).unwrap().len(), 1);
        let (_signed_data, cms) = extract_signature_data(&signed).unwrap();
        assert_eq!(cms, fake_cms());
    }

    #[test]
    fn embedded_invisible_roundtrips() {
        let opts = EmbeddedSignatureOptions {
            visible: false,
            name: Some("Invisible".to_owned()),
            ..Default::default()
        };
        let signed =
            sign_pdf_embedded(BLANK_LETTER, &signer(), "u", "p", timeout(), &opts).unwrap();
        assert_eq!(find_byteranges(&signed).unwrap().len(), 1);
    }

    #[test]
    fn embedded_autosizes_from_explicit_fields() {
        let opts = EmbeddedSignatureOptions {
            fields: Some(vec![
                "A very long signer display name that forces a wide box".to_owned(),
                "SSN: 1234567890".to_owned(),
            ]),
            ..Default::default()
        };
        // Auto-sizing must not break the round-trip.
        let signed =
            sign_pdf_embedded(BLANK_LETTER, &signer(), "u", "p", timeout(), &opts).unwrap();
        assert_eq!(find_byteranges(&signed).unwrap().len(), 1);
    }

    #[test]
    fn embedded_rejects_non_pdf() {
        let opts = EmbeddedSignatureOptions::default();
        let err =
            sign_pdf_embedded(b"not a pdf", &signer(), "u", "p", timeout(), &opts).unwrap_err();
        assert!(matches!(err, RevenantError::Pdf(_)));
    }

    #[test]
    fn embedded_rejects_nonpositive_dimensions() {
        let opts = EmbeddedSignatureOptions {
            w: Some(0.0),
            ..Default::default()
        };
        let err =
            sign_pdf_embedded(BLANK_LETTER, &signer(), "u", "p", timeout(), &opts).unwrap_err();
        assert!(matches!(err, RevenantError::Pdf(_)));
    }

    #[test]
    fn embedded_rejects_negative_coordinates() {
        let opts = EmbeddedSignatureOptions {
            x: Some(-1.0),
            y: Some(10.0),
            ..Default::default()
        };
        let err =
            sign_pdf_embedded(BLANK_LETTER, &signer(), "u", "p", timeout(), &opts).unwrap_err();
        assert!(matches!(err, RevenantError::Pdf(_)));
    }

    #[test]
    fn embedded_fails_on_corrupt_cms() {
        // Too-small CMS -> post-sign structure check fails -> the flow errors
        // rather than returning a corrupt PDF.
        let transport = FakeSigner {
            cms: vec![0x30, 0x02, 0xAB, 0xCD],
        };
        let opts = EmbeddedSignatureOptions {
            name: Some("X".to_owned()),
            ..Default::default()
        };
        let err =
            sign_pdf_embedded(BLANK_LETTER, &transport, "u", "p", timeout(), &opts).unwrap_err();
        assert!(matches!(err, RevenantError::Pdf(_)));
        assert!(err.to_string().contains("Post-sign verification FAILED"));
    }

    #[test]
    fn detached_signs_and_validates_input() {
        let cms = sign_pdf_detached(BLANK_LETTER, &signer(), "u", "p", timeout()).unwrap();
        assert_eq!(cms, fake_cms());
        let err = sign_pdf_detached(b"nope", &signer(), "u", "p", timeout()).unwrap_err();
        assert!(matches!(err, RevenantError::Pdf(_)));
    }

    #[test]
    fn sign_hash_validates_length() {
        assert!(sign_hash(&[0u8; 20], &signer(), "u", "p", timeout()).is_ok());
        let err = sign_hash(&[0u8; 19], &signer(), "u", "p", timeout()).unwrap_err();
        assert!(matches!(err, RevenantError::Other(_)));
    }

    #[test]
    fn sign_data_rejects_empty() {
        assert!(sign_data(b"data", &signer(), "u", "p", timeout()).is_ok());
        let err = sign_data(b"", &signer(), "u", "p", timeout()).unwrap_err();
        assert!(matches!(err, RevenantError::Other(_)));
    }
}
