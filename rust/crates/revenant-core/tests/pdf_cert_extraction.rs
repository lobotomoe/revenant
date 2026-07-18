// SPDX-License-Identifier: Apache-2.0
//! Offline end-to-end coverage for PDF-based certificate extraction.
//!
//! Builds a signed PDF from committed fixtures -- a blank page prepared with a
//! signature field, then a real CMS blob spliced into the reserved `/Contents`
//! -- and confirms [`CertInfo::all_from_pdf`] recovers the signer. This
//! exercises the `pki` -> `cms` -> `pdf` seam through the public API only, with
//! no network access.

use revenant_core::pdf::{insert_cms, prepare_pdf_with_sig_field, PrepareOptions, PreparedPdf};
use revenant_core::pki::CertInfo;

/// A blank single-page PDF (the committed PDF-layer fixture).
const BLANK_PDF: &[u8] = include_bytes!("../src/pdf/testdata/blank_letter.pdf");

/// A real CMS/PKCS#7 signature whose signer certificate is "Test Signer Direct".
const CMS_LEAF_DIRECT: &[u8] = include_bytes!("../src/pki/testdata/cms_leaf_direct.der");

#[test]
fn extract_all_cert_info_from_a_signed_pdf() {
    // Prepare an (invisible) signature field, then splice the fixture CMS into
    // the reserved /Contents to produce a structurally signed PDF.
    let opts = PrepareOptions {
        visible: false,
        ..PrepareOptions::default()
    };
    let PreparedPdf {
        bytes: prepared,
        contents_hex_offset: hex_start,
        contents_hex_len: hex_len,
    } = prepare_pdf_with_sig_field(BLANK_PDF, &opts).expect("prepare signature field");
    let signed = insert_cms(&prepared, hex_start, hex_len, CMS_LEAF_DIRECT).expect("insert CMS");

    let infos = CertInfo::all_from_pdf(&signed).expect("extraction should succeed");
    assert_eq!(infos.len(), 1, "one signature, one signer");
    let first = &infos[0];
    assert_eq!(first.name.as_deref(), Some("Test Signer Direct"));
    assert!(
        first
            .dn
            .as_deref()
            .is_some_and(|dn| dn.contains("Test Signer Direct")),
        "{first:?}"
    );
}
