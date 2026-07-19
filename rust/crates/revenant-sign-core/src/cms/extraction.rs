//! Locating the signed byte ranges and the CMS blob inside a signed PDF.
//!
//! A PAdES/CoSign signature stores its `/ByteRange [off1 len1 off2 len2]` and a
//! hex `/Contents <...>` placeholder. The two ranges cover everything *except*
//! the placeholder; the signature is the CMS bytes between the `<` and `>`. This
//! module finds those ranges by scanning the raw file bytes (a structural PDF
//! parser would not preserve the exact offsets the `/ByteRange` refers to) and
//! hands the padded hex to [`crate::cms::asn1`] for exact-length extraction.

use std::sync::LazyLock;

use regex::bytes::Regex;

use super::asn1::extract_der_from_padded_hex;
use crate::{Result, RevenantError};

/// Regex matching a `/ByteRange` array, tolerant of the whitespace variations
/// real writers emit.
pub const BYTERANGE_PATTERN: &str = r"/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]";

static BYTERANGE_RE: LazyLock<Regex> = LazyLock::new(|| {
    // The pattern is a compile-time constant; a failure here is a build-time
    // bug in this crate, exercised by `pattern_compiles`, not runtime input.
    Regex::new(BYTERANGE_PATTERN).expect("BYTERANGE_PATTERN is a valid regex")
});

/// The four integers of a PDF signature `/ByteRange [off1 len1 off2 len2]`.
///
/// The signed data is `pdf[off1..off1+len1]` concatenated with
/// `pdf[off2..off2+len2]`; the gap in between holds the hex CMS placeholder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByteRange {
    pub off1: usize,
    pub len1: usize,
    pub off2: usize,
    pub len2: usize,
}

/// Every `/ByteRange` array in the file, in document order.
///
/// For a multiply-signed PDF the last entry is the most recent signature.
///
/// # Errors
///
/// Returns [`RevenantError::Pdf`] if a matched integer does not fit in a
/// `usize` (a malformed byte range).
pub fn find_byteranges(pdf_bytes: &[u8]) -> Result<Vec<ByteRange>> {
    let mut ranges = Vec::new();
    for caps in BYTERANGE_RE.captures_iter(pdf_bytes) {
        ranges.push(ByteRange {
            off1: parse_group(&caps, 1)?,
            len1: parse_group(&caps, 2)?,
            off2: parse_group(&caps, 3)?,
            len2: parse_group(&caps, 4)?,
        });
    }
    Ok(ranges)
}

/// Extract the CMS DER blob given the first-chunk length and second-chunk
/// offset of a `/ByteRange`. This is the canonical low-level extraction used by
/// both signature verification and certificate discovery.
///
/// # Errors
///
/// Returns [`RevenantError::Pdf`] if the byte range is inconsistent with the
/// file, the angle brackets are not where expected, or the hex/ASN.1 is
/// malformed.
pub fn extract_cms_from_byterange(pdf_bytes: &[u8], len1: usize, off2: usize) -> Result<Vec<u8>> {
    if len1 == 0 {
        return Err(RevenantError::Pdf(format!(
            "Invalid ByteRange: len1 must be positive, got {len1}"
        )));
    }
    if off2 <= len1 {
        return Err(RevenantError::Pdf(format!(
            "Invalid ByteRange: off2 ({off2}) must be greater than len1 ({len1})"
        )));
    }
    if off2 > pdf_bytes.len() {
        return Err(RevenantError::Pdf(format!(
            "Invalid ByteRange: off2 ({off2}) exceeds PDF size ({})",
            pdf_bytes.len()
        )));
    }

    // The hex signature sits between angle brackets in the gap between chunks.
    // Two conventions exist for where the '<' falls:
    //   Revenant:        '<' is at len1-1 (included in chunk1), hex starts at len1
    //   Original cosign: '<' is at len1 (first gap byte),       hex starts at len1+1
    // The '>' is consistently at off2-1 in both.
    let hex_start = if pdf_bytes.get(len1 - 1) == Some(&b'<') {
        len1
    } else if pdf_bytes.get(len1) == Some(&b'<') {
        len1 + 1
    } else {
        return Err(RevenantError::Pdf(format!(
            "Expected '<' near offset {len1}"
        )));
    };

    let hex_end = off2 - 1; // position of '>'
    if pdf_bytes.get(hex_end) != Some(&b'>') {
        return Err(RevenantError::Pdf(format!(
            "Expected '>' at offset {hex_end}"
        )));
    }

    let hex_region = pdf_bytes
        .get(hex_start..hex_end)
        .ok_or_else(|| RevenantError::Pdf("CMS hex region is empty or inverted".to_owned()))?;
    let hex_region = std::str::from_utf8(hex_region)
        .map_err(|_| RevenantError::Pdf("CMS hex region is not ASCII".to_owned()))?;

    // A PDF hexadecimal string may contain white space, which is not significant
    // (ISO 32000-1 section 7.3.4.3). Strip every whitespace byte -- not just the
    // ends -- so the ASN.1 length walk sees contiguous hex regardless of how the
    // producing tool laid out the `/Contents` field.
    let hex_str: String = hex_region
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();

    extract_der_from_padded_hex(&hex_str)
        .map_err(|e| RevenantError::Pdf(format!("Invalid hex in CMS blob: {e}")))
}

/// Extract the signed data and the CMS blob for one `/ByteRange`.
///
/// Returns `(signed_data, cms_der)` where `signed_data` is the two byte-range
/// chunks concatenated (what the signature is computed over).
///
/// # Errors
///
/// Returns [`RevenantError::Pdf`] if the byte range is invalid or extraction
/// fails.
pub fn extract_signature_data_for(pdf_bytes: &[u8], br: &ByteRange) -> Result<(Vec<u8>, Vec<u8>)> {
    if br.off1 != 0 {
        return Err(RevenantError::Pdf(format!(
            "ByteRange offset1 should be 0, got {}",
            br.off1
        )));
    }
    if br.off2 <= br.len1 {
        return Err(RevenantError::Pdf(format!(
            "ByteRange offset2 ({}) <= len1 ({})",
            br.off2, br.len1
        )));
    }
    let end2 = br
        .off2
        .checked_add(br.len2)
        .ok_or_else(|| RevenantError::Pdf("ByteRange chunk2 length overflows".to_owned()))?;
    if end2 > pdf_bytes.len() {
        return Err(RevenantError::Pdf(format!(
            "ByteRange extends beyond EOF: {}+{} > {}",
            br.off2,
            br.len2,
            pdf_bytes.len()
        )));
    }

    let chunk1 = pdf_bytes
        .get(br.off1..br.off1 + br.len1)
        .ok_or_else(|| RevenantError::Pdf("ByteRange chunk1 out of bounds".to_owned()))?;
    let chunk2 = pdf_bytes
        .get(br.off2..end2)
        .ok_or_else(|| RevenantError::Pdf("ByteRange chunk2 out of bounds".to_owned()))?;

    let mut signed_data = Vec::with_capacity(chunk1.len() + chunk2.len());
    signed_data.extend_from_slice(chunk1);
    signed_data.extend_from_slice(chunk2);

    let cms_der = extract_cms_from_byterange(pdf_bytes, br.len1, br.off2)?;
    Ok((signed_data, cms_der))
}

/// Extract the signed data and CMS blob from the last (most recent) signature.
///
/// # Errors
///
/// Returns [`RevenantError::Pdf`] if the PDF has no `/ByteRange` or the last
/// signature cannot be extracted.
pub fn extract_signature_data(pdf_bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let ranges = find_byteranges(pdf_bytes)?;
    let last = ranges.last().ok_or_else(|| {
        RevenantError::Pdf("No /ByteRange found in PDF -- not a signed PDF?".to_owned())
    })?;
    extract_signature_data_for(pdf_bytes, last)
}

/// Parse one capture group of the byte-range regex as a `usize`.
fn parse_group(caps: &regex::bytes::Captures<'_>, index: usize) -> Result<usize> {
    let raw = caps
        .get(index)
        .ok_or_else(|| RevenantError::Pdf("ByteRange match missing a capture group".to_owned()))?
        .as_bytes();
    // The regex only captures ASCII digits, so `from_utf8` cannot fail here.
    let text = std::str::from_utf8(raw)
        .map_err(|_| RevenantError::Pdf("ByteRange integer is not ASCII".to_owned()))?;
    text.parse::<usize>()
        .map_err(|e| RevenantError::Pdf(format!("Invalid ByteRange integer {text:?}: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    const CMS: [u8; 5] = [0x30, 0x03, 0x01, 0x02, 0x03];

    fn padded_hex(der: &[u8], width: usize) -> String {
        let mut s = hex::encode(der);
        s.push_str(&"0".repeat(width - s.len()));
        s
    }

    #[test]
    fn pattern_compiles() {
        assert!(BYTERANGE_RE.captures_iter(b"nope").next().is_none());
    }

    #[test]
    fn finds_and_parses_byteranges() {
        let pdf = b"header /ByteRange [0 840 960 1240] middle /ByteRange[0 10 20 30]tail";
        let ranges = find_byteranges(pdf).unwrap();
        assert_eq!(ranges.len(), 2);
        assert_eq!(
            ranges[0],
            ByteRange {
                off1: 0,
                len1: 840,
                off2: 960,
                len2: 1240
            }
        );
        assert_eq!(ranges.last().unwrap().len1, 10);
    }

    #[test]
    fn extracts_cms_revenant_convention() {
        // chunk1 includes the '<' (Revenant convention).
        let hex = padded_hex(&CMS, 40);
        let mut pdf = b"prefix<".to_vec();
        let head_len = pdf.len(); // '<' is the last byte, at head_len-1
        pdf.extend_from_slice(hex.as_bytes());
        pdf.push(b'>');
        pdf.extend_from_slice(b"trailer");
        let len1 = head_len; // '<' at len1-1
        let off2 = head_len + hex.len() + 1; // right after '>'
        assert_eq!(extract_cms_from_byterange(&pdf, len1, off2).unwrap(), CMS);
    }

    #[test]
    fn extracts_cms_original_cosign_convention() {
        // '<' sits just outside chunk1 (original cosign convention).
        let hex = padded_hex(&CMS, 40);
        let mut pdf = b"prefix".to_vec();
        let len1 = pdf.len(); // '<' will be at index len1
        pdf.push(b'<');
        pdf.extend_from_slice(hex.as_bytes());
        pdf.push(b'>');
        let off2 = pdf.len(); // '>' is the last byte, at off2-1
        assert_eq!(extract_cms_from_byterange(&pdf, len1, off2).unwrap(), CMS);
    }

    #[test]
    fn tolerates_interior_whitespace_in_hex() {
        // A producer that laid out /Contents with spaces and newlines between
        // hex digits is still valid PDF; extraction must ignore the whitespace.
        let spaced = "30 03\n01 02 03";
        let mut pdf = b"prefix<".to_vec();
        let head_len = pdf.len();
        pdf.extend_from_slice(spaced.as_bytes());
        // Pad the remainder of the reserved field with zeros, then close.
        pdf.extend_from_slice(b"00000000");
        pdf.push(b'>');
        let off2 = pdf.len();
        assert_eq!(
            extract_cms_from_byterange(&pdf, head_len, off2).unwrap(),
            CMS
        );
    }

    #[test]
    fn rejects_missing_open_bracket() {
        let pdf = b"prefixXXXX>tail";
        let err = extract_cms_from_byterange(pdf, 6, 11).unwrap_err();
        assert!(matches!(err, RevenantError::Pdf(m) if m.contains("Expected '<'")));
    }

    #[test]
    fn rejects_missing_close_bracket() {
        let hex = padded_hex(&CMS, 40);
        let mut pdf = b"prefix<".to_vec();
        let head_len = pdf.len();
        pdf.extend_from_slice(hex.as_bytes());
        pdf.push(b'X'); // not '>'
        let off2 = head_len + hex.len() + 1;
        let err = extract_cms_from_byterange(&pdf, head_len, off2).unwrap_err();
        assert!(matches!(err, RevenantError::Pdf(m) if m.contains("Expected '>'")));
    }

    #[test]
    fn extract_signature_data_roundtrips_last_signature() {
        // A fixed len2 keeps the ByteRange numbers embedded in the tail
        // self-consistent regardless of how many digits the offsets take.
        const LEN2: usize = 64;

        // Assemble: [head]<hex>[tail-with-ByteRange].
        let hex = padded_hex(&CMS, 40);
        let mut prefix = b"%PDF-1.4 fake body <".to_vec();
        let len1 = prefix.len(); // '<' at len1-1
        prefix.extend_from_slice(hex.as_bytes());
        prefix.push(b'>');
        let off2 = prefix.len(); // chunk2 starts right after '>'

        let mut tail = format!("\n/ByteRange [0 {len1} {off2} {LEN2}]\n").into_bytes();
        assert!(tail.len() <= LEN2);
        tail.resize(LEN2, b' '); // pad so len2 == LEN2 exactly

        let mut pdf = prefix.clone();
        pdf.extend_from_slice(&tail);

        let (signed, cms) = extract_signature_data(&pdf).unwrap();
        assert_eq!(cms, CMS);
        let mut expected = prefix[..len1].to_vec();
        expected.extend_from_slice(&pdf[off2..off2 + LEN2]);
        assert_eq!(signed, expected);
    }

    #[test]
    fn errors_when_no_signature_present() {
        let err = extract_signature_data(b"just a plain document").unwrap_err();
        assert!(matches!(err, RevenantError::Pdf(m) if m.contains("No /ByteRange")));
    }
}
