//! Extracting the exact CMS blob from a zero-padded hex placeholder.
//!
//! A signed PDF reserves space for the signature as a fixed-size `/Contents`
//! hex string, right-padded with zeros. To recover the real signature we must
//! find where the CMS structure ends inside that padding. Two encodings occur:
//!
//! * **DER (definite length):** the ASN.1 `SEQUENCE` header states the exact
//!   content length, so the total size is known from the first few bytes.
//! * **BER (indefinite length):** the original EKENG cosign tool emits
//!   `30 80 ... 00 00`; the blob ends at the top-level end-of-contents marker,
//!   which we locate by walking the TLV structure (the trailing zeros are
//!   indistinguishable from the padding otherwise).
//!
//! This is a pure byte/hex utility with no PDF or crypto knowledge; it returns
//! `Result<_, String>` and the caller maps failures onto the library error
//! type.

/// ASN.1 `SEQUENCE` tag -- the first byte of any valid CMS/PKCS#7 blob.
pub const ASN1_SEQUENCE_TAG: u8 = 0x30;

/// Minimum plausible CMS blob size in bytes (header + basic content).
pub const MIN_CMS_SIZE: usize = 100;

/// Maximum hex chars for a single CMS blob (16 MB DER = 32M hex chars).
/// Guards against a malformed length field claiming an absurd size.
const MAX_CMS_HEX_CHARS: usize = 32 * 1024 * 1024;

/// End-of-contents octets terminating a BER indefinite-length encoding.
const EOC_BYTES: [u8; 2] = [0x00, 0x00];

/// Maximum BER nesting depth before we treat the structure as hostile.
const MAX_BER_DEPTH: usize = 64;

/// Extract the exact CMS blob from a zero-padded hex string.
///
/// Handles both DER (definite length) and BER (indefinite length) encodings.
///
/// # Errors
///
/// Returns a human-readable message if the hex is invalid or the ASN.1 header
/// is malformed, exceeds the size cap, or claims more data than is present.
pub(crate) fn extract_der_from_padded_hex(hex_str: &str) -> Result<Vec<u8>, String> {
    if hex_str.len() < 4 {
        return Err("Hex string too short for ASN.1 TLV header".to_owned());
    }
    // Hex is ASCII by definition; a non-ASCII byte cannot be a hex digit, and
    // rejecting it up front keeps the byte-index slicing below panic-free.
    if !hex_str.is_ascii() {
        return Err("Hex string contains non-hex characters".to_owned());
    }

    let tag = parse_hex_u8(&hex_str[0..2])?;
    if tag != ASN1_SEQUENCE_TAG {
        return Err(format!("Expected ASN.1 SEQUENCE (0x30), got 0x{tag:02x}"));
    }

    let length_byte = parse_hex_u8(&hex_str[2..4])?;
    if length_byte == 0x80 {
        // BER indefinite length: walk the TLV structure to find the EOC.
        return extract_ber_indefinite(hex_str);
    }

    let mut header_bytes = 2usize; // tag + initial length byte
    let content_len = if length_byte < 0x80 {
        // Short form: the length byte IS the length.
        usize::from(length_byte)
    } else {
        // Long form: the lower 7 bits count the length bytes that follow.
        let num_len_bytes = usize::from(length_byte & 0x7f);
        if num_len_bytes > 4 {
            return Err(format!(
                "ASN.1 length field too large: {num_len_bytes} bytes"
            ));
        }
        header_bytes += num_len_bytes;
        let needed_hex = 4 + num_len_bytes * 2;
        if hex_str.len() < needed_hex {
            return Err("Hex string too short for ASN.1 length field".to_owned());
        }
        parse_hex_uint(&hex_str[4..needed_hex])?
    };

    let total_der_bytes = header_bytes.saturating_add(content_len);
    let total_hex_chars = total_der_bytes.saturating_mul(2);

    if total_hex_chars > MAX_CMS_HEX_CHARS {
        return Err(format!(
            "ASN.1 claims {total_der_bytes} bytes, exceeds maximum ({} bytes)",
            MAX_CMS_HEX_CHARS / 2
        ));
    }
    if total_hex_chars > hex_str.len() {
        return Err(format!(
            "ASN.1 length ({total_der_bytes} bytes) exceeds available hex data ({} bytes)",
            hex_str.len() / 2
        ));
    }

    decode_hex(&hex_str[..total_hex_chars])
}

/// Extract a BER indefinite-length blob from zero-padded hex.
///
/// Decodes the full hex, then walks the TLV structure to find where the
/// top-level `SEQUENCE`'s EOC marker (`00 00`) is; everything after it is
/// padding from the PDF placeholder.
fn extract_ber_indefinite(hex_str: &str) -> Result<Vec<u8>, String> {
    let raw = decode_hex(hex_str)?;
    let end = raw.len();
    // Start after the top-level tag (0x30) and length (0x80).
    let mut pos = 2usize;

    while pos < end {
        if raw[pos..].starts_with(&EOC_BYTES) {
            return Ok(raw[..pos + 2].to_vec());
        }
        pos = skip_tlv(&raw, pos, end, 0)?;
    }

    Err("BER indefinite-length SEQUENCE: EOC marker not found".to_owned())
}

/// Skip a single TLV element, returning the position after it. Handles both
/// definite and indefinite length children.
fn skip_tlv(data: &[u8], pos: usize, end: usize, depth: usize) -> Result<usize, String> {
    if depth > MAX_BER_DEPTH {
        return Err(format!(
            "BER parse: nesting too deep (>{MAX_BER_DEPTH} levels)"
        ));
    }
    if pos >= end {
        return Err(format!("BER parse: unexpected end at offset {pos}"));
    }

    // Skip the tag byte(s): single-byte, or high-tag-number form (0x1f) whose
    // continuation bytes each have the high bit set until a final byte < 0x80.
    let tag_byte = data[pos];
    let mut cursor = pos + 1;
    if tag_byte & 0x1f == 0x1f {
        while cursor < end && data[cursor] & 0x80 != 0 {
            cursor += 1;
        }
        cursor += 1; // final tag byte
    }

    if cursor >= end {
        return Err("BER parse: tag extends beyond data".to_owned());
    }

    let length_byte = data[cursor];
    cursor += 1;

    if length_byte == 0x80 {
        // Indefinite-length child: walk its children until their EOC.
        while cursor < end {
            if data[cursor..].starts_with(&EOC_BYTES) {
                return Ok(cursor + 2);
            }
            cursor = skip_tlv(data, cursor, end, depth + 1)?;
        }
        return Err("BER parse: nested indefinite-length without EOC".to_owned());
    }

    let content_len = if length_byte < 0x80 {
        usize::from(length_byte)
    } else {
        let num_len_bytes = usize::from(length_byte & 0x7f);
        // A length wider than a machine word cannot be represented; a real CMS
        // never exceeds four length bytes, so reject the rest as hostile.
        if num_len_bytes > core::mem::size_of::<usize>() {
            return Err(format!(
                "BER parse: length field too large: {num_len_bytes} bytes"
            ));
        }
        if cursor + num_len_bytes > end {
            return Err("BER parse: length field extends beyond data".to_owned());
        }
        let mut len = 0usize;
        for &byte in &data[cursor..cursor + num_len_bytes] {
            len = (len << 8) | usize::from(byte);
        }
        cursor += num_len_bytes;
        len
    };

    Ok(cursor.saturating_add(content_len))
}

/// Parse two hex chars into a byte.
fn parse_hex_u8(pair: &str) -> Result<u8, String> {
    u8::from_str_radix(pair, 16).map_err(|_| format!("Invalid hex byte: {pair:?}"))
}

/// Parse a run of hex chars into an unsigned integer.
fn parse_hex_uint(digits: &str) -> Result<usize, String> {
    usize::from_str_radix(digits, 16).map_err(|_| format!("Invalid hex length field: {digits:?}"))
}

/// Strictly decode an even-length string of hex digits into bytes, erroring on
/// odd length or a non-hex digit rather than silently truncating -- a malformed
/// placeholder must be caught, not half-decoded.
fn decode_hex(hex_str: &str) -> Result<Vec<u8>, String> {
    hex::decode(hex_str).map_err(|e| format!("invalid hex: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pad a DER blob's hex with trailing zeros to a fixed placeholder width.
    fn padded(der: &[u8], width: usize) -> String {
        let mut s = hex::encode(der);
        s.push_str(&"0".repeat(width - s.len()));
        s
    }

    #[test]
    fn extracts_short_form_der() {
        // SEQUENCE, length 3, three content bytes.
        let der = [0x30, 0x03, 0x01, 0x02, 0x03];
        let hex = padded(&der, 200);
        assert_eq!(extract_der_from_padded_hex(&hex).unwrap(), der);
    }

    #[test]
    fn extracts_long_form_der() {
        // SEQUENCE, long-form length 0x81 0x80 (128 content bytes).
        let mut der = vec![0x30, 0x81, 0x80];
        der.extend(std::iter::repeat_n(0xAB, 128));
        let hex = padded(&der, 1000);
        assert_eq!(extract_der_from_padded_hex(&hex).unwrap(), der);
    }

    #[test]
    fn extracts_ber_indefinite() {
        // SEQUENCE (indefinite) { OCTET STRING "hi" } EOC, then zero padding.
        let der = [0x30, 0x80, 0x04, 0x02, b'h', b'i', 0x00, 0x00];
        let hex = padded(&der, 200);
        assert_eq!(extract_der_from_padded_hex(&hex).unwrap(), der);
    }

    #[test]
    fn ber_walks_nested_indefinite_children() {
        // Outer indefinite SEQUENCE containing an inner indefinite SEQUENCE.
        let der = [
            0x30, 0x80, // outer SEQUENCE, indefinite
            0x30, 0x80, // inner SEQUENCE, indefinite
            0x04, 0x01, b'x', // OCTET STRING "x"
            0x00, 0x00, // inner EOC
            0x00, 0x00, // outer EOC
        ];
        let hex = padded(&der, 200);
        assert_eq!(extract_der_from_padded_hex(&hex).unwrap(), der);
    }

    #[test]
    fn rejects_non_sequence_tag() {
        let err = extract_der_from_padded_hex("02030102030000").unwrap_err();
        assert!(err.contains("Expected ASN.1 SEQUENCE"), "{err}");
    }

    #[test]
    fn rejects_too_short() {
        let err = extract_der_from_padded_hex("30").unwrap_err();
        assert!(err.contains("too short"), "{err}");
    }

    #[test]
    fn rejects_length_exceeding_available_data() {
        // Claims 200 content bytes but only a few hex chars are present.
        let err = extract_der_from_padded_hex("3081c8").unwrap_err();
        assert!(err.contains("exceeds available hex data"), "{err}");
    }

    #[test]
    fn rejects_oversized_length_field() {
        // 0x85 => five length bytes, over the four-byte cap.
        let err = extract_der_from_padded_hex("30850000000000").unwrap_err();
        assert!(err.contains("length field too large"), "{err}");
    }

    #[test]
    fn rejects_ber_without_eoc() {
        // Indefinite SEQUENCE whose only child ends exactly at the buffer end,
        // with no EOC and no trailing padding (padding zeros would themselves
        // read as a terminating `00 00`, which is the correct BER behavior).
        let der = [0x30, 0x80, 0x04, 0x03, b'a', b'b', b'c'];
        let hex = hex::encode(der);
        let err = extract_der_from_padded_hex(&hex).unwrap_err();
        assert!(err.contains("EOC marker not found"), "{err}");
    }

    #[test]
    fn rejects_non_hex_input() {
        let err = extract_der_from_padded_hex("30zz0102").unwrap_err();
        assert!(
            err.contains("Invalid hex byte") || err.contains("invalid hex"),
            "{err}"
        );
    }
}
