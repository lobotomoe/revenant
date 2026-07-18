//! PDF structure analysis and incremental-update assembly.
//!
//! Reads the bits of existing PDF structure that a byte-level scan handles best
//! -- the authoritative `/Root` reference, the last `startxref`, and whether the
//! file uses cross-reference streams -- then assembles the incremental update:
//! the new objects, a matching xref (table or stream), and the trailer. The
//! `/Size` and `/Info`+`/ID` carry-forward come from [`super::reader::PdfReader`]
//! (which resolves xref streams correctly); object dictionaries are read there
//! too.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use regex::bytes::Regex;

use super::objects::{deflate, BYTERANGE_PLACEHOLDER, CMS_HEX_SIZE};
use super::reader::ObjRef;
use crate::{Result, RevenantError};

/// The last `/Root N G R` wins: incremental updates may redefine it.
static ROOT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"/Root\s+(\d+)\s+(\d+)\s+R").expect("valid /Root regex"));
/// Lenient `startxref` match (some PDFs have trailing junk after `%%EOF`).
static STARTXREF_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"startxref\s+(\d+)\s+%%EOF").expect("valid startxref regex"));
/// At the last `startxref` offset, an object definition (rather than `xref`)
/// means the PDF uses cross-reference streams.
static XREF_STREAM_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*\d+\s+\d+\s+obj\b").expect("valid xref-stream regex"));

// ── Structure analysis ──────────────────────────────────────────────────

/// Find the catalog `/Root` object number and generation from the trailer.
///
/// # Errors
///
/// Returns [`RevenantError::Pdf`] if no `/Root` reference is present.
pub fn find_root_obj_num(pdf_bytes: &[u8]) -> Result<ObjRef> {
    let caps = ROOT_RE.captures_iter(pdf_bytes).last().ok_or_else(|| {
        RevenantError::Pdf("Cannot find /Root reference in PDF trailer.".to_owned())
    })?;
    let num = parse_uint::<u32>(&caps[1])?;
    let gen = parse_uint::<u16>(&caps[2])?;
    Ok(ObjRef::new(num, gen))
}

/// Find the byte offset from the last `startxref`.
///
/// # Errors
///
/// Returns [`RevenantError::Pdf`] if no `startxref` is present.
pub fn find_startxref_offset(pdf_bytes: &[u8]) -> Result<usize> {
    let caps = STARTXREF_RE
        .captures_iter(pdf_bytes)
        .last()
        .ok_or_else(|| RevenantError::Pdf("Cannot find startxref in PDF.".to_owned()))?;
    parse_uint::<usize>(&caps[1])
}

/// Detect whether the PDF uses cross-reference streams (PDF 1.5+).
///
/// An incremental update must match the source format (ISO 32000-1 S7.5.8.4).
#[must_use]
pub fn detect_xref_stream(pdf_bytes: &[u8], startxref_offset: usize) -> bool {
    let end = startxref_offset.saturating_add(40).min(pdf_bytes.len());
    let chunk = pdf_bytes.get(startxref_offset..end).unwrap_or(&[]);
    XREF_STREAM_RE.is_match(chunk)
}

// ── Incremental update assembly ─────────────────────────────────────────

/// The pieces of trailer identity carried forward into an incremental update.
#[derive(Debug, Clone)]
pub struct UpdatePlan<'a> {
    /// The `(raw_bytes, obj_num)` objects to append, in order.
    pub raw_objects: &'a [(Vec<u8>, u32)],
    /// The new `/Size` (one past the highest object number).
    pub new_size: u32,
    /// The previous `startxref` offset (`/Prev`).
    pub prev_xref: usize,
    /// The catalog `/Root` reference.
    pub root: ObjRef,
    /// Extra trailer entries to carry forward (`/Info`, `/ID`).
    pub trailer_extra: &'a [String],
    /// Whether to emit a cross-reference stream instead of a table.
    pub use_xref_stream: bool,
}

/// Assemble the full PDF with the incremental update appended.
///
/// The original bytes are preserved exactly (a newline is added only if the file
/// does not already end with one), so the signed byte range covers the original
/// document unchanged.
///
/// # Errors
///
/// Returns [`RevenantError::Pdf`] if there are no objects to reference, or if
/// xref-stream compression fails.
pub fn assemble_incremental_update(pdf_bytes: &[u8], plan: &UpdatePlan<'_>) -> Result<Vec<u8>> {
    let mut base = pdf_bytes.to_vec();
    if !base.ends_with(b"\n") {
        base.push(b'\n');
    }
    let update_start = base.len();

    let mut xref_entries: BTreeMap<u32, usize> = BTreeMap::new();
    let mut running = update_start;
    let mut objects = Vec::new();
    for (raw, obj_num) in plan.raw_objects {
        xref_entries.insert(*obj_num, running);
        objects.extend_from_slice(raw);
        running = running.saturating_add(raw.len());
    }

    let xref_offset = update_start + objects.len();
    let ObjRef {
        num: root_obj_num,
        gen: root_gen,
    } = plan.root;

    let tail = if plan.use_xref_stream {
        build_xref_stream(
            &xref_entries,
            plan.prev_xref,
            root_obj_num,
            root_gen,
            plan.trailer_extra,
            xref_offset,
            plan.new_size,
        )?
    } else {
        build_xref_and_trailer(
            &xref_entries,
            plan.new_size,
            plan.prev_xref,
            root_obj_num,
            root_gen,
            plan.trailer_extra,
            xref_offset,
        )?
    };

    let mut out = base;
    out.extend_from_slice(&objects);
    out.extend_from_slice(&tail);
    Ok(out)
}

/// A PDF prepared for hash-then-sign: the bytes with an empty signature field
/// and a patched `/ByteRange`, plus where the reserved `/Contents` hex
/// placeholder sits so the caller can hash the ByteRange and later splice in the
/// CMS.
#[derive(Debug, Clone)]
pub struct PreparedPdf {
    /// The prepared PDF bytes.
    pub bytes: Vec<u8>,
    /// Byte offset of the reserved `/Contents` hex placeholder.
    pub contents_hex_offset: usize,
    /// Length of the `/Contents` hex placeholder, in bytes.
    pub contents_hex_len: usize,
}

/// Patch the `/ByteRange` placeholder in the incremental update.
///
/// The search starts at `original_len` so it only touches the freshly appended
/// signature, never a placeholder in a previously signed document.
///
/// # Errors
///
/// Returns [`RevenantError::Pdf`] if either placeholder is missing, the
/// `/Contents` field is not the expected zero-filled shape, or the computed
/// ByteRange overflows the fixed-width placeholder.
pub fn patch_byterange(mut full_pdf: Vec<u8>, original_len: usize) -> Result<PreparedPdf> {
    let prefix = b"/Contents <";
    let contents_pos = find_from(&full_pdf, prefix, original_len).ok_or_else(|| {
        RevenantError::Pdf("Cannot find Contents placeholder in prepared PDF.".to_owned())
    })?;
    let hex_start = contents_pos + prefix.len();
    let hex_end = hex_start + CMS_HEX_SIZE;

    // The reserved field must be exactly CMS_HEX_SIZE zeros closed by '>'.
    let is_zero_filled = full_pdf
        .get(hex_start..hex_end)
        .is_some_and(|s| s.iter().all(|&b| b == b'0'));
    if !is_zero_filled || full_pdf.get(hex_end) != Some(&b'>') {
        return Err(RevenantError::Pdf(
            "Contents placeholder is not the expected zero-filled field.".to_owned(),
        ));
    }

    let br_before_len = hex_start;
    let br_after_start = hex_end + 1; // +1 for the closing '>'
    let br_after_len = full_pdf.len() - br_after_start;
    let byterange_value = format!(
        "/ByteRange [{:>10} {:>10} {:>10} {:>10}]",
        0, br_before_len, br_after_start, br_after_len
    );
    if byterange_value.len() != BYTERANGE_PLACEHOLDER.len() {
        return Err(RevenantError::Pdf(format!(
            "ByteRange value ({} bytes) does not fit the fixed placeholder ({} bytes); \
             the document is too large to sign.",
            byterange_value.len(),
            BYTERANGE_PLACEHOLDER.len()
        )));
    }

    let br_pos =
        find_from(&full_pdf, BYTERANGE_PLACEHOLDER.as_bytes(), original_len).ok_or_else(|| {
            RevenantError::Pdf(
                "Cannot find ByteRange placeholder in incremental update.".to_owned(),
            )
        })?;
    // In-place patch: same width, so no offsets shift and hex_start stays valid.
    full_pdf[br_pos..br_pos + byterange_value.len()].copy_from_slice(byterange_value.as_bytes());

    Ok(PreparedPdf {
        bytes: full_pdf,
        contents_hex_offset: hex_start,
        contents_hex_len: CMS_HEX_SIZE,
    })
}

// ── Xref builders ───────────────────────────────────────────────────────

/// Build an xref table and trailer for an incremental update.
///
/// # Errors
///
/// Returns [`RevenantError::Pdf`] if there are no entries to reference.
pub fn build_xref_and_trailer(
    xref_entries: &BTreeMap<u32, usize>,
    new_size: u32,
    prev_xref: usize,
    root_obj_num: u32,
    root_gen: u16,
    trailer_extra: &[String],
    xref_offset: usize,
) -> Result<Vec<u8>> {
    if xref_entries.is_empty() {
        return Err(RevenantError::Pdf(
            "Cannot build xref table: no objects to reference.".to_owned(),
        ));
    }

    let nums: Vec<u32> = xref_entries.keys().copied().collect();
    let mut lines: Vec<String> = vec!["xref".to_owned()];
    for group in group_consecutive(&nums) {
        lines.push(format!("{} {}", group[0], group.len()));
        for obj_num in group {
            let offset = xref_entries[&obj_num];
            // 20-byte entry: "oooooooooo ggggg n\r" + the joining "\n".
            lines.push(format!("{offset:010} 00000 n\r"));
        }
    }

    lines.push("trailer".to_owned());
    lines.push("<<".to_owned());
    lines.push(format!("  /Size {new_size}"));
    lines.push(format!("  /Prev {prev_xref}"));
    lines.push(format!("  /Root {root_obj_num} {root_gen} R"));
    for extra in trailer_extra {
        lines.push(format!("  {extra}"));
    }
    lines.push(">>".to_owned());
    lines.push("startxref".to_owned());
    lines.push(xref_offset.to_string());
    lines.push("%%EOF".to_owned());
    lines.push(String::new()); // trailing newline

    Ok(lines.join("\n").into_bytes())
}

/// Build a cross-reference stream for an incremental update (PDF 1.5+).
///
/// # Errors
///
/// Returns [`RevenantError::Pdf`] if compression fails.
pub fn build_xref_stream(
    xref_entries: &BTreeMap<u32, usize>,
    prev_xref: usize,
    root_obj_num: u32,
    root_gen: u16,
    trailer_extra: &[String],
    xref_offset: usize,
    xref_obj_num: u32,
) -> Result<Vec<u8>> {
    // The xref stream references itself.
    let mut all_entries = xref_entries.clone();
    all_entries.insert(xref_obj_num, xref_offset);

    let actual_size = xref_obj_num + 1;
    let max_offset = all_entries.values().copied().max().unwrap_or(0);
    let w2 = bytes_needed(max_offset);

    let nums: Vec<u32> = all_entries.keys().copied().collect();
    let mut index_parts: Vec<String> = Vec::new();
    let mut binary = Vec::new();
    for group in group_consecutive(&nums) {
        index_parts.push(format!("{} {}", group[0], group.len()));
        for obj_num in group {
            let offset = all_entries[&obj_num];
            binary.push(1u8); // type 1 = in-use, uncompressed
            binary.extend_from_slice(&offset_be_bytes(offset, w2));
            binary.push(0u8); // generation
        }
    }

    let compressed = deflate(&binary)?;

    let mut lines: Vec<String> = vec![
        format!("{xref_obj_num} 0 obj"),
        "<<".to_owned(),
        "  /Type /XRef".to_owned(),
        format!("  /Size {actual_size}"),
        format!("  /Prev {prev_xref}"),
        format!("  /Root {root_obj_num} {root_gen} R"),
        format!("  /W [1 {w2} 1]"),
        format!("  /Index [{}]", index_parts.join(" ")),
        "  /Filter /FlateDecode".to_owned(),
        format!("  /Length {}", compressed.len()),
    ];
    for extra in trailer_extra {
        lines.push(format!("  {extra}"));
    }
    lines.push(">>".to_owned());
    lines.push("stream".to_owned());

    let mut out = lines.join("\n").into_bytes();
    out.push(b'\n');
    out.extend_from_slice(&compressed);
    out.extend_from_slice(
        format!("\nendstream\nendobj\nstartxref\n{xref_offset}\n%%EOF\n").as_bytes(),
    );
    Ok(out)
}

// ── Helpers ─────────────────────────────────────────────────────────────

/// Group sorted object numbers into consecutive runs for xref subsections.
fn group_consecutive(sorted_nums: &[u32]) -> Vec<Vec<u32>> {
    let mut groups: Vec<Vec<u32>> = Vec::new();
    for &n in sorted_nums {
        match groups.last_mut() {
            Some(group) if group.last().copied() == n.checked_sub(1) => group.push(n),
            _ => groups.push(vec![n]),
        }
    }
    groups
}

/// Minimum bytes to hold a byte offset big-endian, capped at 4 (xref-stream
/// offsets are assumed to fit 32 bits -- true for any real PDF).
fn bytes_needed(value: usize) -> usize {
    if value <= 0xFF {
        1
    } else if value <= 0xFFFF {
        2
    } else if value <= 0x00FF_FFFF {
        3
    } else {
        4
    }
}

/// The low `width` big-endian bytes of an offset.
fn offset_be_bytes(offset: usize, width: usize) -> Vec<u8> {
    let full = u64::try_from(offset).unwrap_or(u64::MAX).to_be_bytes();
    full[full.len().saturating_sub(width)..].to_vec()
}

/// Parse an unsigned integer from ASCII digit bytes.
fn parse_uint<T: std::str::FromStr>(bytes: &[u8]) -> Result<T> {
    std::str::from_utf8(bytes)
        .ok()
        .and_then(|s| s.parse::<T>().ok())
        .ok_or_else(|| RevenantError::Pdf("Malformed integer in PDF structure.".to_owned()))
}

/// Find `needle` in `haystack` at or after `from`.
fn find_from(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || from >= haystack.len() {
        return None;
    }
    haystack[from..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| p + from)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BLANK_LETTER: &[u8] = include_bytes!("testdata/blank_letter.pdf");
    const XREF_STREAM: &[u8] = include_bytes!("testdata/blank_letter_xref_stream.pdf");

    #[test]
    fn finds_root_and_startxref() {
        let root = find_root_obj_num(BLANK_LETTER).unwrap();
        assert!(root.num > 0);
        let off = find_startxref_offset(BLANK_LETTER).unwrap();
        assert!(off > 0 && off < BLANK_LETTER.len());
    }

    #[test]
    fn detects_format() {
        let off = find_startxref_offset(BLANK_LETTER).unwrap();
        assert!(!detect_xref_stream(BLANK_LETTER, off));
        let off2 = find_startxref_offset(XREF_STREAM).unwrap();
        assert!(detect_xref_stream(XREF_STREAM, off2));
    }

    #[test]
    fn missing_root_errors() {
        assert!(find_root_obj_num(b"not a pdf").is_err());
        assert!(find_startxref_offset(b"not a pdf").is_err());
    }

    #[test]
    fn groups_consecutive_runs() {
        assert_eq!(
            group_consecutive(&[1, 2, 3, 7, 8, 10]),
            vec![vec![1, 2, 3], vec![7, 8], vec![10]]
        );
        assert!(group_consecutive(&[]).is_empty());
    }

    #[test]
    fn bytes_needed_boundaries() {
        assert_eq!(bytes_needed(0), 1);
        assert_eq!(bytes_needed(255), 1);
        assert_eq!(bytes_needed(256), 2);
        assert_eq!(bytes_needed(65_535), 2);
        assert_eq!(bytes_needed(65_536), 3);
        assert_eq!(bytes_needed(16_777_216), 4);
    }

    #[test]
    fn offset_bytes_are_big_endian() {
        assert_eq!(offset_be_bytes(0x1234, 2), vec![0x12, 0x34]);
        assert_eq!(offset_be_bytes(0xAB, 1), vec![0xAB]);
        assert_eq!(offset_be_bytes(0x01_0203, 3), vec![0x01, 0x02, 0x03]);
    }

    #[test]
    fn xref_table_has_20_byte_entries() {
        let mut entries = BTreeMap::new();
        entries.insert(4u32, 100usize);
        entries.insert(5u32, 250usize);
        let extra = vec!["/Info 2 0 R".to_owned()];
        let raw = build_xref_and_trailer(&entries, 6, 42, 1, 0, &extra, 999).unwrap();
        let s = String::from_utf8(raw).unwrap();
        assert!(s.starts_with("xref\n4 2\n"), "{s}");
        assert!(s.contains("0000000100 00000 n\r\n"), "{s}");
        assert!(s.contains("/Size 6"), "{s}");
        assert!(s.contains("/Prev 42"), "{s}");
        assert!(s.contains("/Root 1 0 R"), "{s}");
        assert!(s.contains("/Info 2 0 R"), "{s}");
        assert!(s.trim_end().ends_with("%%EOF"), "{s}");
    }

    #[test]
    fn empty_xref_errors() {
        let entries = BTreeMap::new();
        assert!(build_xref_and_trailer(&entries, 1, 0, 1, 0, &[], 0).is_err());
    }
}
