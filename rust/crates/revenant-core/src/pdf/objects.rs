//! Low-level PDF object construction for signature incremental updates.
//!
//! Constants, string escaping, object-number allocation, and page/catalog
//! overrides. PDF structure analysis and update assembly live in
//! [`super::incremental`]; the visual objects (fonts, forms, widgets) in
//! [`super::render`]; the high-level API in [`super::builder`].

use std::io::Write as _;

use flate2::write::ZlibEncoder;
use flate2::Compression;

use super::reader::PdfReader;
use crate::{Result, RevenantError};

/// A raw PDF object as `(serialized_bytes, object_number)`, the unit the
/// incremental-update assembly appends.
pub(crate) type RawObject = (Vec<u8>, u32);

// ── Constants ───────────────────────────────────────────────────────────

/// Bytes reserved for the CMS blob in the `/Contents` placeholder. CoSign's CMS
/// is ~1867 bytes, so 8 KiB leaves ample room.
pub const CMS_RESERVED_SIZE: usize = 8192;
/// Hex-string length of the reserved `/Contents` (two hex chars per byte).
pub const CMS_HEX_SIZE: usize = CMS_RESERVED_SIZE * 2;

/// The `/ByteRange` placeholder written into the unsigned signature dictionary.
///
/// Four zero-valued 10-wide fields, patched in place once the final byte
/// offsets are known. Its length must equal that of the real value so the patch
/// does not shift any offsets -- guarded by a unit test.
pub const BYTERANGE_PLACEHOLDER: &str = "/ByteRange [         0          0          0          0]";

/// PDF annotation flags for a signature widget (`/F`): Print (4) | Locked (128).
/// See PDF Reference 1.7, Table 165.
pub const ANNOT_FLAGS_SIG_WIDGET: u32 = 4 | 128; // 132

// ── PDF literal string escaping ─────────────────────────────────────────

/// Escape text for a PDF literal string (the `(...)` form).
///
/// Handles backslash, parentheses, the common control characters, and other
/// control bytes (as octal escapes). Characters outside Latin-1 are replaced
/// with `?`, since PDFDocEncoding cannot represent them; a warning is logged
/// when that happens, as it means data loss in the output.
#[must_use]
pub fn pdf_string(text: &str) -> String {
    use std::fmt::Write as _;

    let mut result = String::with_capacity(text.len());
    let mut replaced = 0usize;
    for ch in text.chars() {
        let code = ch as u32;
        match ch {
            '\\' => result.push_str("\\\\"),
            '(' => result.push_str("\\("),
            ')' => result.push_str("\\)"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            _ if code < 0x20 || code == 0x7F => {
                // Control byte -> three-digit octal escape.
                let _ = write!(result, "\\{code:03o}");
            }
            _ if code > 0xFF => {
                result.push('?');
                replaced += 1;
            }
            _ => result.push(ch),
        }
    }
    if replaced > 0 {
        log::warn!("pdf_string: {replaced} non-Latin1 character(s) replaced with '?' in: {text:?}");
    }
    result
}

// ── Object-number allocation ────────────────────────────────────────────

/// Object numbers for the embedded Type0/CIDFontType2 font chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FontObjNums {
    pub font: u32,      // Type0 font dict
    pub cidfont: u32,   // CIDFontType2
    pub font_desc: u32, // FontDescriptor
    pub font_file: u32, // FontFile2 stream
    pub tounicode: u32, // ToUnicode CMap stream
}

/// Object numbers for the nested form XObject structure (CoSign-compatible).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FormObjNums {
    pub ap: u32,  // top-level AP/N form ("/FRM Do")
    pub frm: u32, // /FRM intermediate form
    pub n0: u32,  // /n0 empty placeholder
    pub n2: u32,  // /n2 actual visible content
}

/// The appearance-related object numbers, present only for a visible signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VisibleObjNums {
    pub fonts: FontObjNums,
    pub forms: FormObjNums,
    pub img: Option<u32>,
    pub smask: Option<u32>,
}

/// Object numbers allocated for a signature's PDF objects.
///
/// An invisible signature carries `visible: None`, so the type system -- not a
/// runtime check -- guarantees the appearance objects exist exactly when they
/// are used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SigObjectNums {
    pub sig: u32,
    pub annot: u32,
    pub visible: Option<VisibleObjNums>,
    /// The new `/Size` (one past the highest allocated object number).
    pub new_size: u32,
}

impl SigObjectNums {
    /// Allocate object numbers for all new PDF objects.
    ///
    /// For a visible signature, allocates the full CoSign-compatible nested form
    /// structure (AP/N -> /FRM -> /n0 + /n2), the font chain, and optional image
    /// objects. For an invisible signature, only the signature dictionary and
    /// annotation are allocated.
    #[must_use]
    pub fn allocate(prev_size: u32, has_image: bool, has_smask: bool, visible: bool) -> Self {
        /// Return the current object number and advance the counter.
        fn take(next: &mut u32) -> u32 {
            let n = *next;
            *next += 1;
            n
        }

        let mut next = prev_size;

        let sig = take(&mut next);
        let annot = take(&mut next);

        if !visible {
            return Self {
                sig,
                annot,
                visible: None,
                new_size: next,
            };
        }

        let fonts = FontObjNums {
            font: take(&mut next),
            cidfont: take(&mut next),
            font_desc: take(&mut next),
            font_file: take(&mut next),
            tounicode: take(&mut next),
        };
        let forms = FormObjNums {
            ap: take(&mut next),
            frm: take(&mut next),
            n0: take(&mut next),
            n2: take(&mut next),
        };
        let img = has_image.then(|| take(&mut next));
        let smask = (has_image && has_smask).then(|| take(&mut next));

        Self {
            sig,
            annot,
            visible: Some(VisibleObjNums {
                fonts,
                forms,
                img,
                smask,
            }),
            new_size: next,
        }
    }
}

// ── Object override builders ────────────────────────────────────────────

/// Build a raw override of the page object that adds `/Annots`.
///
/// # Errors
///
/// Propagates [`crate::RevenantError::Pdf`] from the reader if the page object
/// cannot be read.
pub fn build_page_override(
    reader: &PdfReader,
    page_obj_num: u32,
    annots_list: &str,
) -> Result<Vec<u8>> {
    reader.object_override(
        page_obj_num,
        "/Annots",
        &format!("  /Annots [{annots_list}]"),
    )
}

/// Zlib-deflate a byte slice at the default compression level.
///
/// Shared by the font-file and xref-stream builders; in-memory compression
/// never fails in practice, but the `io::Result` is surfaced honestly.
///
/// # Errors
///
/// Returns [`RevenantError::Pdf`] if the underlying encoder errors.
pub(super) fn deflate(data: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(data)
        .map_err(|e| RevenantError::Pdf(format!("Deflate compression failed: {e}")))?;
    encoder
        .finish()
        .map_err(|e| RevenantError::Pdf(format!("Deflate compression failed: {e}")))
}

/// Build a raw override of the catalog that adds `/AcroForm`.
///
/// # Errors
///
/// Propagates [`crate::RevenantError::Pdf`] from the reader if the catalog
/// object cannot be read.
pub fn build_catalog_override(
    reader: &PdfReader,
    root_obj_num: u32,
    annot_obj_num: u32,
) -> Result<Vec<u8>> {
    reader.object_override(
        root_obj_num,
        "/AcroForm",
        &format!("  /AcroForm << /Fields [{annot_obj_num} 0 R] /SigFlags 3 >>"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byterange_placeholder_matches_real_value_width() {
        // The real patched value uses four 10-wide right-justified fields.
        let real = format!(
            "/ByteRange [{:>10} {:>10} {:>10} {:>10}]",
            0, 12345, 67890, 111
        );
        assert_eq!(real.len(), BYTERANGE_PLACEHOLDER.len());
        assert_eq!(BYTERANGE_PLACEHOLDER.len(), 56);
        // The placeholder is the same shape with all zeros.
        let zeros = format!("/ByteRange [{:>10} {:>10} {:>10} {:>10}]", 0, 0, 0, 0);
        assert_eq!(zeros, BYTERANGE_PLACEHOLDER);
    }

    #[test]
    fn cms_sizes() {
        assert_eq!(CMS_HEX_SIZE, 16384);
        assert_eq!(ANNOT_FLAGS_SIG_WIDGET, 132);
    }

    #[test]
    fn pdf_string_escapes_specials() {
        assert_eq!(pdf_string("a(b)c\\d"), "a\\(b\\)c\\\\d");
        assert_eq!(pdf_string("line\tbreak"), "line\\tbreak");
        // Control byte -> octal.
        assert_eq!(pdf_string("\u{01}"), "\\001");
    }

    #[test]
    fn pdf_string_replaces_non_latin1() {
        // Armenian letter is > 0xFF -> replaced with '?'.
        assert_eq!(pdf_string("Ա"), "?");
        // Latin-1 accented char is preserved.
        assert_eq!(pdf_string("é"), "é");
    }

    #[test]
    fn allocate_invisible_only_sig_and_annot() {
        let n = SigObjectNums::allocate(10, false, false, false);
        assert_eq!(n.sig, 10);
        assert_eq!(n.annot, 11);
        assert!(n.visible.is_none());
        assert_eq!(n.new_size, 12);
    }

    #[test]
    fn allocate_visible_no_image() {
        let n = SigObjectNums::allocate(10, false, false, true);
        let v = n.visible.expect("visible");
        assert_eq!(n.sig, 10);
        assert_eq!(n.annot, 11);
        assert_eq!(v.fonts.font, 12);
        assert_eq!(v.fonts.tounicode, 16);
        assert_eq!(v.forms.ap, 17);
        assert_eq!(v.forms.n2, 20);
        assert!(v.img.is_none());
        assert!(v.smask.is_none());
        assert_eq!(n.new_size, 21);
    }

    #[test]
    fn allocate_visible_with_image_and_smask() {
        let n = SigObjectNums::allocate(10, true, true, true);
        let v = n.visible.expect("visible");
        assert_eq!(v.img, Some(21));
        assert_eq!(v.smask, Some(22));
        assert_eq!(n.new_size, 23);
    }

    #[test]
    fn allocate_image_without_smask() {
        let n = SigObjectNums::allocate(10, true, false, true);
        let v = n.visible.expect("visible");
        assert_eq!(v.img, Some(21));
        assert!(v.smask.is_none());
        assert_eq!(n.new_size, 22);
    }
}
