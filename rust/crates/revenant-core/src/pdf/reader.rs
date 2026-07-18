//! Read-only PDF structure access, backed by `lopdf`.
//!
//! Opens a PDF purely to read structure -- page object numbers and dimensions,
//! the trailer `/Size`, `/Info` and `/ID` carry-forward entries, and per-object
//! entry enumeration for building page/catalog overrides. It never writes; the
//! actual signed output is assembled as raw bytes in [`super::incremental`].
//!
//! All `lopdf` types are contained here so the rest of the `pdf` module depends
//! on plain data (numbers, strings, [`PageInfo`]) rather than a specific PDF
//! library -- if the backing library ever changes, only this file moves.

use lopdf::{Dictionary, Document, Object, ObjectId};

use crate::{Result, RevenantError};

/// Maximum `/Parent` walk depth when resolving inherited page attributes.
/// A page tree deeper than this is almost certainly malformed or cyclic.
const MAX_PARENT_DEPTH: usize = 64;

/// An indirect-object reference: object number and generation. Displays as the
/// PDF `"N G R"` reference syntax.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjRef {
    pub num: u32,
    pub gen: u16,
}

impl ObjRef {
    /// Construct a reference from an object number and generation.
    #[must_use]
    pub fn new(num: u32, gen: u16) -> Self {
        Self { num, gen }
    }
}

impl std::fmt::Display for ObjRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {} R", self.num, self.gen)
    }
}

/// Structural facts about one page needed to place a signature.
#[derive(Debug, Clone, PartialEq)]
pub struct PageInfo {
    /// The page object's number (generation is assumed 0).
    pub obj_num: u32,
    /// Effective page width in PDF points (CropBox over MediaBox, rotation-aware).
    pub width: f64,
    /// Effective page height in PDF points.
    pub height: f64,
    /// Existing `/Annots` references, in order.
    pub annots: Vec<ObjRef>,
}

/// An opened PDF, queried for the structure a signature update needs.
#[derive(Debug)]
pub struct PdfReader {
    doc: Document,
}

impl PdfReader {
    /// Parse a PDF from memory.
    ///
    /// # Errors
    ///
    /// Returns [`RevenantError::Pdf`] if the bytes are not a parseable PDF.
    pub fn open(pdf_bytes: &[u8]) -> Result<Self> {
        let doc = Document::load_mem(pdf_bytes)
            .map_err(|e| RevenantError::Pdf(format!("Cannot parse PDF: {e}")))?;
        Ok(Self { doc })
    }

    /// Number of pages in the document.
    #[must_use]
    pub fn page_count(&self) -> usize {
        self.doc.get_pages().len()
    }

    /// Whether the PDF declares document encryption (`/Encrypt` in the trailer).
    ///
    /// An encrypted source cannot receive a correct incremental-update
    /// signature: the appended objects would have to be encrypted with the
    /// document key and the `/Encrypt` reference carried into the new trailer.
    /// Signing one regardless yields a structurally inconsistent file whose
    /// original content is unreadable, so the embedded-signing path rejects it
    /// up front (fail-loud) rather than emitting a corrupt "signed" document.
    ///
    /// Two lopdf signals are combined because either alone is insufficient:
    /// `is_encrypted()` reports a trailer that still carries `/Encrypt` (a
    /// document lopdf did not decrypt -- e.g. a non-empty user password);
    /// `was_encrypted()` reports one lopdf transparently decrypted on load (the
    /// common empty-user-password case), which strips `/Encrypt` from the
    /// in-memory trailer. A trailer check alone would wrongly pass the latter and
    /// append plaintext objects onto still-encrypted original bytes.
    #[must_use]
    pub fn is_encrypted(&self) -> bool {
        self.doc.is_encrypted() || self.doc.was_encrypted()
    }

    /// The `/Size` value from the trailer (highest object number + 1).
    ///
    /// Uses `lopdf`, which resolves cross-reference streams, incremental
    /// updates, and hybrid-reference files -- a plain regex over the bytes
    /// fails when a large xref-stream `/Size` is followed by a smaller
    /// traditional trailer.
    ///
    /// # Errors
    ///
    /// Returns [`RevenantError::Pdf`] if `/Size` is missing or not an integer.
    pub fn size(&self) -> Result<i64> {
        self.doc
            .trailer
            .get(b"Size")
            .and_then(Object::as_i64)
            .map_err(|e| {
                RevenantError::Pdf(format!("Cannot determine /Size from PDF trailer: {e}"))
            })
    }

    /// Trailer entries to carry forward into the incremental update's trailer
    /// (`/Info` and `/ID`), each as a raw `"  /Key value"` line.
    ///
    /// Per ISO 32000-1 S7.5.6 an incremental trailer must repeat the previous
    /// trailer's entries (except `/Prev` and `/Size`, which are updated). This
    /// reads `lopdf`'s resolved trailer uniformly, which is correct for both
    /// traditional and cross-reference-stream trailers.
    #[must_use]
    pub fn trailer_carry_forward(&self) -> Vec<String> {
        let mut out = Vec::new();
        if let Ok(Object::Reference(id)) = self.doc.trailer.get(b"Info") {
            out.push(format!("/Info {} {} R", id.0, id.1));
        }
        if let Ok(id_obj) = self.doc.trailer.get(b"ID") {
            let mut buf = Vec::new();
            write_object(id_obj, &mut buf);
            out.push(format!("/ID {}", String::from_utf8_lossy(&buf)));
        }
        out
    }

    /// Read structural facts about the page at a 0-based index.
    ///
    /// # Errors
    ///
    /// Returns [`RevenantError::Pdf`] if the index is out of range, the page or
    /// its box cannot be read, or an existing annotation is not an indirect
    /// reference.
    pub fn page_info(&self, page_index: usize) -> Result<PageInfo> {
        let pages = self.doc.get_pages();
        // get_pages() is keyed 1-based.
        let page_number = u32::try_from(page_index)
            .ok()
            .and_then(|i| i.checked_add(1))
            .ok_or_else(|| RevenantError::Pdf(format!("Page index {page_index} too large")))?;
        let page_id = *pages.get(&page_number).ok_or_else(|| {
            RevenantError::Pdf(format!(
                "Page {page_index} out of range (PDF has {} page(s), 0-based).",
                pages.len()
            ))
        })?;

        let (width, height) = self.page_dimensions(page_id)?;
        let annots = self.page_annots(page_id)?;

        Ok(PageInfo {
            obj_num: page_id.0,
            width,
            height,
            annots,
        })
    }

    /// Effective (width, height): CropBox if present else MediaBox, with the
    /// page's `/Rotate` (90/270 swap) applied.
    fn page_dimensions(&self, page_id: ObjectId) -> Result<(f64, f64)> {
        let box_obj = self
            .get_inherited(page_id, b"CropBox")
            .or_else(|| self.get_inherited(page_id, b"MediaBox"))
            .ok_or_else(|| {
                RevenantError::Pdf(format!("Page {} has no MediaBox or CropBox", page_id.0))
            })?;

        let [x0, y0, x1, y1] = self.array_f64_4(box_obj)?;
        let mut w = (x1 - x0).abs();
        let mut h = (y1 - y0).abs();

        if let Some(rotate_obj) = self.get_inherited(page_id, b"Rotate") {
            let rotate = rotate_obj.as_i64().unwrap_or(0).rem_euclid(360);
            if rotate == 90 || rotate == 270 {
                std::mem::swap(&mut w, &mut h);
            }
        }
        Ok((w, h))
    }

    /// Existing `/Annots` references on a page, in order.
    fn page_annots(&self, page_id: ObjectId) -> Result<Vec<ObjRef>> {
        let page = self
            .doc
            .get_dictionary(page_id)
            .map_err(|e| RevenantError::Pdf(format!("Cannot read page object: {e}")))?;
        let Ok(annots_obj) = page.get(b"Annots") else {
            return Ok(Vec::new());
        };
        // /Annots may itself be an indirect reference to the array.
        let annots_obj = self.deref(annots_obj);
        let Ok(array) = annots_obj.as_array() else {
            return Ok(Vec::new());
        };

        let mut refs = Vec::with_capacity(array.len());
        for elem in array {
            let id = elem.as_reference().map_err(|_| {
                RevenantError::Pdf(
                    "Existing annotation is inline, not an indirect reference; \
                     cannot carry it forward."
                        .to_owned(),
                )
            })?;
            refs.push(ObjRef::new(id.0, id.1));
        }
        Ok(refs)
    }

    /// Build a raw override of a PDF object with one entry replaced/added.
    ///
    /// Enumerates every entry of object `obj_num` (generation 0), skipping
    /// `skip_key`, re-serializes each value, appends `new_entry`, and returns
    /// the complete `N 0 obj ... endobj` definition as bytes. Indirect
    /// references are preserved as references (not inlined); this is valid PDF
    /// and avoids duplicating the referenced objects into the override.
    ///
    /// # Errors
    ///
    /// Returns [`RevenantError::Pdf`] if the object is missing or is not a
    /// dictionary.
    pub fn object_override(
        &self,
        obj_num: u32,
        skip_key: &str,
        new_entry: &str,
    ) -> Result<Vec<u8>> {
        let obj = self
            .doc
            .get_object((obj_num, 0))
            .map_err(|e| RevenantError::Pdf(format!("Cannot read object {obj_num}: {e}")))?;
        let dict = obj.as_dict().map_err(|e| {
            RevenantError::Pdf(format!("Object {obj_num} is not a dictionary: {e}"))
        })?;

        let skip = skip_key.strip_prefix('/').unwrap_or(skip_key).as_bytes();

        let mut out = Vec::new();
        out.extend_from_slice(format!("{obj_num} 0 obj\n<<\n").as_bytes());
        for (key, value) in dict {
            if key.as_slice() == skip {
                continue;
            }
            out.extend_from_slice(b"  ");
            write_name(key, &mut out);
            out.push(b' ');
            write_object(value, &mut out);
            out.push(b'\n');
        }
        out.extend_from_slice(new_entry.as_bytes());
        out.push(b'\n');
        out.extend_from_slice(b">>\nendobj\n");
        Ok(out)
    }

    /// Resolve `key` on `start`, walking `/Parent` for inheritable page
    /// attributes (MediaBox/CropBox/Rotate), depth-capped against cycles.
    fn get_inherited(&self, start: ObjectId, key: &[u8]) -> Option<&Object> {
        let mut current = start;
        for _ in 0..MAX_PARENT_DEPTH {
            let dict = self.doc.get_dictionary(current).ok()?;
            if let Ok(value) = dict.get(key) {
                return Some(self.deref(value));
            }
            let parent = dict.get(b"Parent").ok()?;
            current = parent.as_reference().ok()?;
        }
        None
    }

    /// Resolve an object one level if it is an indirect reference; otherwise
    /// return it unchanged.
    fn deref<'a>(&'a self, obj: &'a Object) -> &'a Object {
        self.doc
            .dereference(obj)
            .map_or(obj, |(_, resolved)| resolved)
    }

    /// Read a 4-number array (a rectangle), resolving any element references.
    fn array_f64_4(&self, obj: &Object) -> Result<[f64; 4]> {
        let array = self
            .deref(obj)
            .as_array()
            .map_err(|e| RevenantError::Pdf(format!("Page box is not an array: {e}")))?;
        if array.len() < 4 {
            return Err(RevenantError::Pdf(format!(
                "Page box has {} elements, expected 4",
                array.len()
            )));
        }
        let mut out = [0.0f64; 4];
        for (slot, elem) in out.iter_mut().zip(array.iter()) {
            *slot =
                f64::from(self.deref(elem).as_float().map_err(|e| {
                    RevenantError::Pdf(format!("Page box value is not numeric: {e}"))
                })?);
        }
        Ok(out)
    }
}

// ── Minimal PDF object serialization ────────────────────────────────────
//
// lopdf's own writer is a private module, so we serialize the handful of
// object shapes that appear as page/catalog entries ourselves. References are
// emitted as references; this is the intended, reference-preserving behavior.

/// Serialize a PDF name (`/Key`), escaping delimiter and non-printable bytes as
/// `#XX`, matching the PDF name-encoding rules.
fn write_name(name: &[u8], out: &mut Vec<u8>) {
    out.push(b'/');
    for &byte in name {
        if is_name_special(byte) {
            out.extend_from_slice(format!("#{byte:02X}").as_bytes());
        } else {
            out.push(byte);
        }
    }
}

fn is_name_special(byte: u8) -> bool {
    b" \t\n\r\x0C()<>[]{}/%#".contains(&byte) || !(33..=126).contains(&byte)
}

/// Serialize a single PDF object value to bytes.
fn write_object(obj: &Object, out: &mut Vec<u8>) {
    match obj {
        Object::Null => out.extend_from_slice(b"null"),
        Object::Boolean(true) => out.extend_from_slice(b"true"),
        Object::Boolean(false) => out.extend_from_slice(b"false"),
        Object::Integer(value) => out.extend_from_slice(value.to_string().as_bytes()),
        Object::Real(value) => out.extend_from_slice(format_real(*value).as_bytes()),
        Object::Name(name) => write_name(name, out),
        Object::String(text, format) => write_string(text, *format, out),
        Object::Array(array) => write_array(array, out),
        Object::Dictionary(dict) => write_dictionary(dict, out),
        Object::Reference(id) => out.extend_from_slice(format!("{} {} R", id.0, id.1).as_bytes()),
        // Streams are always indirect objects, so a stream never appears as an
        // inline entry value; if one somehow does, emit its dictionary.
        Object::Stream(stream) => write_dictionary(&stream.dict, out),
    }
}

/// Format a real number as a valid PDF number (Rust's float `Display` omits a
/// trailing `.0`, so whole values render as integers).
fn format_real(value: f32) -> String {
    format!("{value}")
}

fn write_string(text: &[u8], format: lopdf::StringFormat, out: &mut Vec<u8>) {
    match format {
        lopdf::StringFormat::Literal => {
            out.push(b'(');
            for &byte in text {
                if matches!(byte, b'(' | b')' | b'\\' | b'\r') {
                    out.push(b'\\');
                }
                out.push(byte);
            }
            out.push(b')');
        }
        lopdf::StringFormat::Hexadecimal => {
            out.push(b'<');
            for &byte in text {
                out.extend_from_slice(format!("{byte:02X}").as_bytes());
            }
            out.push(b'>');
        }
    }
}

fn write_array(array: &[Object], out: &mut Vec<u8>) {
    out.push(b'[');
    for (i, elem) in array.iter().enumerate() {
        if i > 0 {
            out.push(b' ');
        }
        write_object(elem, out);
    }
    out.push(b']');
}

fn write_dictionary(dict: &Dictionary, out: &mut Vec<u8>) {
    out.extend_from_slice(b"<< ");
    for (key, value) in dict {
        write_name(key, out);
        out.push(b' ');
        write_object(value, out);
        out.push(b' ');
    }
    out.extend_from_slice(b">>");
}

#[cfg(test)]
mod tests {
    use super::*;

    const BLANK_LETTER: &[u8] = include_bytes!("testdata/blank_letter.pdf");
    const TWO_PAGE_A4: &[u8] = include_bytes!("testdata/two_page_a4.pdf");
    const XREF_STREAM: &[u8] = include_bytes!("testdata/blank_letter_xref_stream.pdf");
    const ENCRYPTED: &[u8] = include_bytes!("testdata/encrypted.pdf");
    // AES-256 with an empty user password: lopdf decrypts it transparently on
    // load and strips /Encrypt from the in-memory trailer, so a trailer-only
    // check would miss it. `was_encrypted()` is what catches this case.
    const ENCRYPTED_EMPTY_PW: &[u8] = include_bytes!("testdata/encrypted_empty_password.pdf");

    #[test]
    fn detects_encryption() {
        // An encrypted PDF whose trailer still carries /Encrypt must be flagged:
        // signing it would silently corrupt the document.
        let r = PdfReader::open(ENCRYPTED).unwrap();
        assert!(r.is_encrypted());
        // A plain PDF is not flagged.
        assert!(!PdfReader::open(BLANK_LETTER).unwrap().is_encrypted());
    }

    #[test]
    fn detects_empty_password_encryption() {
        // Regression: an empty-user-password document is decrypted on load, which
        // clears /Encrypt from the in-memory trailer. A trailer-only guard would
        // wrongly pass it and the signer would append plaintext objects onto
        // still-encrypted bytes, producing a file no reader can open. The guard
        // must still reject it (via was_encrypted()).
        let r = PdfReader::open(ENCRYPTED_EMPTY_PW).unwrap();
        assert!(r.is_encrypted());
    }

    #[test]
    fn reads_single_letter_page() {
        let r = PdfReader::open(BLANK_LETTER).unwrap();
        assert_eq!(r.page_count(), 1);
        let info = r.page_info(0).unwrap();
        assert!((info.width - 612.0).abs() < 1e-6, "width {}", info.width);
        assert!((info.height - 792.0).abs() < 1e-6, "height {}", info.height);
        assert!(info.annots.is_empty());
        assert!(info.obj_num > 0);
    }

    #[test]
    fn reads_two_a4_pages() {
        let r = PdfReader::open(TWO_PAGE_A4).unwrap();
        assert_eq!(r.page_count(), 2);
        let p1 = r.page_info(0).unwrap();
        let p2 = r.page_info(1).unwrap();
        assert!((p1.width - 595.0).abs() < 1e-6);
        assert!((p1.height - 842.0).abs() < 1e-6);
        assert!((p2.height - 842.0).abs() < 1e-6);
        assert_ne!(p1.obj_num, p2.obj_num);
    }

    #[test]
    fn out_of_range_page_errors() {
        let r = PdfReader::open(BLANK_LETTER).unwrap();
        assert!(r.page_info(1).is_err());
    }

    #[test]
    fn size_matches_object_count() {
        let r = PdfReader::open(BLANK_LETTER).unwrap();
        // A blank single-page PDF has at least catalog + pages + page.
        assert!(r.size().unwrap() >= 4);
    }

    #[test]
    fn xref_stream_pdf_reads() {
        let r = PdfReader::open(XREF_STREAM).unwrap();
        assert_eq!(r.page_count(), 1);
        let info = r.page_info(0).unwrap();
        assert!((info.width - 612.0).abs() < 1e-6);
        assert!(r.size().unwrap() >= 4);
    }

    #[test]
    fn object_override_preserves_entries_and_appends() {
        let r = PdfReader::open(BLANK_LETTER).unwrap();
        let page_num = r.page_info(0).unwrap().obj_num;
        let raw = r
            .object_override(page_num, "/Annots", "  /Annots [99 0 R]")
            .unwrap();
        let text = String::from_utf8_lossy(&raw);
        assert!(
            text.starts_with(&format!("{page_num} 0 obj\n<<\n")),
            "{text}"
        );
        assert!(text.contains("/Type /Page"), "{text}");
        assert!(text.contains("/MediaBox"), "{text}");
        assert!(text.contains("/Annots [99 0 R]"), "{text}");
        assert!(text.ends_with(">>\nendobj\n"), "{text}");
    }

    #[test]
    fn object_override_skips_named_key() {
        let r = PdfReader::open(BLANK_LETTER).unwrap();
        let page_num = r.page_info(0).unwrap().obj_num;
        // /Type exists on the page; skipping it must drop it from the output.
        let raw = r.object_override(page_num, "/Type", "  /Extra 1").unwrap();
        let text = String::from_utf8_lossy(&raw);
        assert!(!text.contains("/Type /Page"), "{text}");
        assert!(text.contains("/Extra 1"), "{text}");
    }
}
