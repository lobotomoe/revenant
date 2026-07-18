//! High-level PDF signature-field preparation.
//!
//! Prepares a PDF with an empty signature field via a true incremental update
//! (the original bytes are preserved exactly), computes the SHA-1 ByteRange hash
//! to send to the appliance, and splices the returned CMS into the reserved
//! `/Contents`. Object construction lives in [`super::render`] and
//! [`super::objects`]; structure analysis and assembly in
//! [`super::incremental`].

use sha1::{Digest, Sha1};

use super::incremental::{
    assemble_incremental_update, detect_xref_stream, find_root_obj_num, find_startxref_offset,
    patch_byterange, PreparedPdf, UpdatePlan,
};
use super::objects::{build_catalog_override, build_page_override, RawObject, SigObjectNums};
use super::position::{
    compute_sig_rect, resolve_page_index, PageSpec, Position, SigRect, SIG_HEIGHT, SIG_MARGIN_H,
    SIG_MARGIN_V, SIG_WIDTH,
};
use super::reader::{ObjRef, PageInfo, PdfReader};
use super::render::{
    build_annot_widget, build_embedded_font_objects, build_form_xobjects,
    build_invisible_annot_widget, build_sig_dict,
};
use crate::appearance::{build_appearance_stream, get_font, load_signature_image, make_date_str};
use crate::{Result, RevenantError};

/// SHA-1 digest length in bytes.
const SHA1_LEN: usize = 20;

/// Options for [`prepare_pdf_with_sig_field`].
///
/// Construct from [`PrepareOptions::default`] and override the fields that matter.
#[derive(Debug, Clone)]
pub struct PrepareOptions<'a> {
    /// The page to place the signature on.
    pub page: PageSpec,
    /// The placement preset, used when `manual_xy` is `None`.
    pub position: Position,
    /// Explicit `(x, y)` origin overriding the preset (PDF points, bottom-left).
    pub manual_xy: Option<(f64, f64)>,
    /// Signature field `(width, height)` in PDF points.
    pub size: (f64, f64),
    /// The `/Reason` string.
    pub reason: &'a str,
    /// The signer display name (for `/Name` and the default first field).
    pub name: Option<&'a str>,
    /// Path to a PNG/JPEG signature image.
    pub image_path: Option<&'a str>,
    /// Explicit ordered display strings; defaults to `[name, auto_date]`.
    pub fields: Option<Vec<String>>,
    /// Whether the signature has a visual appearance.
    pub visible: bool,
    /// Font registry key; `None` uses the default font.
    pub font: Option<&'a str>,
}

impl Default for PrepareOptions<'_> {
    fn default() -> Self {
        Self {
            page: PageSpec::Index(0),
            position: Position::BottomRight,
            manual_xy: None,
            size: (SIG_WIDTH, SIG_HEIGHT),
            reason: "",
            name: None,
            image_path: None,
            fields: None,
            visible: true,
            font: None,
        }
    }
}

/// Prepare a PDF with an empty signature field for hash-then-sign.
///
/// # Errors
///
/// Returns [`RevenantError::Pdf`] if the PDF cannot be read, the page or
/// position is invalid, an image cannot be loaded, or assembly fails.
pub fn prepare_pdf_with_sig_field(
    pdf_bytes: &[u8],
    opts: &PrepareOptions<'_>,
) -> Result<PreparedPdf> {
    // Read-only analysis of the original PDF.
    let root = find_root_obj_num(pdf_bytes)?;
    let reader = PdfReader::open(pdf_bytes)?;
    if reader.is_encrypted() {
        return Err(RevenantError::Pdf(
            "PDF is encrypted; encrypted documents cannot be signed with an \
             embedded signature. Remove the password/encryption and try again."
                .to_owned(),
        ));
    }
    let page_index = resolve_page_index(opts.page, reader.page_count())?;
    let page_info = reader.page_info(page_index)?;
    let prev_xref = find_startxref_offset(pdf_bytes)?;
    let prev_size = u32::try_from(reader.size()?)
        .map_err(|_| RevenantError::Pdf("PDF /Size is negative or too large.".to_owned()))?;
    let trailer_extra = reader.trailer_carry_forward();
    let use_xref_stream = detect_xref_stream(pdf_bytes, prev_xref);

    let (raw_objects, new_size) = if opts.visible {
        prepare_visible(&reader, prev_size, root.num, &page_info, opts)?
    } else {
        prepare_invisible(&reader, prev_size, root.num, &page_info, opts)?
    };

    let plan = UpdatePlan {
        raw_objects: &raw_objects,
        new_size,
        prev_xref,
        root,
        trailer_extra: &trailer_extra,
        use_xref_stream,
    };
    let full_pdf = assemble_incremental_update(pdf_bytes, &plan)?;
    patch_byterange(full_pdf, pdf_bytes.len())
}

/// Build every object for a visible signature, in append order.
fn prepare_visible(
    reader: &PdfReader,
    prev_size: u32,
    root_obj_num: u32,
    page_info: &PageInfo,
    opts: &PrepareOptions<'_>,
) -> Result<(Vec<RawObject>, u32)> {
    let font = get_font(opts.font)?;

    let (w, h) = opts.size;
    let rect = match opts.manual_xy {
        Some((x, y)) => {
            // The preset branch validates geometry inside compute_sig_rect; the
            // manual branch must do the same or a non-finite/non-positive size
            // would emit NaN/inf tokens into the appearance stream.
            if !(w > 0.0 && h > 0.0 && [x, y, w, h].iter().all(|v| v.is_finite())) {
                return Err(RevenantError::Pdf(format!(
                    "Invalid manual signature geometry: x={x}, y={y}, w={w}, h={h}"
                )));
            }
            SigRect { x, y, w, h }
        }
        None => compute_sig_rect(
            page_info.width,
            page_info.height,
            opts.position,
            w,
            h,
            SIG_MARGIN_H,
            SIG_MARGIN_V,
        )?,
    };

    // Load the image first so its aspect ratio can drive the layout.
    let img_data = match opts.image_path {
        Some(path) => Some(load_signature_image(path)?),
        None => None,
    };
    let image_aspect = img_data
        .as_ref()
        .and_then(|d| (d.height > 0).then(|| f64::from(d.width) / f64::from(d.height)));

    // Resolve the display fields (default: name + auto date).
    let default_fields;
    let display_fields: &[String] = if let Some(fields) = &opts.fields {
        fields
    } else {
        let name = opts
            .name
            .filter(|n| !n.is_empty())
            .unwrap_or("Digital Signature");
        default_fields = vec![name.to_owned(), format!("Date: {}", make_date_str())];
        &default_fields
    };

    let ap_info = build_appearance_stream(
        rect.w,
        rect.h,
        display_fields,
        opts.image_path.is_some(),
        font,
        image_aspect,
    );

    let has_image = img_data.is_some();
    let has_smask = img_data.as_ref().is_some_and(|d| d.smask.is_some());
    let obj_nums = SigObjectNums::allocate(prev_size, has_image, has_smask, true);
    let Some(v) = obj_nums.visible else {
        return Err(RevenantError::Pdf(
            "Internal error: visible allocation produced no appearance objects.".to_owned(),
        ));
    };

    let sig = build_sig_dict(obj_nums.sig, opts.reason, opts.name);
    let font_objects = build_embedded_font_objects(v.fonts, font)?;
    let forms = build_form_xobjects(&v, rect.w, rect.h, &ap_info, img_data.as_ref());
    let annot = build_annot_widget(
        obj_nums.sig,
        obj_nums.annot,
        v.forms.ap,
        page_info.obj_num,
        rect,
    );

    let annots_list = build_annots_list(&page_info.annots, obj_nums.annot);
    let page_override = build_page_override(reader, page_info.obj_num, &annots_list)?;
    let catalog_override = build_catalog_override(reader, root_obj_num, obj_nums.annot)?;

    let mut objects: Vec<RawObject> = Vec::new();
    objects.push((sig, obj_nums.sig));
    objects.push((annot, obj_nums.annot));
    objects.extend(font_objects);
    objects.push((forms.n0, v.forms.n0));
    objects.push((forms.n2, v.forms.n2));
    objects.push((forms.frm, v.forms.frm));
    objects.push((forms.ap, v.forms.ap));
    if let (Some(bytes), Some(num)) = (forms.img, v.img) {
        objects.push((bytes, num));
    }
    if let (Some(bytes), Some(num)) = (forms.smask, v.smask) {
        objects.push((bytes, num));
    }
    objects.push((page_override, page_info.obj_num));
    objects.push((catalog_override, root_obj_num));

    Ok((objects, obj_nums.new_size))
}

/// Build the objects for an invisible signature (no visual appearance).
fn prepare_invisible(
    reader: &PdfReader,
    prev_size: u32,
    root_obj_num: u32,
    page_info: &PageInfo,
    opts: &PrepareOptions<'_>,
) -> Result<(Vec<RawObject>, u32)> {
    let obj_nums = SigObjectNums::allocate(prev_size, false, false, false);
    let sig = build_sig_dict(obj_nums.sig, opts.reason, opts.name);
    let annot = build_invisible_annot_widget(obj_nums.sig, obj_nums.annot, page_info.obj_num);

    let annots_list = build_annots_list(&page_info.annots, obj_nums.annot);
    let page_override = build_page_override(reader, page_info.obj_num, &annots_list)?;
    let catalog_override = build_catalog_override(reader, root_obj_num, obj_nums.annot)?;

    let objects = vec![
        (sig, obj_nums.sig),
        (annot, obj_nums.annot),
        (page_override, page_info.obj_num),
        (catalog_override, root_obj_num),
    ];
    Ok((objects, obj_nums.new_size))
}

/// Build the `/Annots` array body: existing references plus the new widget.
fn build_annots_list(existing: &[ObjRef], annot_num: u32) -> String {
    use std::fmt::Write as _;

    let mut list = String::new();
    for obj_ref in existing {
        let _ = write!(list, "{obj_ref} ");
    }
    let _ = write!(list, "{annot_num} 0 R");
    list
}

/// Compute the SHA-1 hash of the ByteRange (everything except the Contents hex).
///
/// # Errors
///
/// Returns [`RevenantError::Pdf`] if the hex range is out of bounds or the
/// `/Contents` field is not delimited by `<` and `>`.
pub fn compute_byterange_hash(
    pdf_bytes: &[u8],
    hex_start: usize,
    hex_len: usize,
) -> Result<[u8; SHA1_LEN]> {
    let Some(end) = hex_start.checked_add(hex_len) else {
        return Err(RevenantError::Pdf(format!(
            "Invalid hex range: start={hex_start}, len={hex_len} overflows pdf_size={}",
            pdf_bytes.len()
        )));
    };
    if hex_start == 0 || end >= pdf_bytes.len() {
        return Err(RevenantError::Pdf(format!(
            "Invalid hex range: start={hex_start}, len={hex_len}, pdf_size={}",
            pdf_bytes.len()
        )));
    }
    if pdf_bytes.get(hex_start - 1) != Some(&b'<') {
        return Err(RevenantError::Pdf(
            "Malformed Contents field: expected '<' before hex data".to_owned(),
        ));
    }
    if pdf_bytes.get(end) != Some(&b'>') {
        return Err(RevenantError::Pdf(
            "Malformed Contents field: expected '>' after hex data".to_owned(),
        ));
    }

    let mut hasher = Sha1::new();
    hasher.update(&pdf_bytes[..hex_start]);
    hasher.update(&pdf_bytes[end + 1..]);
    Ok(hasher.finalize().into())
}

/// Insert the CMS DER bytes as a hex string into the reserved `/Contents`.
///
/// # Errors
///
/// Returns [`RevenantError::Pdf`] if the CMS is larger than the reserved field
/// or the reserved region is out of range.
pub fn insert_cms(
    pdf_bytes: &[u8],
    hex_start: usize,
    hex_len: usize,
    cms_der: &[u8],
) -> Result<Vec<u8>> {
    let cms_hex = hex::encode(cms_der);
    if cms_hex.len() > hex_len {
        return Err(RevenantError::Pdf(format!(
            "CMS too large: {} hex chars > {hex_len} reserved",
            cms_hex.len()
        )));
    }

    let end = hex_start
        .checked_add(hex_len)
        .ok_or_else(|| RevenantError::Pdf("Contents region offset overflows.".to_owned()))?;
    let mut out = pdf_bytes.to_vec();
    let region = out
        .get_mut(hex_start..end)
        .ok_or_else(|| RevenantError::Pdf("Contents region is out of range.".to_owned()))?;
    let (filled, padding) = region.split_at_mut(cms_hex.len());
    filled.copy_from_slice(cms_hex.as_bytes());
    padding.fill(b'0');
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cms::{extract_signature_data, find_byteranges};

    const BLANK_LETTER: &[u8] = include_bytes!("testdata/blank_letter.pdf");
    const TWO_PAGE_A4: &[u8] = include_bytes!("testdata/two_page_a4.pdf");
    const XREF_STREAM: &[u8] = include_bytes!("testdata/blank_letter_xref_stream.pdf");
    const ENCRYPTED: &[u8] = include_bytes!("testdata/encrypted.pdf");

    #[test]
    fn rejects_encrypted_pdf() {
        // Encrypted input must fail loud, not silently produce a corrupt signed
        // document (its original content would become unreadable).
        let err = prepare_pdf_with_sig_field(ENCRYPTED, &PrepareOptions::default()).unwrap_err();
        assert!(matches!(err, RevenantError::Pdf(_)));
        assert!(err.to_string().contains("encrypted"));
    }

    /// A well-formed DER SEQUENCE standing in for a CMS blob (203 bytes,
    /// declared length matches actual, above MIN_CMS_SIZE).
    fn fake_cms() -> Vec<u8> {
        let mut der = vec![0x30, 0x81, 0xC8]; // SEQUENCE, long-form length 200
        der.extend(std::iter::repeat_n(0xAB, 200));
        der
    }

    fn sha1(data: &[u8]) -> [u8; 20] {
        let mut hasher = Sha1::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    /// Run the full prepare -> hash -> insert -> extract cycle and assert the
    /// signed byte range and the embedded CMS both round-trip.
    fn assert_round_trip(pdf: &[u8], opts: &PrepareOptions<'_>, expect_pages: usize) {
        let PreparedPdf {
            bytes: prepared,
            contents_hex_offset: hex_start,
            contents_hex_len: hex_len,
        } = prepare_pdf_with_sig_field(pdf, opts).unwrap();

        // The prepared PDF is still structurally valid.
        let reader = PdfReader::open(&prepared).unwrap();
        assert_eq!(reader.page_count(), expect_pages);

        // Exactly one ByteRange, and the reserved field is well-formed.
        assert_eq!(find_byteranges(&prepared).unwrap().len(), 1);
        let hash_before = compute_byterange_hash(&prepared, hex_start, hex_len).unwrap();

        // Splice in the CMS; the byte range is unchanged by this.
        let cms = fake_cms();
        let signed = insert_cms(&prepared, hex_start, hex_len, &cms).unwrap();

        let (signed_data, extracted_cms) = extract_signature_data(&signed).unwrap();
        // The ByteRange hash of the signed PDF matches what we hashed before
        // inserting -- the invariant hash-then-sign depends on.
        assert_eq!(sha1(&signed_data), hash_before);
        // The exact CMS is recovered from the padded placeholder.
        assert_eq!(extracted_cms, cms);
    }

    #[test]
    fn round_trip_visible_letter() {
        let opts = PrepareOptions {
            reason: "Approved",
            name: Some("John Doe"),
            ..Default::default()
        };
        assert_round_trip(BLANK_LETTER, &opts, 1);
    }

    #[test]
    fn round_trip_invisible() {
        let opts = PrepareOptions {
            visible: false,
            reason: "Invisible",
            name: Some("Jane"),
            ..Default::default()
        };
        assert_round_trip(BLANK_LETTER, &opts, 1);
    }

    #[test]
    fn round_trip_xref_stream_source() {
        // Exercises the build_xref_stream path.
        let opts = PrepareOptions {
            name: Some("XRef Stream"),
            ..Default::default()
        };
        assert_round_trip(XREF_STREAM, &opts, 1);
    }

    #[test]
    fn round_trip_last_page_of_two() {
        let opts = PrepareOptions {
            page: PageSpec::Last,
            position: Position::TopLeft,
            name: Some("Page 2"),
            ..Default::default()
        };
        assert_round_trip(TWO_PAGE_A4, &opts, 2);
    }

    #[test]
    fn round_trip_with_explicit_fields_and_font() {
        let opts = PrepareOptions {
            fields: Some(vec!["Ստորագրող".to_owned(), "SSN: 1234567890".to_owned()]),
            font: Some("ghea-mariam"),
            ..Default::default()
        };
        assert_round_trip(BLANK_LETTER, &opts, 1);
    }

    #[test]
    fn build_annots_list_appends() {
        assert_eq!(build_annots_list(&[], 7), "7 0 R");
        assert_eq!(
            build_annots_list(&[ObjRef::new(3, 0), ObjRef::new(4, 0)], 7),
            "3 0 R 4 0 R 7 0 R"
        );
    }

    #[test]
    fn insert_cms_pads_and_rejects_oversize() {
        // 20-char reserved field.
        let pdf = b"<<<<<<<<<<<<<<<<<<<<".to_vec();
        let out = insert_cms(&pdf, 0, 20, &[0xAB, 0xCD]).unwrap();
        // hex::encode produces lowercase, which is what the reader expects.
        assert_eq!(&out[..4], b"abcd");
        assert!(out[4..20].iter().all(|&b| b == b'0'));
        // Oversize CMS is rejected.
        assert!(insert_cms(&pdf, 0, 2, &[0xAB, 0xCD]).is_err());
    }
}
