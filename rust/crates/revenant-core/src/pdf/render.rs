//! Raw PDF object construction for a signature's visual appearance.
//!
//! Builds the individual objects that make up a signature: the `/Sig`
//! dictionary, the embedded Type0/CIDFontType2 font chain, the nested form
//! XObjects (CoSign-compatible: AP/N -> /FRM -> /n0 + /n2), the annotation
//! widget, and the optional image + soft-mask XObjects. Each is emitted as raw
//! bytes for the incremental update.

use super::objects::pdf_text_string;
use super::objects::{
    deflate, FontObjNums, RawObject, VisibleObjNums, ANNOT_FLAGS_SIG_WIDGET, BYTERANGE_PLACEHOLDER,
    CMS_HEX_SIZE,
};
use super::position::SigRect;
use crate::appearance::{AppearanceData, Font, SignatureImageData};
use crate::constants::VERSION;
use crate::Result;

/// PDF Reference Table 123 font flag: Nonsymbolic (bit 6).
const FONT_FLAGS_NONSYMBOLIC: u32 = 32;

/// Build the `/Type /Sig` dictionary object.
///
/// Reserves the `/Contents` hex placeholder and the `/ByteRange` placeholder,
/// both patched later once the final byte offsets are known.
#[must_use]
pub(crate) fn build_sig_dict(sig_num: u32, reason: &str, name: Option<&str>) -> Vec<u8> {
    let now = chrono::Utc::now();
    let pdf_date = now.format("D:%Y%m%d%H%M%S+00'00'").to_string();
    let contents_zeros = "0".repeat(CMS_HEX_SIZE);
    let name_entry = match name {
        Some(n) if !n.is_empty() => format!("  /Name {}\n", pdf_text_string(n)),
        _ => String::new(),
    };
    let prop_build = format!(
        "  /Prop_Build << /App << /Name /Revenant /REx ({VERSION}) >> \
         /Filter << /Name /Adobe.PPKLite >> >>\n"
    );
    let reason_value = pdf_text_string(reason);
    format!(
        "{sig_num} 0 obj\n<<\n  /Type /Sig\n  /Filter /Adobe.PPKLite\n  \
         /SubFilter /adbe.pkcs7.detached\n  {BYTERANGE_PLACEHOLDER}\n  \
         /Contents <{contents_zeros}>\n  /M ({pdf_date})\n  \
         /Reason {reason_value}\n{name_entry}{prop_build}>>\nendobj\n"
    )
    .into_bytes()
}

/// Build the embedded font chain: Type0 -> CIDFontType2 -> FontDescriptor ->
/// FontFile2 (zlib-compressed TTF), plus a ToUnicode CMap.
///
/// Returns the five `(raw_bytes, obj_num)` pairs in append order.
///
/// # Errors
///
/// Returns [`RevenantError::Pdf`] if compressing the TTF fails.
pub(crate) fn build_embedded_font_objects(
    fonts: FontObjNums,
    font: &Font,
) -> Result<Vec<RawObject>> {
    let base = font.name;
    let (bx0, by0, bx1, by1) = font.bbox;
    let mut result = Vec::with_capacity(5);

    // 1. Type0 font dict.
    let type0 = format!(
        "{} 0 obj\n<< /Type /Font /Subtype /Type0\n   /BaseFont /{base}\n   \
         /Encoding /Identity-H\n   /DescendantFonts [{} 0 R]\n   /ToUnicode {} 0 R\n>>\nendobj\n",
        fonts.font, fonts.cidfont, fonts.tounicode
    );
    result.push((type0.into_bytes(), fonts.font));

    // 2. CIDFontType2 dict.
    let cidfont = format!(
        "{} 0 obj\n<< /Type /Font /Subtype /CIDFontType2\n   /BaseFont /{base}\n   \
         /CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >>\n   \
         /DW {}\n   /W {}\n   /FontDescriptor {} 0 R\n>>\nendobj\n",
        fonts.cidfont, font.default_width, font.cid_widths_str, fonts.font_desc
    );
    result.push((cidfont.into_bytes(), fonts.cidfont));

    // 3. FontDescriptor.
    let font_desc = format!(
        "{} 0 obj\n<< /Type /FontDescriptor\n   /FontName /{base}\n   /Flags {FONT_FLAGS_NONSYMBOLIC}\n   \
         /FontBBox [{bx0} {by0} {bx1} {by1}]\n   /ItalicAngle {}\n   /Ascent {}\n   /Descent {}\n   \
         /CapHeight {}\n   /StemV {}\n   /FontFile2 {} 0 R\n>>\nendobj\n",
        fonts.font_desc,
        font.italic_angle,
        font.ascent,
        font.descent,
        font.cap_height,
        font.stem_v,
        fonts.font_file
    );
    result.push((font_desc.into_bytes(), fonts.font_desc));

    // 4. FontFile2 stream (zlib-compressed TTF).
    let compressed = deflate(font.ttf)?;
    let header = format!(
        "{} 0 obj\n<< /Length {} /Length1 {} /Filter /FlateDecode >>\nstream\n",
        fonts.font_file,
        compressed.len(),
        font.ttf.len()
    );
    let mut font_file = header.into_bytes();
    font_file.extend_from_slice(&compressed);
    font_file.extend_from_slice(b"\nendstream\nendobj\n");
    result.push((font_file, fonts.font_file));

    // 5. ToUnicode CMap stream.
    let cmap_bytes = font.tounicode_cmap.as_bytes();
    let header = format!(
        "{} 0 obj\n<< /Length {} >>\nstream\n",
        fonts.tounicode,
        cmap_bytes.len()
    );
    let mut tounicode = header.into_bytes();
    tounicode.extend_from_slice(cmap_bytes);
    tounicode.extend_from_slice(b"\nendstream\nendobj\n");
    result.push((tounicode, fonts.tounicode));

    Ok(result)
}

/// The nested form XObjects for a visible signature.
#[derive(Debug, Clone)]
pub(crate) struct FormObjects {
    pub n0: Vec<u8>,
    pub n2: Vec<u8>,
    pub frm: Vec<u8>,
    pub ap: Vec<u8>,
    pub img: Option<Vec<u8>>,
    pub smask: Option<Vec<u8>>,
}

/// Build the nested form XObject structure (CoSign-compatible).
#[must_use]
pub(crate) fn build_form_xobjects(
    v: &VisibleObjNums,
    w: f64,
    h: f64,
    ap_info: &AppearanceData,
    img_data: Option<&SignatureImageData>,
) -> FormObjects {
    // /n0 -- empty placeholder form (required by the PDF signature spec).
    let n0_stream = b"% DSBlank";
    let mut n0 = format!(
        "{} 0 obj\n<< /Type /XObject /Subtype /Form /FormType 1\n   /BBox [0 0 100 100]\n   \
         /Length {}\n>>\nstream\n",
        v.forms.n0,
        n0_stream.len()
    )
    .into_bytes();
    n0.extend_from_slice(n0_stream);
    n0.extend_from_slice(b"\nendstream\nendobj\n");

    // /n2 -- the actual visible content (backdrop, border, text, image).
    let n2_xobject_entry = match (img_data, v.img) {
        (Some(_), Some(img_num)) => format!(" /XObject << /Img1 {img_num} 0 R >>"),
        _ => String::new(),
    };
    let n2_extgstate_entry = if ap_info.bg_opacity > 0.0 {
        format!(" /ExtGState << /GS1 << /ca {:.2} >> >>", ap_info.bg_opacity)
    } else {
        String::new()
    };
    let mut n2 = format!(
        "{} 0 obj\n<< /Type /XObject /Subtype /Form /FormType 1\n   /BBox [0.00 0.00 {w:.2} {h:.2}]\n   \
         /Resources << /Font << /F1 {} 0 R >>{n2_xobject_entry}{n2_extgstate_entry} >>\n   \
         /Length {}\n>>\nstream\n",
        v.forms.n2,
        v.fonts.font,
        ap_info.stream.len()
    )
    .into_bytes();
    n2.extend_from_slice(&ap_info.stream);
    n2.extend_from_slice(b"\nendstream\nendobj\n");

    // /FRM -- intermediate form delegating to /n0 and /n2.
    let frm_stream = b"q 1 0 0 1 0 0 cm /n0 Do Q q 1 0 0 1 0 0 cm /n2 Do Q";
    let mut frm = format!(
        "{} 0 obj\n<< /Type /XObject /Subtype /Form /FormType 1\n   /BBox [0.00 0.00 {w:.2} {h:.2}]\n   \
         /Resources << /XObject << /n0 {} 0 R /n2 {} 0 R >> >>\n   /Length {}\n>>\nstream\n",
        v.forms.frm,
        v.forms.n0,
        v.forms.n2,
        frm_stream.len()
    )
    .into_bytes();
    frm.extend_from_slice(frm_stream);
    frm.extend_from_slice(b"\nendstream\nendobj\n");

    // AP/N -- top-level appearance form delegating to /FRM.
    let ap_stream = b"/FRM Do";
    let mut ap = format!(
        "{} 0 obj\n<< /Type /XObject /Subtype /Form /FormType 1\n   /BBox [0.00 0.00 {w:.2} {h:.2}]\n   \
         /Resources << /XObject << /FRM {} 0 R >> >>\n   /Length {}\n>>\nstream\n",
        v.forms.ap,
        v.forms.frm,
        ap_stream.len()
    )
    .into_bytes();
    ap.extend_from_slice(ap_stream);
    ap.extend_from_slice(b"\nendstream\nendobj\n");

    // Image + soft-mask objects (if present).
    let (img, smask) = match (img_data, v.img) {
        (Some(data), Some(img_num)) => {
            let img_obj = build_image_object(img_num, data, v.smask);
            let smask_obj = match (v.smask, &data.smask) {
                (Some(smask_num), Some(smask_bytes)) => Some(build_smask_object(
                    smask_num,
                    smask_bytes,
                    data.width,
                    data.height,
                    data.bpc,
                )),
                _ => None,
            };
            (Some(img_obj), smask_obj)
        }
        _ => (None, None),
    };

    FormObjects {
        n0,
        n2,
        frm,
        ap,
        img,
        smask,
    }
}

/// Build the annotation widget for a visible signature field.
///
/// `/Border [0 0 0]` suppresses the viewer's default 1pt border, since the
/// border is drawn in the `/FRM` stream instead.
#[must_use]
pub(crate) fn build_annot_widget(
    sig_num: u32,
    annot_num: u32,
    ap_num: u32,
    page_obj_num: u32,
    rect: SigRect,
) -> Vec<u8> {
    format!(
        "{annot_num} 0 obj\n<<\n  /Type /Annot\n  /Subtype /Widget\n  /FT /Sig\n  \
         /Rect [{:.2} {:.2} {:.2} {:.2}]\n  /V {sig_num} 0 R\n  /T (Signature_{annot_num})\n  \
         /F {ANNOT_FLAGS_SIG_WIDGET}\n  /P {page_obj_num} 0 R\n  /AP << /N {ap_num} 0 R >>\n  \
         /Border [0 0 0]\n>>\nendobj\n",
        rect.x,
        rect.y,
        rect.x + rect.w,
        rect.y + rect.h,
    )
    .into_bytes()
}

/// Build an invisible annotation widget (`/Rect [0 0 0 0]`, no `/AP`).
#[must_use]
pub(crate) fn build_invisible_annot_widget(
    sig_num: u32,
    annot_num: u32,
    page_obj_num: u32,
) -> Vec<u8> {
    format!(
        "{annot_num} 0 obj\n<<\n  /Type /Annot\n  /Subtype /Widget\n  /FT /Sig\n  \
         /Rect [0 0 0 0]\n  /V {sig_num} 0 R\n  /T (Signature_{annot_num})\n  \
         /F {ANNOT_FLAGS_SIG_WIDGET}\n  /P {page_obj_num} 0 R\n  /Border [0 0 0]\n>>\nendobj\n"
    )
    .into_bytes()
}

/// Build a raw image XObject (DeviceRGB, FlateDecode).
fn build_image_object(
    img_num: u32,
    img_data: &SignatureImageData,
    smask_num: Option<u32>,
) -> Vec<u8> {
    let smask_ref = smask_num.map_or_else(String::new, |n| format!(" /SMask {n} 0 R"));
    let mut out = format!(
        "{img_num} 0 obj\n<< /Type /XObject /Subtype /Image\n   /Width {} /Height {}\n   \
         /ColorSpace /DeviceRGB /BitsPerComponent {}\n   /Filter /FlateDecode{smask_ref}\n   \
         /Length {}\n>>\nstream\n",
        img_data.width,
        img_data.height,
        img_data.bpc,
        img_data.samples.len()
    )
    .into_bytes();
    out.extend_from_slice(&img_data.samples);
    out.extend_from_slice(b"\nendstream\nendobj\n");
    out
}

/// Build a raw soft-mask image XObject (DeviceGray, FlateDecode).
fn build_smask_object(
    smask_num: u32,
    smask_data: &[u8],
    width: u32,
    height: u32,
    bpc: u8,
) -> Vec<u8> {
    let mut out = format!(
        "{smask_num} 0 obj\n<< /Type /XObject /Subtype /Image\n   /Width {width} /Height {height}\n   \
         /ColorSpace /DeviceGray /BitsPerComponent {bpc}\n   /Filter /FlateDecode\n   \
         /Length {}\n>>\nstream\n",
        smask_data.len()
    )
    .into_bytes();
    out.extend_from_slice(smask_data);
    out.extend_from_slice(b"\nendstream\nendobj\n");
    out
}

#[cfg(test)]
mod tests {
    use super::super::objects::SigObjectNums;
    use super::*;
    use crate::appearance::{build_appearance_stream, get_default_font};

    #[test]
    fn sig_dict_has_required_entries() {
        let raw = build_sig_dict(5, "I approve", Some("John Doe"));
        let s = String::from_utf8(raw).unwrap();
        assert!(s.starts_with("5 0 obj\n"), "{s}");
        assert!(s.contains("/Type /Sig"), "{s}");
        assert!(s.contains("/SubFilter /adbe.pkcs7.detached"), "{s}");
        assert!(s.contains("/ByteRange ["), "{s}");
        assert!(s.contains("/Contents <"), "{s}");
        assert!(s.contains("/Reason (I approve)"), "{s}");
        assert!(s.contains("/Name (John Doe)"), "{s}");
        assert!(s.contains("/Prop_Build"), "{s}");
        assert!(
            s.contains(&"0".repeat(CMS_HEX_SIZE)),
            "contents placeholder wrong size"
        );
    }

    #[test]
    fn sig_dict_omits_name_when_absent() {
        let s = String::from_utf8(build_sig_dict(5, "", None)).unwrap();
        assert!(!s.contains("/Name ("), "{s}");
    }

    #[test]
    fn sig_dict_encodes_armenian_name_and_reason_as_utf16() {
        // Non-ASCII must be UTF-16BE hex strings, never flattened to '?'.
        let s = String::from_utf8(build_sig_dict(5, "Հաստատված", Some("Բարեւ Ձեզ"))).unwrap();
        assert!(s.contains("/Name <FEFF"), "{s}");
        assert!(s.contains("/Reason <FEFF"), "{s}");
        assert!(!s.contains('?'), "{s}");
    }

    #[test]
    fn font_objects_build_full_chain() {
        let nums = SigObjectNums::allocate(10, false, false, true)
            .visible
            .unwrap();
        let objs = build_embedded_font_objects(nums.fonts, get_default_font()).unwrap();
        assert_eq!(objs.len(), 5);
        let type0 = String::from_utf8(objs[0].0.clone()).unwrap();
        assert!(type0.contains("/Subtype /Type0"), "{type0}");
        assert!(type0.contains("/Encoding /Identity-H"), "{type0}");
        let font_file = String::from_utf8_lossy(&objs[3].0);
        assert!(font_file.contains("/Length1 "), "{font_file}");
        assert!(font_file.contains("/Filter /FlateDecode"), "{font_file}");
    }

    #[test]
    fn form_xobjects_without_image() {
        let nums = SigObjectNums::allocate(10, false, false, true)
            .visible
            .unwrap();
        let ap = build_appearance_stream(
            210.0,
            70.0,
            &["John".to_owned()],
            false,
            get_default_font(),
            None,
        );
        let forms = build_form_xobjects(&nums, 210.0, 70.0, &ap, None);
        assert!(forms.img.is_none());
        assert!(forms.smask.is_none());
        let n2 = String::from_utf8_lossy(&forms.n2);
        assert!(n2.contains("/Font << /F1 "), "{n2}");
        assert!(!n2.contains("/Img1"), "{n2}");
        let frm = String::from_utf8_lossy(&forms.frm);
        assert!(frm.contains("/n0 Do"), "{frm}");
        assert!(frm.contains("/n2 Do"), "{frm}");
    }

    #[test]
    fn annot_widget_carries_rect_and_refs() {
        let rect = SigRect {
            x: 100.0,
            y: 50.0,
            w: 210.0,
            h: 70.0,
        };
        let s = String::from_utf8(build_annot_widget(5, 6, 15, 3, rect)).unwrap();
        assert!(s.contains("/Rect [100.00 50.00 310.00 120.00]"), "{s}");
        assert!(s.contains("/V 5 0 R"), "{s}");
        assert!(s.contains("/AP << /N 15 0 R >>"), "{s}");
        assert!(s.contains("/P 3 0 R"), "{s}");
    }

    #[test]
    fn invisible_widget_has_zero_rect_and_no_ap() {
        let s = String::from_utf8(build_invisible_annot_widget(5, 6, 3)).unwrap();
        assert!(s.contains("/Rect [0 0 0 0]"), "{s}");
        assert!(!s.contains("/AP"), "{s}");
    }
}
