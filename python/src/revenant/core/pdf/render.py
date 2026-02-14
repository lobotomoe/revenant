"""Low-level PDF object construction for signature fields.

Builds the individual PDF objects that form a signature's visual
appearance: signature dictionary, embedded font chain, nested form
XObjects (CoSign-compatible), annotation widget, and images.

These helpers are called by builder.py's orchestration layer.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from ...constants import __version__
from ...errors import PDFError
from .objects import (
    ANNOT_FLAGS_SIG_WIDGET,
    BYTERANGE_PLACEHOLDER_STR,
    CMS_HEX_SIZE,
    SigObjectNums,
    pdf_string,
)

if TYPE_CHECKING:
    from ..appearance import AppearanceData, SignatureImageData
    from ..appearance.fonts import FontMetrics


def build_sig_dict(obj_num: int, reason: str, name: str | None) -> str:
    """Build the /Type /Sig dictionary object."""

    now = datetime.now(timezone.utc)
    pdf_date = now.strftime("D:%Y%m%d%H%M%S+00'00'")
    contents_zeros = "0" * CMS_HEX_SIZE
    name_entry = f"  /Name ({pdf_string(name)})\n" if name else ""
    prop_build = (
        f"  /Prop_Build << /App << /Name /Revenant /REx ({__version__}) >> "
        f"/Filter << /Name /Adobe.PPKLite >> >>\n"
    )
    return (
        f"{obj_num} 0 obj\n"
        f"<<\n"
        f"  /Type /Sig\n"
        f"  /Filter /Adobe.PPKLite\n"
        f"  /SubFilter /adbe.pkcs7.detached\n"
        f"  {BYTERANGE_PLACEHOLDER_STR}\n"
        f"  /Contents <{contents_zeros}>\n"
        f"  /M ({pdf_date})\n"
        f"  /Reason ({pdf_string(reason)})\n"
        f"{name_entry}"
        f"{prop_build}"
        f">>\n"
        f"endobj\n"
    )


def build_embedded_font_objects(
    obj_nums: SigObjectNums, metrics: FontMetrics
) -> list[tuple[bytes, int]]:
    """Build Type0/CIDFontType2 font objects for the given font.

    Creates the complete PDF font chain:
      Type0 -> CIDFontType2 -> FontDescriptor -> FontFile2 (TTF)
      Type0 -> ToUnicode CMap

    Args:
        obj_nums: Allocated PDF object numbers.
        metrics: Font metrics (name, descriptors, cmap, TTF location).

    Returns:
        List of (raw_bytes, obj_num) tuples for all 5 font objects.
    """
    import importlib.resources
    import zlib

    font_num = obj_nums["font"]
    cidfont_num = obj_nums["cidfont"]
    font_desc_num = obj_nums["font_desc"]
    font_file_num = obj_nums["font_file"]
    tounicode_num = obj_nums["tounicode"]
    if font_num is None or cidfont_num is None:
        raise PDFError("Font object allocation failed: missing font/cidfont numbers")
    if font_desc_num is None or font_file_num is None or tounicode_num is None:
        raise PDFError("Font object allocation failed: missing descriptor/file/tounicode numbers")

    base = metrics.name
    bbox = metrics.bbox
    result: list[tuple[bytes, int]] = []

    # 1. Type0 font dict
    type0_str = (
        f"{font_num} 0 obj\n"
        f"<< /Type /Font /Subtype /Type0\n"
        f"   /BaseFont /{base}\n"
        f"   /Encoding /Identity-H\n"
        f"   /DescendantFonts [{cidfont_num} 0 R]\n"
        f"   /ToUnicode {tounicode_num} 0 R\n"
        f">>\nendobj\n"
    )
    result.append((type0_str.encode("latin-1"), font_num))

    # 2. CIDFontType2 dict
    cidfont_str = (
        f"{cidfont_num} 0 obj\n"
        f"<< /Type /Font /Subtype /CIDFontType2\n"
        f"   /BaseFont /{base}\n"
        f"   /CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >>\n"
        f"   /DW {metrics.default_width}\n"
        f"   /W {metrics.cid_widths_str}\n"
        f"   /FontDescriptor {font_desc_num} 0 R\n"
        f">>\nendobj\n"
    )
    result.append((cidfont_str.encode("latin-1"), cidfont_num))

    # 3. FontDescriptor
    # PDF Reference Table 123: Font flags. Bit 6 (value 32) = Nonsymbolic.
    _FONT_FLAGS_NONSYMBOLIC = 32
    flags = _FONT_FLAGS_NONSYMBOLIC
    font_desc_str = (
        f"{font_desc_num} 0 obj\n"
        f"<< /Type /FontDescriptor\n"
        f"   /FontName /{base}\n"
        f"   /Flags {flags}\n"
        f"   /FontBBox [{bbox[0]} {bbox[1]} {bbox[2]} {bbox[3]}]\n"
        f"   /ItalicAngle {metrics.italic_angle}\n"
        f"   /Ascent {metrics.ascent}\n"
        f"   /Descent {metrics.descent}\n"
        f"   /CapHeight {metrics.cap_height}\n"
        f"   /StemV {metrics.stem_v}\n"
        f"   /FontFile2 {font_file_num} 0 R\n"
        f">>\nendobj\n"
    )
    result.append((font_desc_str.encode("latin-1"), font_desc_num))

    # 4. FontFile2 stream (zlib-compressed TTF)
    ttf_ref = importlib.resources.files(metrics.ttf_package).joinpath(metrics.ttf_resource)
    ttf_bytes = ttf_ref.read_bytes()
    compressed_ttf = zlib.compress(ttf_bytes)
    font_file_header = (
        f"{font_file_num} 0 obj\n"
        f"<< /Length {len(compressed_ttf)} /Length1 {len(ttf_bytes)}"
        f" /Filter /FlateDecode >>\n"
        f"stream\n"
    )
    font_file_raw = font_file_header.encode("latin-1") + compressed_ttf + b"\nendstream\nendobj\n"
    result.append((font_file_raw, font_file_num))

    # 5. ToUnicode CMap stream
    cmap_bytes = metrics.tounicode_cmap.encode("latin-1")
    tounicode_header = f"{tounicode_num} 0 obj\n<< /Length {len(cmap_bytes)} >>\nstream\n"
    tounicode_raw = tounicode_header.encode("latin-1") + cmap_bytes + b"\nendstream\nendobj\n"
    result.append((tounicode_raw, tounicode_num))

    return result


def build_form_xobjects(
    obj_nums: SigObjectNums,
    w: float,
    h: float,
    ap_info: AppearanceData,
    img_data: SignatureImageData | None,
) -> tuple[bytes, bytes, bytes, bytes, bytes, bytes]:
    """Build the nested form XObject structure (CoSign-compatible).

    Returns:
        (n0_raw, n2_raw, frm_raw, ap_raw, img_raw, smask_raw)
    """
    font = obj_nums["font"]
    ap = obj_nums["ap"]
    frm = obj_nums["frm"]
    n0 = obj_nums["n0"]
    n2 = obj_nums["n2"]
    img = obj_nums["img"]
    smask = obj_nums["smask"]
    if font is None or ap is None or frm is None:
        raise PDFError("Form XObject allocation failed: missing font/ap/frm numbers")
    if n0 is None or n2 is None:
        raise PDFError("Form XObject allocation failed: missing n0/n2 numbers")

    n2_stream_bytes = ap_info["stream"]

    # /n0 -- empty placeholder form (required by PDF signature spec)
    n0_stream = b"% DSBlank"
    n0_raw = (
        (
            f"{n0} 0 obj\n"
            f"<< /Type /XObject /Subtype /Form /FormType 1\n"
            f"   /BBox [0 0 100 100]\n"
            f"   /Length {len(n0_stream)}\n"
            f">>\nstream\n"
        ).encode("latin-1")
        + n0_stream
        + b"\nendstream\nendobj\n"
    )

    # /n2 -- actual visible content (border, divider, text, image)
    n2_xobject_entry = ""
    if img_data is not None:
        n2_xobject_entry = f" /XObject << /Img1 {img} 0 R >>"
    bg_opacity = ap_info.get("bg_opacity", 0)
    n2_extgstate_entry = ""
    if bg_opacity > 0:
        n2_extgstate_entry = f" /ExtGState << /GS1 << /ca {bg_opacity:.2f} >> >>"
    n2_dict = (
        f"{n2} 0 obj\n"
        f"<< /Type /XObject /Subtype /Form /FormType 1\n"
        f"   /BBox [0.00 0.00 {w:.2f} {h:.2f}]\n"
        f"   /Resources << /Font << /F1 {font} 0 R >>{n2_xobject_entry}{n2_extgstate_entry} >>\n"
        f"   /Length {len(n2_stream_bytes)}\n"
        f">>\nstream\n"
    )
    n2_raw = n2_dict.encode("latin-1") + n2_stream_bytes + b"\nendstream\nendobj\n"

    # /FRM -- intermediate form, delegates to /n0 and /n2
    frm_stream = b"q 1 0 0 1 0 0 cm /n0 Do Q q 1 0 0 1 0 0 cm /n2 Do Q"
    frm_dict = (
        f"{frm} 0 obj\n"
        f"<< /Type /XObject /Subtype /Form /FormType 1\n"
        f"   /BBox [0.00 0.00 {w:.2f} {h:.2f}]\n"
        f"   /Resources << /XObject << /n0 {n0} 0 R /n2 {n2} 0 R >> >>\n"
        f"   /Length {len(frm_stream)}\n"
        f">>\nstream\n"
    )
    frm_raw = frm_dict.encode("latin-1") + frm_stream + b"\nendstream\nendobj\n"

    # AP/N -- top-level appearance form (just delegates to /FRM)
    ap_stream = b"/FRM Do"
    ap_dict = (
        f"{ap} 0 obj\n"
        f"<< /Type /XObject /Subtype /Form /FormType 1\n"
        f"   /BBox [0.00 0.00 {w:.2f} {h:.2f}]\n"
        f"   /Resources << /XObject << /FRM {frm} 0 R >> >>\n"
        f"   /Length {len(ap_stream)}\n"
        f">>\nstream\n"
    )
    ap_raw = ap_dict.encode("latin-1") + ap_stream + b"\nendstream\nendobj\n"

    # Image objects (if needed)
    img_raw = b""
    smask_raw = b""
    if img_data is not None and img is not None:
        img_raw = _build_image_object(img, img_data, smask)
        smask_bytes = img_data["smask"]
        if smask is not None and smask_bytes is not None:
            smask_raw = _build_smask_object(
                smask, smask_bytes, img_data["width"], img_data["height"], img_data["bpc"]
            )

    return n0_raw, n2_raw, frm_raw, ap_raw, img_raw, smask_raw


def build_annot_widget(
    obj_nums: SigObjectNums,
    page_obj_num: int,
    x: float,
    y: float,
    w: float,
    h: float,
) -> str:
    """Build the annotation widget for the signature field."""
    sig = obj_nums["sig"]
    annot = obj_nums["annot"]
    ap = obj_nums["ap"]
    # /Border [0 0 0] suppresses the default 1pt viewer-drawn border
    # since we draw our own in the /FRM stream.
    return (
        f"{annot} 0 obj\n"
        f"<<\n"
        f"  /Type /Annot\n"
        f"  /Subtype /Widget\n"
        f"  /FT /Sig\n"
        f"  /Rect [{x:.2f} {y:.2f} {x + w:.2f} {y + h:.2f}]\n"
        f"  /V {sig} 0 R\n"
        f"  /T (Signature_{annot})\n"
        f"  /F {ANNOT_FLAGS_SIG_WIDGET}\n"
        f"  /P {page_obj_num} 0 R\n"
        f"  /AP << /N {ap} 0 R >>\n"
        f"  /Border [0 0 0]\n"
        f">>\n"
        f"endobj\n"
    )


def build_invisible_annot_widget(
    obj_nums: SigObjectNums,
    page_obj_num: int,
) -> str:
    """Build an invisible annotation widget (/Rect [0 0 0 0], no /AP).

    The signature is cryptographically present but has no visual
    representation on the page.
    """
    sig = obj_nums["sig"]
    annot = obj_nums["annot"]
    return (
        f"{annot} 0 obj\n"
        f"<<\n"
        f"  /Type /Annot\n"
        f"  /Subtype /Widget\n"
        f"  /FT /Sig\n"
        f"  /Rect [0 0 0 0]\n"
        f"  /V {sig} 0 R\n"
        f"  /T (Signature_{annot})\n"
        f"  /F {ANNOT_FLAGS_SIG_WIDGET}\n"
        f"  /P {page_obj_num} 0 R\n"
        f"  /Border [0 0 0]\n"
        f">>\n"
        f"endobj\n"
    )


def _build_image_object(
    img_obj_num: int, img_data: SignatureImageData, smask_obj_num: int | None
) -> bytes:
    """Build a raw PDF image XObject."""
    smask_ref = ""
    if smask_obj_num is not None:
        smask_ref = f" /SMask {smask_obj_num} 0 R"
    img_dict = (
        f"{img_obj_num} 0 obj\n"
        f"<< /Type /XObject /Subtype /Image\n"
        f"   /Width {img_data['width']} /Height {img_data['height']}\n"
        f"   /ColorSpace /DeviceRGB /BitsPerComponent {img_data['bpc']}\n"
        f"   /Filter /FlateDecode{smask_ref}\n"
        f"   /Length {len(img_data['samples'])}\n"
        f">>\n"
        f"stream\n"
    )
    return img_dict.encode("latin-1") + img_data["samples"] + b"\nendstream\nendobj\n"


def _build_smask_object(
    smask_obj_num: int, smask_data: bytes, width: int, height: int, bpc: int
) -> bytes:
    """Build a raw PDF soft mask image XObject."""
    smask_dict = (
        f"{smask_obj_num} 0 obj\n"
        f"<< /Type /XObject /Subtype /Image\n"
        f"   /Width {width} /Height {height}\n"
        f"   /ColorSpace /DeviceGray /BitsPerComponent {bpc}\n"
        f"   /Filter /FlateDecode\n"
        f"   /Length {len(smask_data)}\n"
        f">>\n"
        f"stream\n"
    )
    return smask_dict.encode("latin-1") + smask_data + b"\nendstream\nendobj\n"
