"""PDF signature field preparation.

High-level API for preparing PDFs with empty signature fields,
computing ByteRange hashes, and inserting CMS containers.

Low-level PDF object building is in objects.py.
Low-level rendering object construction is in render.py.
Position/geometry helpers are in position.py.
Post-sign verification is in verify.py.
"""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

from ...errors import PDFError
from ..appearance import (
    AppearanceData,
    SignatureImageData,
    build_appearance_stream,
    get_font,
    load_signature_image,
    make_date_str,
)
from .incremental import (
    assemble_incremental_update,
    find_page_obj_num,
    find_prev_startxref,
    find_root_obj_num,
    patch_byterange,
)
from .objects import (
    SigObjectNums,
    allocate_sig_objects,
    build_catalog_override,
    build_page_override,
)
from .position import SIG_HEIGHT, SIG_WIDTH, compute_sig_rect
from .render import (
    build_annot_widget,
    build_embedded_font_objects,
    build_form_xobjects,
    build_invisible_annot_widget,
    build_sig_dict,
)

if TYPE_CHECKING:
    from ..appearance.fonts import FontMetrics

# ── Helpers ────────────────────────────────────────────────────────────


def _to_bytes(raw: str | bytes) -> bytes:
    """Convert a raw PDF object (str or bytes) to bytes."""
    return raw if isinstance(raw, bytes) else raw.encode("latin-1")


def prepare_pdf_with_sig_field(
    pdf_bytes: bytes,
    page: int | str = 0,
    x: float | None = None,
    y: float | None = None,
    w: float = SIG_WIDTH,
    h: float = SIG_HEIGHT,
    position: str = "bottom-right",
    reason: str = "Signed with Revenant",
    name: str | None = None,
    image_path: str | None = None,
    fields: list[str] | None = None,
    visible: bool = True,
    font: str | None = None,
) -> tuple[bytes, int, int]:
    """
    Prepare a PDF with an empty signature field for hash-then-sign.

    Uses a TRUE incremental update: the original PDF bytes are preserved
    exactly, and new objects are appended after the original %%EOF.
    This is critical for validators (like e-keng) that verify the original
    file bytes are unchanged.

    Position can be set in two ways:
    - **Preset** (default): use ``position`` name like "bottom-right" or alias "br".
      Coordinates are computed from actual page dimensions.
    - **Manual**: pass explicit ``x`` and ``y`` to override the preset.

    Args:
        pdf_bytes: Raw PDF content.
        page: Page for the signature -- 0-based int, "first", or "last".
        x, y: Manual coordinates (PDF points, origin = bottom-left).
            If None, computed from ``position`` preset.
        w, h: Signature field size in PDF points.
        position: Preset name ("bottom-right", "br", etc.).
            Ignored when x/y are provided explicitly.
        reason: Signature reason string.
        name: Signer display name (used for PDF /Name entry).
        image_path: Optional path to a PNG/JPEG signature image.
        fields: Ordered display strings for the signature appearance.
            If None, defaults to [name, auto_date].
        visible: If False, create an invisible signature (no visual
            appearance on the page, /Rect [0 0 0 0]).
        font: Font registry key (e.g. "noto-sans", "ghea-grapalat").
            If None, uses the default font.

    Returns:
        (pdf_bytes, contents_hex_offset, contents_hex_length)
    """
    # ── Read-only analysis of the original PDF ──────────────────
    root_obj_num, root_gen = find_root_obj_num(pdf_bytes)
    page_obj_num, page_w, page_h, _has_annots, existing_annots = find_page_obj_num(
        pdf_bytes, root_obj_num, page
    )
    prev_xref, prev_size, trailer_extra = find_prev_startxref(pdf_bytes)

    if visible:
        raw_objects, new_size = _prepare_visible(
            pdf_bytes,
            prev_size,
            root_obj_num,
            page_obj_num,
            existing_annots,
            page_w,
            page_h,
            x,
            y,
            w,
            h,
            position,
            reason,
            name,
            image_path,
            fields,
            font,
        )
    else:
        raw_objects, new_size = _prepare_invisible(
            pdf_bytes,
            prev_size,
            root_obj_num,
            page_obj_num,
            existing_annots,
            reason,
            name,
        )

    # ── Assemble incremental update ────────────────────────────
    full_pdf = assemble_incremental_update(
        pdf_bytes=pdf_bytes,
        raw_objects=raw_objects,
        new_size=new_size,
        prev_xref=prev_xref,
        root_obj_num=root_obj_num,
        root_gen=root_gen,
        trailer_extra=trailer_extra,
    )

    # ── Patch the ByteRange and return offsets ─────────────────
    return patch_byterange(full_pdf, len(pdf_bytes))


def _prepare_visible(
    pdf_bytes: bytes,
    prev_size: int,
    root_obj_num: int,
    page_obj_num: int,
    existing_annots: list[str],
    page_w: float,
    page_h: float,
    x: float | None,
    y: float | None,
    w: float,
    h: float,
    position: str,
    reason: str,
    name: str | None,
    image_path: str | None,
    fields: list[str] | None,
    font_key: str | None = None,
) -> tuple[list[tuple[bytes, int]], int]:
    """Build PDF objects for a visible signature."""
    font_obj = get_font(font_key)

    # Resolve signature position
    if x is None or y is None:
        x, y, w, h = compute_sig_rect(page_w, page_h, position, w, h)

    # Load signature image first (need dimensions for aspect-ratio-correct layout)
    img_data = None
    image_aspect = None
    if image_path is not None:
        img_data = load_signature_image(image_path)
        if img_data["height"] > 0:
            image_aspect = img_data["width"] / img_data["height"]

    # Build appearance stream
    display_fields = fields
    if display_fields is None:
        display_fields = [name or "Digital Signature", f"Date: {make_date_str()}"]
    ap_info = build_appearance_stream(
        width=w,
        height=h,
        fields=display_fields,
        has_image=(image_path is not None),
        font=font_obj,
        image_aspect=image_aspect,
    )

    # Allocate new object numbers
    has_image = img_data is not None
    has_smask = has_image and img_data["smask"] is not None
    obj_nums = allocate_sig_objects(prev_size, has_image, has_smask, visible=True)

    raw_objects = _build_all_objects(
        pdf_bytes=pdf_bytes,
        obj_nums=obj_nums,
        root_obj_num=root_obj_num,
        page_obj_num=page_obj_num,
        existing_annots=existing_annots,
        x=x,
        y=y,
        w=w,
        h=h,
        reason=reason,
        name=name,
        ap_info=ap_info,
        img_data=img_data,
        font_metrics=font_obj.metrics,
    )
    return raw_objects, obj_nums["new_size"]


def _prepare_invisible(
    pdf_bytes: bytes,
    prev_size: int,
    root_obj_num: int,
    page_obj_num: int,
    existing_annots: list[str],
    reason: str,
    name: str | None,
) -> tuple[list[tuple[bytes, int]], int]:
    """Build PDF objects for an invisible signature (no visual appearance)."""
    obj_nums = allocate_sig_objects(prev_size, has_image=False, has_smask=False, visible=False)

    sig_dict_raw = build_sig_dict(obj_nums["sig"], reason, name)
    annot_raw = build_invisible_annot_widget(obj_nums, page_obj_num)

    annots_list = " ".join(existing_annots) if existing_annots else ""
    if annots_list:
        annots_list += " "
    annots_list += f"{obj_nums['annot']} 0 R"

    page_override = build_page_override(pdf_bytes, page_obj_num, annots_list)
    catalog_override = build_catalog_override(pdf_bytes, root_obj_num, obj_nums["annot"])

    raw_objects = [
        (_to_bytes(sig_dict_raw), obj_nums["sig"]),
        (_to_bytes(annot_raw), obj_nums["annot"]),
        (_to_bytes(page_override), page_obj_num),
        (_to_bytes(catalog_override), root_obj_num),
    ]
    return raw_objects, obj_nums["new_size"]


def _build_all_objects(
    pdf_bytes: bytes,
    obj_nums: SigObjectNums,
    root_obj_num: int,
    page_obj_num: int,
    existing_annots: list[str],
    x: float,
    y: float,
    w: float,
    h: float,
    reason: str,
    name: str | None,
    ap_info: AppearanceData,
    img_data: SignatureImageData | None,
    font_metrics: FontMetrics | None = None,
) -> list[tuple[bytes, int]]:
    """Build all raw PDF objects for the incremental update.

    Returns:
        List of (raw_bytes, obj_num) tuples in append order.
    """
    if font_metrics is None:
        font_metrics = get_font().metrics
    sig_dict_raw = build_sig_dict(obj_nums["sig"], reason, name)
    font_objects = build_embedded_font_objects(obj_nums, font_metrics)

    n0_raw, n2_raw, frm_raw, ap_raw, img_raw, smask_raw = build_form_xobjects(
        obj_nums, w, h, ap_info, img_data
    )
    annot_raw = build_annot_widget(obj_nums, page_obj_num, x, y, w, h)

    # Updated page object (override with /Annots added)
    annots_list = " ".join(existing_annots) if existing_annots else ""
    if annots_list:
        annots_list += " "
    annots_list += f"{obj_nums['annot']} 0 R"

    page_override = build_page_override(pdf_bytes, page_obj_num, annots_list)
    catalog_override = build_catalog_override(pdf_bytes, root_obj_num, obj_nums["annot"])

    return _collect_objects(
        sig_dict_raw=sig_dict_raw,
        annot_raw=annot_raw,
        font_objects=font_objects,
        n0_raw=n0_raw,
        n2_raw=n2_raw,
        frm_raw=frm_raw,
        ap_raw=ap_raw,
        img_raw=img_raw,
        smask_raw=smask_raw,
        page_override=page_override,
        catalog_override=catalog_override,
        obj_nums=obj_nums,
        page_obj_num=page_obj_num,
        root_obj_num=root_obj_num,
    )


def _collect_objects(
    sig_dict_raw: str,
    annot_raw: str,
    font_objects: list[tuple[bytes, int]],
    n0_raw: bytes,
    n2_raw: bytes,
    frm_raw: bytes,
    ap_raw: bytes,
    img_raw: bytes,
    smask_raw: bytes,
    page_override: str,
    catalog_override: str,
    obj_nums: SigObjectNums,
    page_obj_num: int,
    root_obj_num: int,
) -> list[tuple[bytes, int]]:
    """Collect all raw objects into (bytes, obj_num) tuples in append order."""
    n0_num = obj_nums["n0"]
    n2_num = obj_nums["n2"]
    frm_num = obj_nums["frm"]
    ap_num = obj_nums["ap"]
    if n0_num is None or n2_num is None or frm_num is None or ap_num is None:
        raise PDFError("Visible signature requires n0/n2/frm/ap object numbers, but some are None")

    result: list[tuple[bytes, int]] = []
    result.append((_to_bytes(sig_dict_raw), obj_nums["sig"]))
    result.append((_to_bytes(annot_raw), obj_nums["annot"]))
    result.extend(font_objects)
    result.append((n0_raw, n0_num))
    result.append((n2_raw, n2_num))
    result.append((frm_raw, frm_num))
    result.append((ap_raw, ap_num))
    img_num = obj_nums["img"]
    if img_raw and img_num is not None:
        result.append((img_raw, img_num))
    smask_num = obj_nums["smask"]
    if smask_raw and smask_num is not None:
        result.append((smask_raw, smask_num))
    result.append((_to_bytes(page_override), page_obj_num))
    result.append((_to_bytes(catalog_override), root_obj_num))
    return result


def compute_byterange_hash(pdf_bytes: bytes, hex_start: int, hex_len: int) -> bytes:
    """Compute SHA-1 hash of the ByteRange (everything except the Contents hex)."""
    end = hex_start + hex_len
    if hex_start <= 0 or end + 1 > len(pdf_bytes):
        raise PDFError(
            f"Invalid hex range: start={hex_start}, len={hex_len}, pdf_size={len(pdf_bytes)}"
        )
    if pdf_bytes[hex_start - 1 : hex_start] != b"<":
        raise PDFError("Malformed Contents field: expected '<' before hex data")
    if pdf_bytes[end : end + 1] != b">":
        raise PDFError("Malformed Contents field: expected '>' after hex data")

    before = pdf_bytes[:hex_start]
    after = pdf_bytes[end + 1 :]  # +1 for closing ">"
    h = hashlib.sha1()
    h.update(before)
    h.update(after)
    return h.digest()


def insert_cms(pdf_bytes: bytes, hex_start: int, hex_len: int, cms_der: bytes) -> bytes:
    """Insert the CMS DER bytes as a hex string into the reserved Contents."""
    cms_hex = cms_der.hex()
    if len(cms_hex) > hex_len:
        raise PDFError(f"CMS too large: {len(cms_hex)} hex chars > {hex_len} reserved")
    cms_hex_padded = cms_hex + "0" * (hex_len - len(cms_hex))

    result = bytearray(pdf_bytes)
    result[hex_start : hex_start + hex_len] = cms_hex_padded.encode("ascii")
    return bytes(result)
