"""Low-level PDF object construction.

Types, constants, and helpers for building PDF objects used in
signature incremental updates: signature dictionaries, annotation
widgets, font objects, appearance streams.

PDF structure analysis and incremental update assembly is in incremental.py.
High-level signing API is in builder.py.
Position/geometry helpers are in position.py.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, TypedDict

if TYPE_CHECKING:
    import pikepdf

from .. import require_pikepdf as _require_pikepdf


class SigObjectNums(TypedDict):
    """Object numbers allocated for signature PDF objects.

    When ``visible=False`` (invisible signature), only ``sig`` and ``annot``
    are allocated; all appearance-related keys (font, ap, frm, n0, n2, etc.)
    are None.
    """

    sig: int
    annot: int
    font: int | None  # Type0 font dict
    cidfont: int | None  # CIDFontType2
    font_desc: int | None  # FontDescriptor
    font_file: int | None  # FontFile2 stream
    tounicode: int | None  # ToUnicode CMap stream
    ap: int | None
    frm: int | None
    n0: int | None
    n2: int | None
    img: int | None
    smask: int | None
    new_size: int


# ── Constants ────────────────────────────────────────────────────────
# Reserve 8192 bytes for CMS (CoSign CMS is ~1867 bytes, plenty of room)
CMS_RESERVED_SIZE = 8192
CMS_HEX_SIZE = CMS_RESERVED_SIZE * 2

BYTERANGE_PLACEHOLDER = b"/ByteRange [         0          0          0          0]"
BYTERANGE_PLACEHOLDER_STR = BYTERANGE_PLACEHOLDER.decode("ascii")

# PDF annotation flags for signature widget (/F entry).
# Print flag is 4, Locked flag is 128; combined value is 132.
# See PDF Reference 1.7, Table 165 -- Annotation flags.
_ANNOT_FLAG_PRINT = 4
_ANNOT_FLAG_LOCKED = 128
ANNOT_FLAGS_SIG_WIDGET = _ANNOT_FLAG_PRINT | _ANNOT_FLAG_LOCKED  # 132


# ── PDF string/object helpers ────────────────────────────────────────


def pdf_string(text: str) -> str:
    """Escape text for a PDF literal string.

    Handles backslash, parentheses, control characters, and non-Latin1
    characters (replaced with '?' since PDFDocEncoding has limited
    Unicode support).

    Logs a warning if any characters are replaced, as this indicates
    data loss in the PDF output.
    """
    import logging

    result: list[str] = []
    replaced_count = 0
    for char in text:
        code = ord(char)
        if char == "\\":
            result.append("\\\\")
        elif char == "(":
            result.append("\\(")
        elif char == ")":
            result.append("\\)")
        elif char == "\n":
            result.append("\\n")
        elif char == "\r":
            result.append("\\r")
        elif char == "\t":
            result.append("\\t")
        elif code < 0x20 or code == 0x7F:
            result.append(f"\\{code:03o}")
        elif code > 0xFF:
            # Non-Latin1 -> replacement (PDFDocEncoding can't represent these)
            result.append("?")
            replaced_count += 1
        else:
            result.append(char)
    if replaced_count > 0:
        logging.getLogger(__name__).warning(
            "pdf_string: %d non-Latin1 character(s) replaced with '?' in: %r", replaced_count, text
        )
    return "".join(result)


def _serialize_pikepdf_obj(obj: None | bool | int | float | pikepdf.Object) -> str:
    """Serialize a pikepdf object to a raw PDF string for embedding.

    Uses pikepdf's built-in unparse() for correct PDF syntax, with
    special handling for indirect references (emitted as "N G R")
    and plain Python types that pikepdf may return.
    """
    # Plain Python types (pikepdf sometimes returns these directly)
    if obj is None:
        return "null"
    if isinstance(obj, bool):
        return "true" if obj else "false"
    if isinstance(obj, int):
        return str(obj)
    if isinstance(obj, float):
        return str(int(obj)) if obj % 1 == 0.0 else f"{obj:.6f}"
    # pikepdf indirect reference (pikepdf must be imported by caller)
    pikepdf = _require_pikepdf()
    if isinstance(obj, pikepdf.Object) and obj.is_indirect:
        return f"{obj.objgen[0]} {obj.objgen[1]} R"
    # pikepdf's unparse handles all types correctly: null, arrays, dicts, names, etc.
    return obj.unparse(resolved=True).decode("latin-1")


# ── Object override builders ─────────────────────────────────────────


def build_object_override(
    pdf_bytes: bytes,
    obj_num: int,
    skip_key: str,
    new_entry: str,
) -> str:
    """Build a raw override of a PDF object with a new/replaced entry.

    Opens the PDF, extracts all entries from the target object (skipping
    skip_key), appends new_entry, and returns the raw PDF object string.

    Uses BytesIO for in-memory PDF access (no temp files).

    Args:
        pdf_bytes: Raw PDF content.
        obj_num: Target object number.
        skip_key: Key to omit from the original object (e.g., "/Annots").
        new_entry: New entry to append (e.g., "  /Annots [5 0 R]").

    Returns:
        str -- Raw PDF object definition.
    """
    import io

    pikepdf = _require_pikepdf()
    with pikepdf.open(io.BytesIO(pdf_bytes)) as pdf:
        obj = pdf.get_object((obj_num, 0))
        # pikepdf dict requires .keys() -- __iter__ yields values, not keys
        obj_keys = list(obj.keys())
        entries: list[str] = []
        for key in obj_keys:
            if key == skip_key:
                continue
            entries.append(f"  {key} {_serialize_pikepdf_obj(obj[key])}")

    entries.append(new_entry)
    body = "\n".join(entries)
    return f"{obj_num} 0 obj\n<<\n{body}\n>>\nendobj\n"


def build_page_override(pdf_bytes: bytes, page_obj_num: int, annots_list: str) -> str:
    """Build a raw override of the page object that adds /Annots."""
    return build_object_override(
        pdf_bytes,
        page_obj_num,
        skip_key="/Annots",
        new_entry=f"  /Annots [{annots_list}]",
    )


def build_catalog_override(pdf_bytes: bytes, root_obj_num: int, annot_obj_num: int) -> str:
    """Build a raw override of the catalog that adds /AcroForm."""
    return build_object_override(
        pdf_bytes,
        root_obj_num,
        skip_key="/AcroForm",
        new_entry=f"  /AcroForm << /Fields [{annot_obj_num} 0 R] /SigFlags 3 >>",
    )


# ── Object number allocation ────────────────────────────────────────


def allocate_sig_objects(
    prev_size: int,
    has_image: bool,
    has_smask: bool,
    visible: bool = True,
) -> SigObjectNums:
    """Allocate object numbers for all new PDF objects.

    When ``visible=True`` (default), allocates the full CoSign-compatible
    nested form structure:
      AP/N (top) -> /FRM Do
      /FRM       -> /n0 Do + /n2 Do
      /n0        -> empty placeholder ("% DSBlank")
      /n2        -> actual visible content (text, divider, image)
    Per PDF spec 12.7.4.5, Adobe Reader expects this structure for
    digital signature appearances.

    When ``visible=False``, only sig dict and annotation are allocated.
    The annotation will use /Rect [0 0 0 0] with no /AP entry.
    """
    next_obj = prev_size  # first free object number

    sig_obj_num = next_obj
    next_obj += 1
    annot_obj_num = next_obj
    next_obj += 1

    if not visible:
        return {
            "sig": sig_obj_num,
            "annot": annot_obj_num,
            "font": None,
            "cidfont": None,
            "font_desc": None,
            "font_file": None,
            "tounicode": None,
            "ap": None,
            "frm": None,
            "n0": None,
            "n2": None,
            "img": None,
            "smask": None,
            "new_size": next_obj,
        }

    font_obj_num = next_obj  # Type0 font dict
    next_obj += 1
    cidfont_obj_num = next_obj
    next_obj += 1
    font_desc_obj_num = next_obj
    next_obj += 1
    font_file_obj_num = next_obj
    next_obj += 1
    tounicode_obj_num = next_obj
    next_obj += 1

    ap_obj_num = next_obj  # top-level AP/N form ("/FRM Do")
    next_obj += 1
    frm_obj_num = next_obj  # /FRM intermediate form
    next_obj += 1
    n0_obj_num = next_obj  # /n0 empty placeholder
    next_obj += 1
    n2_obj_num = next_obj  # /n2 actual content
    next_obj += 1

    img_obj_num = None
    smask_obj_num = None
    if has_image:
        img_obj_num = next_obj
        next_obj += 1
        if has_smask:
            smask_obj_num = next_obj
            next_obj += 1

    return {
        "sig": sig_obj_num,
        "annot": annot_obj_num,
        "font": font_obj_num,
        "cidfont": cidfont_obj_num,
        "font_desc": font_desc_obj_num,
        "font_file": font_file_obj_num,
        "tounicode": tounicode_obj_num,
        "ap": ap_obj_num,
        "frm": frm_obj_num,
        "n0": n0_obj_num,
        "n2": n2_obj_num,
        "img": img_obj_num,
        "smask": smask_obj_num,
        "new_size": next_obj,
    }
