# SPDX-License-Identifier: Apache-2.0
"""PDF structure analysis and incremental update assembly.

Functions for reading existing PDF structure (finding objects, xref offsets)
and building incremental updates (xref tables, trailers, ByteRange patching).

Object-level construction (types, allocation, overrides) is in objects.py.
High-level signing API is in builder.py.
"""

from __future__ import annotations

import io
import re
import zlib
from typing import TYPE_CHECKING

from ...errors import PDFError
from .. import require_pikepdf as _require_pikepdf
from .objects import BYTERANGE_PLACEHOLDER, CMS_HEX_SIZE

if TYPE_CHECKING:
    import pikepdf

_PageInfo = tuple[tuple[int, int], float, float, bool, list[str]]

# ── PDF structure analysis ───────────────────────────────────────────


def _open_pdf(pdf_bytes: bytes) -> pikepdf.Pdf:
    pikepdf = _require_pikepdf()
    try:
        return pikepdf.open(io.BytesIO(pdf_bytes))
    except pikepdf.PdfError as exc:
        raise PDFError(f"Cannot read PDF trailer: {exc}") from exc


def _catalog_ref(pdf: pikepdf.Pdf) -> tuple[int, int]:
    root = pdf.Root
    if not root.is_indirect:
        raise PDFError("Expected an indirect /Root reference in PDF trailer.")
    return root.objgen


def find_root_obj_num(pdf_bytes: bytes) -> tuple[int, int]:
    """Read the catalog object number and generation from the active trailer."""
    with _open_pdf(pdf_bytes) as pdf:
        return _catalog_ref(pdf)


def find_page_obj_num(
    pdf_bytes: bytes, _root_obj_num: int, page_spec: int | str
) -> tuple[int, float, float, bool, list[str]]:
    """Find the target page and its geometry and annotations."""
    _, (page_ref, width, height, has_annots, annots) = read_root_and_page(pdf_bytes, page_spec)
    return page_ref[0], width, height, has_annots, annots


def read_root_and_page(pdf_bytes: bytes, page_spec: int | str) -> tuple[tuple[int, int], _PageInfo]:
    """Resolve the catalog and target page from the same document revision."""
    from .position import get_page_dimensions, resolve_page_index

    with _open_pdf(pdf_bytes) as pdf:
        root = _catalog_ref(pdf)
        page_idx = resolve_page_index(pdf, page_spec)
        page_obj = pdf.pages[page_idx].obj
        page_w, page_h = get_page_dimensions(pdf, page_idx)
        # Check if page already has /Annots
        has_annots = "/Annots" in page_obj
        existing_annots: list[str] = []
        if has_annots:
            annots = page_obj["/Annots"]
            for i in range(len(annots)):
                ref = annots[i]
                existing_annots.append(f"{ref.objgen[0]} {ref.objgen[1]} R")
        return root, (page_obj.objgen, page_w, page_h, has_annots, existing_annots)


def find_prev_startxref(pdf_bytes: bytes) -> tuple[int, int, list[str], bool]:
    """Find the last startxref offset, max object number, and trailer entries.

    Returns:
        (prev_xref, max_size, trailer_extra, use_xref_stream) where
        trailer_extra is a list of raw trailer lines to carry forward
        (like /Info and /ID), and use_xref_stream indicates whether the
        PDF uses cross-reference streams (PDF 1.5+).
    """
    # Find the LAST startxref in the file -- PDFs with incremental updates
    # have multiple startxref/%%EOF pairs; the last one is authoritative.
    # The regex is lenient: some PDFs have trailing junk after %%EOF.
    matches = list(re.finditer(rb"startxref\s+(\d+)\s+%%EOF", pdf_bytes))
    if not matches:
        raise PDFError("Cannot find startxref in PDF.")
    prev_xref = int(matches[-1].group(1))

    # Determine /Size using pikepdf, which correctly resolves cross-reference
    # streams, incremental updates, and hybrid-reference files.
    # A regex-based approach fails when a PDF has both a cross-reference stream
    # (with large /Size) and a later traditional trailer (with smaller /Size).
    pikepdf = _require_pikepdf()
    try:
        with pikepdf.open(io.BytesIO(pdf_bytes)) as pdf:
            max_size = int(pdf.trailer["/Size"])
    except (pikepdf.PdfError, KeyError) as e:
        raise PDFError(f"Cannot determine /Size from PDF trailer: {e}") from e

    # Extract extra trailer entries to carry forward (/Info, /ID, etc.)
    # Per PDF spec, incremental update trailers must contain all entries
    # from the previous trailer (except /Prev and /Size which are updated).
    trailer_extra = _extract_trailer_entries(pdf_bytes)

    # Detect if source PDF uses XRef streams -- incremental updates must
    # use the same format (ISO 32000-1 S7.5.8.4)
    use_xref_stream = _detect_xref_streams(pdf_bytes, prev_xref)

    return prev_xref, max_size, trailer_extra, use_xref_stream


def _extract_trailer_entries(pdf_bytes: bytes) -> list[str]:
    """Extract /Info and /ID entries from the trailer.

    Handles both traditional trailers (``trailer << ... >>``) and
    cross-reference stream PDFs where trailer data is stored in the
    xref stream dictionary.  Falls back to pikepdf when no traditional
    trailer is found, which correctly resolves both formats.
    """
    # Try traditional trailers first (cheaper than pikepdf)
    trailer_extra: list[str] = []
    all_trailers = list(re.finditer(rb"trailer\s*<<(.*?)>>", pdf_bytes, re.DOTALL))
    if all_trailers:
        trailer_content = all_trailers[-1].group(1)
        info_m = re.search(rb"/Info\s+\d+\s+\d+\s+R", trailer_content)
        if info_m:
            trailer_extra.append(info_m.group(0).decode("latin-1"))
        id_m = re.search(rb"/ID\s*\[.*?\]", trailer_content, re.DOTALL)
        if id_m:
            trailer_extra.append(id_m.group(0).decode("latin-1"))
        if trailer_extra:
            return trailer_extra

    # No traditional trailer or no entries found -- use pikepdf to read
    # trailer data from cross-reference streams.
    pikepdf = _require_pikepdf()
    with pikepdf.open(io.BytesIO(pdf_bytes)) as pdf:
        trailer = pdf.trailer
        if "/Info" in trailer:
            info_obj = trailer["/Info"]
            if isinstance(info_obj, pikepdf.Object) and info_obj.is_indirect:
                trailer_extra.append(f"/Info {info_obj.objgen[0]} {info_obj.objgen[1]} R")
        if "/ID" in trailer:
            id_array = trailer["/ID"]
            trailer_extra.append(f"/ID {id_array.unparse(resolved=True).decode('latin-1')}")
    return trailer_extra


# ── Incremental update assembly ─────────────────────────────────────


def assemble_incremental_update(
    pdf_bytes: bytes,
    raw_objects: list[tuple[bytes, int]],
    new_size: int,
    prev_xref: int,
    root_obj_num: int,
    root_gen: int,
    trailer_extra: list[str],
    use_xref_stream: bool = False,
    *,
    page_ref: tuple[int, int] | None = None,
) -> bytes:
    """Assemble the full PDF with incremental update appended."""
    # Ensure original PDF ends with \n after %%EOF
    base = pdf_bytes
    if not base.endswith(b"\n"):
        base = base + b"\n"

    update_start = len(base)

    # Collect all new objects and their offsets
    objects_raw: list[bytes] = []
    xref_entries: dict[int, int] = {}

    running_offset = update_start
    for raw_bytes, obj_num in raw_objects:
        xref_entries[obj_num] = running_offset
        objects_raw.append(raw_bytes)
        running_offset += len(raw_bytes)

    all_objects = b"".join(objects_raw)

    # Build xref section (table or stream depending on source PDF format)
    xref_offset = update_start + len(all_objects)

    if use_xref_stream:
        xref_obj_num = new_size
        xref_data = build_xref_stream(
            xref_entries=xref_entries,
            prev_xref=prev_xref,
            root_obj_num=root_obj_num,
            root_gen=root_gen,
            trailer_extra=trailer_extra,
            xref_offset=xref_offset,
            xref_obj_num=xref_obj_num,
            page_ref=page_ref,
        )
        return base + all_objects + xref_data

    xref_data = build_xref_and_trailer(
        xref_entries=xref_entries,
        new_size=new_size,
        prev_xref=prev_xref,
        root_obj_num=root_obj_num,
        root_gen=root_gen,
        trailer_extra=trailer_extra,
        xref_offset=xref_offset,
        page_ref=page_ref,
    )

    return base + all_objects + xref_data


def patch_byterange(full_pdf: bytes, original_len: int) -> tuple[bytes, int, int]:
    """Patch the ByteRange placeholder and return (pdf, hex_start, hex_len)."""
    contents_zeros = "0" * CMS_HEX_SIZE
    contents_marker = f"/Contents <{contents_zeros}>".encode("latin-1")

    # Search from where the incremental update starts
    update_start = original_len
    contents_pos = full_pdf.find(contents_marker, update_start)
    if contents_pos == -1:
        raise PDFError("Cannot find Contents placeholder in prepared PDF.")

    hex_start = contents_pos + len(b"/Contents <")
    hex_end = hex_start + CMS_HEX_SIZE

    # Compute ByteRange values
    br_before_len = hex_start
    br_after_start = hex_end + 1  # +1 for closing ">"
    br_after_len = len(full_pdf) - br_after_start

    byterange_value = (
        f"/ByteRange [{0:>10d} {br_before_len:>10d} {br_after_start:>10d} {br_after_len:>10d}]"
    ).encode("latin-1")

    # Patch the ByteRange placeholder in the incremental update only.
    # Use positional replacement to avoid matching placeholders elsewhere
    # in the original PDF (e.g., if the PDF was previously signed).
    br_pos = full_pdf.find(BYTERANGE_PLACEHOLDER, update_start)
    if br_pos == -1:
        raise PDFError("Cannot find ByteRange placeholder in incremental update.")
    full_pdf = full_pdf[:br_pos] + byterange_value + full_pdf[br_pos + len(BYTERANGE_PLACEHOLDER) :]

    # Recalculate hex_start (should be unchanged since placeholder is same width)
    contents_pos2 = full_pdf.find(b"/Contents <", update_start)
    hex_start = contents_pos2 + len(b"/Contents <")

    return full_pdf, hex_start, CMS_HEX_SIZE


# ── Xref table builder ──────────────────────────────────────────────


def _updated_generations(
    root_obj_num: int, root_gen: int, page_ref: tuple[int, int] | None
) -> dict[int, int]:
    generations = {root_obj_num: root_gen}
    if page_ref is not None:
        page_num, page_gen = page_ref
        generations[page_num] = page_gen
    return generations


def build_xref_and_trailer(
    xref_entries: dict[int, int],
    new_size: int,
    prev_xref: int,
    root_obj_num: int,
    root_gen: int,
    trailer_extra: list[str],
    xref_offset: int,
    *,
    page_ref: tuple[int, int] | None = None,
) -> bytes:
    """Build an xref table and trailer for an incremental update.

    Args:
        xref_entries: Mapping of object number to byte offset.
        new_size: Total object count (/Size value).
        prev_xref: Previous xref offset (/Prev value).
        root_obj_num: Catalog object number for /Root reference.
        root_gen: Catalog generation number.
        page_ref: Page object number and generation when redefining a page.
        trailer_extra: Extra trailer entries to carry forward (/Info, /ID).
        xref_offset: Byte offset where this xref table starts.

    Returns:
        Raw bytes of the xref table, trailer, and %%EOF.
    """
    generations = _updated_generations(root_obj_num, root_gen, page_ref)
    xref_lines = ["xref"]

    if not xref_entries:
        raise PDFError("Cannot build xref table: no objects to reference.")

    # Group consecutive object numbers for compact xref sections
    sorted_nums = sorted(xref_entries.keys())
    groups: list[list[int]] = []
    current_group = [sorted_nums[0]]
    for n in sorted_nums[1:]:
        if n == current_group[-1] + 1:
            current_group.append(n)
        else:
            groups.append(current_group)
            current_group = [n]
    groups.append(current_group)

    for group in groups:
        xref_lines.append(f"{group[0]} {len(group)}")
        # PDF spec S7.5.4: each xref entry is exactly 20 bytes including EOL.
        # Format: "oooooooooo ggggg n\r\n" = 18 chars + \r + \n = 20 bytes.
        # The \r is part of the format string; \n comes from "\n".join().
        for obj_num in group:
            generation = generations.get(obj_num, 0)
            xref_lines.append(f"{xref_entries[obj_num]:010d} {generation:05d} n\r")

    # Trailer -- must carry forward all entries from the previous trailer
    # (per PDF spec S7.5.6: entries from previous trailer that are not
    # overridden must be included)
    xref_lines.append("trailer")
    xref_lines.append("<<")
    xref_lines.append(f"  /Size {new_size}")
    xref_lines.append(f"  /Prev {prev_xref}")
    xref_lines.append(f"  /Root {root_obj_num} {root_gen} R")
    xref_lines.extend(f"  {extra}" for extra in trailer_extra)
    xref_lines.append(">>")
    xref_lines.append("startxref")
    xref_lines.append(str(xref_offset))
    xref_lines.append("%%EOF")
    xref_lines.append("")  # trailing newline

    return "\n".join(xref_lines).encode("latin-1")


def build_xref_stream(
    xref_entries: dict[int, int],
    prev_xref: int,
    root_obj_num: int,
    root_gen: int,
    trailer_extra: list[str],
    xref_offset: int,
    xref_obj_num: int,
    *,
    page_ref: tuple[int, int] | None = None,
) -> bytes:
    """Build a cross-reference stream for an incremental update (PDF 1.5+).

    PDFs that use XRef streams require incremental updates to also use
    XRef streams (ISO 32000-1 S7.5.8.4). This replaces both the xref
    table and trailer with a single stream object.

    Args:
        xref_entries: Mapping of object number to byte offset.
        prev_xref: Previous xref offset (/Prev value).
        root_obj_num: Catalog object number for /Root reference.
        root_gen: Catalog generation number.
        page_ref: Page object number and generation when redefining a page.
        trailer_extra: Extra trailer entries to carry forward (/Info, /ID).
        xref_offset: Byte offset where this XRef stream object starts.
        xref_obj_num: Object number for the XRef stream itself.

    Returns:
        Raw bytes of the XRef stream object, startxref, and %%EOF.
    """
    # Include the XRef stream object in its own cross-reference data
    all_entries = dict(xref_entries)
    all_entries[xref_obj_num] = xref_offset

    # /Size = highest object number + 1
    actual_size = xref_obj_num + 1

    # Determine W (column widths for binary entries per ISO 32000-1 Table 17)
    # Column 1: type (1 byte, value 1 = in-use uncompressed)
    # Column 2: byte offset (variable width, big-endian)
    # Column 3: generation number of each redefined object
    max_offset = max(all_entries.values())
    w2 = _bytes_needed(max_offset)
    generations = _updated_generations(root_obj_num, root_gen, page_ref)
    w3 = _bytes_needed(max(generations.values()))

    # Build /Index subsections and binary stream data
    sorted_nums = sorted(all_entries.keys())
    groups = _group_consecutive(sorted_nums)
    index_parts: list[str] = []
    binary_parts = bytearray()

    for group in groups:
        index_parts.append(f"{group[0]} {len(group)}")
        for obj_num in group:
            offset = all_entries[obj_num]
            binary_parts.append(1)  # type 1 = in-use, uncompressed
            binary_parts.extend(offset.to_bytes(w2, byteorder="big"))
            generation = generations.get(obj_num, 0)
            binary_parts.extend(generation.to_bytes(w3, byteorder="big"))

    compressed = zlib.compress(bytes(binary_parts))

    # Build the XRef stream object (replaces both xref table and trailer)
    lines: list[str] = []
    lines.append(f"{xref_obj_num} 0 obj")
    lines.append("<<")
    lines.append("  /Type /XRef")
    lines.append(f"  /Size {actual_size}")
    lines.append(f"  /Prev {prev_xref}")
    lines.append(f"  /Root {root_obj_num} {root_gen} R")
    lines.append(f"  /W [1 {w2} {w3}]")
    lines.append(f"  /Index [{' '.join(index_parts)}]")
    lines.append("  /Filter /FlateDecode")
    lines.append(f"  /Length {len(compressed)}")
    lines.extend(f"  {extra}" for extra in trailer_extra)
    lines.append(">>")
    lines.append("stream")

    header = ("\n".join(lines) + "\n").encode("latin-1")
    footer = f"\nendstream\nendobj\nstartxref\n{xref_offset}\n%%EOF\n".encode("latin-1")

    return header + compressed + footer


def _detect_xref_streams(pdf_bytes: bytes, startxref_offset: int) -> bool:
    """Detect whether the PDF uses cross-reference streams (PDF 1.5+).

    Checks the bytes at the last startxref offset: if they match an object
    definition (N N obj) rather than ``xref``, the PDF uses XRef streams.
    """
    end = min(startxref_offset + 40, len(pdf_bytes))
    chunk = pdf_bytes[startxref_offset:end]
    return bool(re.match(rb"\s*\d+\s+\d+\s+obj\b", chunk))


def _group_consecutive(sorted_nums: list[int]) -> list[list[int]]:
    """Group sorted numbers into consecutive runs for xref subsections."""
    if not sorted_nums:
        return []
    groups: list[list[int]] = []
    current_group = [sorted_nums[0]]
    for n in sorted_nums[1:]:
        if n == current_group[-1] + 1:
            current_group.append(n)
        else:
            groups.append(current_group)
            current_group = [n]
    groups.append(current_group)
    return groups


def _bytes_needed(value: int) -> int:
    """Minimum bytes needed to represent a non-negative integer in big-endian."""
    if value <= 0xFF:
        return 1
    if value <= 0xFFFF:
        return 2
    if value <= 0xFFFFFF:
        return 3
    return 4
