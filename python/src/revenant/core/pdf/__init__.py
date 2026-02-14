"""PDF preparation, verification, and incremental update assembly."""

from .builder import compute_byterange_hash, insert_cms, prepare_pdf_with_sig_field
from .cms_extraction import (
    BYTERANGE_PATTERN,
    extract_cms_from_byterange,
    extract_cms_from_byterange_match,
)
from .cms_info import CmsInspection, inspect_cms_blob
from .incremental import (
    assemble_incremental_update,
    build_xref_and_trailer,
    find_page_obj_num,
    find_prev_startxref,
    find_root_obj_num,
    patch_byterange,
)
from .objects import (
    ANNOT_FLAGS_SIG_WIDGET,
    BYTERANGE_PLACEHOLDER_STR,
    CMS_HEX_SIZE,
    SigObjectNums,
    allocate_sig_objects,
    build_catalog_override,
    build_page_override,
    pdf_string,
)
from .position import (
    POSITION_ALIASES,
    POSITION_PRESETS,
    SIG_HEIGHT,
    SIG_MARGIN_H,
    SIG_MARGIN_V,
    SIG_WIDTH,
    compute_sig_rect,
    get_page_dimensions,
    parse_page_spec,
    resolve_page_index,
    resolve_position,
)
from .verify import (
    VerificationResult,
    verify_all_embedded_signatures,
    verify_detached_signature,
    verify_embedded_signature,
)

__all__ = [
    "ANNOT_FLAGS_SIG_WIDGET",
    "BYTERANGE_PATTERN",
    "BYTERANGE_PLACEHOLDER_STR",
    "CMS_HEX_SIZE",
    "POSITION_ALIASES",
    "POSITION_PRESETS",
    "SIG_HEIGHT",
    "SIG_MARGIN_H",
    "SIG_MARGIN_V",
    "SIG_WIDTH",
    "CmsInspection",
    "SigObjectNums",
    "VerificationResult",
    "allocate_sig_objects",
    "assemble_incremental_update",
    "build_catalog_override",
    "build_page_override",
    "build_xref_and_trailer",
    "compute_byterange_hash",
    "compute_sig_rect",
    "extract_cms_from_byterange",
    "extract_cms_from_byterange_match",
    "find_page_obj_num",
    "find_prev_startxref",
    "find_root_obj_num",
    "get_page_dimensions",
    "insert_cms",
    "inspect_cms_blob",
    "parse_page_spec",
    "patch_byterange",
    "pdf_string",
    "prepare_pdf_with_sig_field",
    "resolve_page_index",
    "resolve_position",
    "verify_all_embedded_signatures",
    "verify_detached_signature",
    "verify_embedded_signature",
]
