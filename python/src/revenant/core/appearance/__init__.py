"""Signature visual appearance — layout, fonts, and image handling."""

from .fields import extract_cert_fields, extract_display_fields, format_utc_offset, make_date_str
from .fonts import (
    AVAILABLE_FONTS,
    DEFAULT_FONT,
    Font,
    FontMetrics,
    encode_text_hex,
    get_default_font,
    get_font,
    pdf_escape,
    text_width,
    wrap_lines,
)
from .image import SignatureImageData, load_signature_image
from .stream import (
    AppearanceData,
    build_appearance_stream,
    compute_optimal_height,
    compute_optimal_width,
)

__all__ = [
    "AVAILABLE_FONTS",
    "DEFAULT_FONT",
    "AppearanceData",
    "Font",
    "FontMetrics",
    "SignatureImageData",
    "build_appearance_stream",
    "compute_optimal_height",
    "compute_optimal_width",
    "encode_text_hex",
    "extract_cert_fields",
    "extract_display_fields",
    "format_utc_offset",
    "get_default_font",
    "get_font",
    "load_signature_image",
    "make_date_str",
    "pdf_escape",
    "text_width",
    "wrap_lines",
]
