"""
Core signing functions — detached CMS and embedded PDF signatures.

All signing functions accept a SigningTransport, making them transport-agnostic.
Use network.SoapSigningTransport(url) to create a transport instance.
"""

from __future__ import annotations

__all__ = [
    "EmbeddedSignatureOptions",
    "sign_data",
    "sign_hash",
    "sign_pdf_detached",
    "sign_pdf_embedded",
]

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

from ..constants import DEFAULT_TIMEOUT_SOAP, PDF_MAGIC
from ..errors import PDFError, RevenantError
from .appearance import compute_optimal_height, compute_optimal_width, get_font
from .pdf import (
    SIG_HEIGHT,
    SIG_WIDTH,
    compute_byterange_hash,
    insert_cms,
    prepare_pdf_with_sig_field,
    verify_embedded_signature,
)

if TYPE_CHECKING:
    from ..network.protocol import SigningTransport

_logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class EmbeddedSignatureOptions:
    """Options for embedded PDF signature placement and appearance.

    Bundles all appearance and positioning parameters for
    :func:`sign_pdf_embedded` into a single reusable object.

    Attributes:
        page: Page for the signature -- 0-based int, "first", or "last".
        position: Preset position name ("bottom-right", "br", etc.).
            Ignored when x/y are provided explicitly.
        x: Manual x-coordinate (PDF points, origin = bottom-left).
        y: Manual y-coordinate (PDF points, origin = bottom-left).
        w: Signature field width in PDF points.
        h: Signature field height in PDF points.
        reason: Signature reason string.
        name: Signer display name (used for PDF /Name entry).
        image_path: Optional path to a PNG/JPEG signature image.
        fields: Ordered display strings for the signature appearance.
        visible: If False, create an invisible signature.
        font: Font registry key (e.g. "noto-sans", "ghea-grapalat").
    """

    page: int | str = "last"
    position: str = "bottom-right"
    x: float | None = None
    y: float | None = None
    w: float = SIG_WIDTH
    h: float = SIG_HEIGHT
    reason: str = "Signed with Revenant"
    name: str | None = None
    image_path: str | None = None
    fields: list[str] | None = None
    visible: bool = True
    font: str | None = None


_OPTIONS_FIELDS = frozenset(
    (
        "page",
        "position",
        "x",
        "y",
        "w",
        "h",
        "reason",
        "name",
        "image_path",
        "fields",
        "visible",
        "font",
    )
)


def _resolve_options(
    options: EmbeddedSignatureOptions | None,
    kwargs: dict[str, object],
) -> EmbeddedSignatureOptions:
    """Merge explicit keyword arguments into an options instance.

    Keyword arguments override the corresponding fields in *options*.
    Unknown keys raise TypeError.
    """
    unknown = set(kwargs) - _OPTIONS_FIELDS
    if unknown:
        raise TypeError(f"Unexpected keyword arguments: {', '.join(sorted(unknown))}")

    if options is None:
        options = EmbeddedSignatureOptions()

    if not kwargs:
        return options

    from dataclasses import replace

    overrides = {k: v for k, v in kwargs.items() if k in _OPTIONS_FIELDS}
    return replace(options, **overrides)


def _validate_pdf(pdf_bytes: bytes) -> None:
    """Raise PDFError if bytes don't look like a PDF."""
    if not pdf_bytes or not pdf_bytes.startswith(PDF_MAGIC):
        raise PDFError("Input does not appear to be a PDF file.")


def sign_pdf_detached(
    pdf_bytes: bytes,
    transport: SigningTransport,
    username: str,
    password: str,
    timeout: int = DEFAULT_TIMEOUT_SOAP,
) -> bytes:
    """
    Sign a PDF document — returns a detached CMS/PKCS#7 signature.

    The transport handles the actual communication with the signing service.

    Args:
        pdf_bytes: Raw PDF file content.
        transport: SigningTransport implementation.
        username, password: Revenant credentials.
        timeout: Request timeout in seconds.

    Returns:
        Detached CMS/PKCS#7 signature (DER-encoded).
    """
    _validate_pdf(pdf_bytes)
    return transport.sign_pdf_detached(pdf_bytes, username, password, timeout)


def sign_hash(
    hash_bytes: bytes,
    transport: SigningTransport,
    username: str,
    password: str,
    timeout: int = DEFAULT_TIMEOUT_SOAP,
) -> bytes:
    """
    Sign a pre-computed hash.

    Args:
        hash_bytes: Pre-computed hash (typically 20-byte SHA-1).
        transport: SigningTransport implementation.
        username, password: Revenant credentials.
        timeout: Request timeout in seconds.

    Returns:
        CMS/PKCS#7 signature (DER-encoded) over the provided hash.
    """
    from ..constants import SHA1_DIGEST_SIZE

    if len(hash_bytes) != SHA1_DIGEST_SIZE:
        raise RevenantError(
            f"Expected {SHA1_DIGEST_SIZE}-byte SHA-1 hash, got {len(hash_bytes)} bytes."
        )
    return transport.sign_hash(hash_bytes, username, password, timeout)


def sign_data(
    data_bytes: bytes,
    transport: SigningTransport,
    username: str,
    password: str,
    timeout: int = DEFAULT_TIMEOUT_SOAP,
) -> bytes:
    """
    Sign arbitrary data.

    The transport's server computes SHA-1 internally and returns a CMS/PKCS#7
    signature with correct DigestAlgorithm and messageDigest attributes.

    Args:
        data_bytes: Raw data to sign (any size).
        transport: SigningTransport implementation.
        username, password: Revenant credentials.
        timeout: Request timeout in seconds.

    Returns:
        CMS/PKCS#7 signature (DER-encoded) over the data.
    """
    if not data_bytes:
        raise RevenantError("Cannot sign empty data.")
    return transport.sign_data(data_bytes, username, password, timeout)


def sign_pdf_embedded(
    pdf_bytes: bytes,
    transport: SigningTransport,
    username: str,
    password: str,
    timeout: int = DEFAULT_TIMEOUT_SOAP,
    options: EmbeddedSignatureOptions | None = None,
    **kwargs: object,
) -> bytes:
    """
    Sign a PDF with an embedded signature.

    Uses the data-then-sign workflow:
    1. Prepare PDF with empty signature field
    2. Extract ByteRange data (everything except hex placeholder)
    3. Send ByteRange data to transport for signing
    4. Insert CMS into the PDF
    5. Verify the signature

    Requires pikepdf.

    Args:
        pdf_bytes: Raw PDF file content.
        transport: SigningTransport implementation.
        username, password: Revenant credentials.
        timeout: Request timeout in seconds.
        options: Signature placement and appearance options.
            If None, uses defaults from EmbeddedSignatureOptions.
            Individual keyword arguments (page, position, x, y, w, h,
            reason, name, image_path, fields, visible, font) are also
            accepted and override the corresponding options fields.

    Returns:
        Complete PDF with embedded signature.
    """
    _validate_pdf(pdf_bytes)

    opts = _resolve_options(options, kwargs)

    w = opts.w
    h = opts.h
    if w <= 0 or h <= 0:
        raise PDFError(f"Signature dimensions must be positive, got w={w}, h={h}")
    if opts.x is not None and opts.x < 0:
        raise PDFError(f"Signature x-coordinate must be non-negative, got {opts.x}")
    if opts.y is not None and opts.y < 0:
        raise PDFError(f"Signature y-coordinate must be non-negative, got {opts.y}")

    _logger.info(
        "Signing PDF (embedded, %s): %d bytes, page=%s, position=%s",
        "visible" if opts.visible else "invisible",
        len(pdf_bytes),
        opts.page,
        opts.position,
    )

    # Auto-size dimensions if fields are available (visible mode only)
    if opts.visible:
        font_obj = get_font(opts.font)
        has_img = opts.image_path is not None
        if opts.fields:
            if w == SIG_WIDTH:
                w = compute_optimal_width(opts.fields, h, has_image=has_img, font=font_obj)
                _logger.debug("Adaptive signature width: %.1f pt", w)
            if h == SIG_HEIGHT:
                h = compute_optimal_height(opts.fields, w, has_image=has_img, font=font_obj)
                _logger.debug("Adaptive signature height: %.1f pt", h)

    # Step 1: Prepare PDF with signature field
    _logger.debug("Step 1: Preparing PDF with signature field")
    prepared_pdf, hex_start, hex_len = prepare_pdf_with_sig_field(
        pdf_bytes,
        page=opts.page,
        x=opts.x,
        y=opts.y,
        w=w,
        h=h,
        position=opts.position,
        reason=opts.reason,
        name=opts.name,
        image_path=opts.image_path,
        fields=opts.fields,
        visible=opts.visible,
        font=opts.font,
    )
    _logger.debug("Prepared PDF: %d bytes, hex_start=%d", len(prepared_pdf), hex_start)

    # Step 2: Extract ByteRange data (everything except hex placeholder)
    _logger.debug("Step 2: Extracting ByteRange data")
    before = prepared_pdf[:hex_start]
    after = prepared_pdf[hex_start + hex_len + 1 :]  # +1 for '>'
    br_data = before + after
    _logger.debug("ByteRange data: %d bytes", len(br_data))

    # Step 3: Send ByteRange data to transport for signing
    _logger.debug("Step 3: Sending ByteRange data to transport")
    cms_der = sign_data(br_data, transport, username, password, timeout)
    _logger.debug("Received CMS: %d bytes", len(cms_der))

    # Step 4: Insert CMS into PDF
    _logger.debug("Step 4: Inserting CMS into PDF")
    signed_pdf = insert_cms(prepared_pdf, hex_start, hex_len, cms_der)
    if len(signed_pdf) != len(prepared_pdf):
        raise PDFError(f"insert_cms changed PDF size: {len(prepared_pdf)} -> {len(signed_pdf)}")

    # Step 5: Verify the result
    _logger.debug("Step 5: Verifying signature")
    br_hash = compute_byterange_hash(prepared_pdf, hex_start, hex_len)
    result = verify_embedded_signature(signed_pdf, expected_hash=br_hash)
    if not result["valid"]:
        detail_str = "\n  ".join(result["details"])
        _logger.error("Post-sign verification failed: %s", detail_str)
        raise PDFError(
            f"Post-sign verification FAILED:\n  {detail_str}\n"
            "The signed PDF may be corrupt — not saved."
        )
    _logger.debug("Signature verified successfully")

    _logger.info("Signed PDF complete: %d bytes", len(signed_pdf))
    return signed_pdf
