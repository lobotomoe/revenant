# pyright: reportUnknownMemberType=false
"""
Image loading and preparation for PDF signature fields.

Loads PNG/JPEG images, downscales if needed, extracts alpha channels,
and returns deflate-compressed pixel data ready for PDF embedding.
"""

from __future__ import annotations

import zlib
from pathlib import Path
from typing import TypedDict


class SignatureImageData(TypedDict):
    """Data returned by load_signature_image."""

    samples: bytes  # Deflate-compressed RGB pixel data
    smask: bytes | None  # Deflate-compressed alpha channel, or None if opaque
    width: int  # Pixel width
    height: int  # Pixel height
    bpc: int  # Bits per component (always 8)


# Maximum image dimension in pixels before downscaling.
# Signature images don't need to be large — 200x100 is plenty for print.
_MAX_IMAGE_PX = 200

# Maximum input file size (5 MB). Anything larger is certainly not a
# reasonable signature image and might be a decompression bomb or mistake.
_MAX_FILE_SIZE = 5 * 1024 * 1024

# Allowed image formats (Pillow format names).
_ALLOWED_FORMATS = {"PNG", "JPEG", "GIF", "BMP", "TIFF", "WEBP"}

# Maximum pixel count to prevent decompression bombs (CWE-400).
# Pillow's default (~89M pixels) allows ~270 MB RAM for RGB, which is
# excessive for signature images.  A 2000x2000 source is already far
# larger than the 200px target — anything beyond is suspicious.
_MAX_IMAGE_PIXELS = 2000 * 2000


def load_signature_image(image_path: str) -> SignatureImageData:
    """Load an image file and prepare it for embedding in a PDF signature.

    Supports PNG (with transparency) and JPEG.
    Images are downscaled if larger than 200px on any side.

    Args:
        image_path: Path to a PNG or JPEG file.

    Returns:
        dict with keys:
            'samples': bytes -- raw RGB pixel data (deflate-compressed)
            'smask': bytes or None -- alpha channel (deflate-compressed), None if opaque
            'width': int -- pixel width
            'height': int -- pixel height
            'bpc': int -- bits per component (always 8)

    Raises:
        FileNotFoundError: if image_path does not exist.
        ValueError: if the image format is not supported.
    """
    path = Path(image_path).resolve()
    if not path.exists():
        msg = f"Signature image not found: {path}"
        raise FileNotFoundError(msg)

    # Check file size before loading into memory
    file_size = path.stat().st_size
    if file_size > _MAX_FILE_SIZE:
        msg = (
            f"Signature image too large: {file_size / 1024 / 1024:.1f} MB "
            f"(max {_MAX_FILE_SIZE / 1024 / 1024:.0f} MB)"
        )
        raise ValueError(msg)
    if file_size == 0:
        raise ValueError("Signature image file is empty")

    try:
        from PIL import Image
    except ImportError as exc:
        raise ImportError(
            "Pillow is required for signature images.\n"
            "Install with: pip install pikepdf  (includes Pillow)"
        ) from exc

    try:
        img = Image.open(path)
    except OSError as exc:
        # PIL raises UnidentifiedImageError (subclass of OSError) for unknown formats,
        # and OSError for I/O issues.
        raise ValueError(f"Cannot load image file: {exc}") from exc

    try:
        # Reject images with excessive pixel count before any decompression.
        # Image.open() is lazy — it reads the header (dimensions) without
        # loading pixel data into memory.  Decompression happens during
        # resize/tobytes, so we must check BEFORE those calls.
        # A crafted file can be tiny on disk but decompress to massive
        # dimensions (decompression bomb, CWE-400).
        pixel_count = img.width * img.height
        if pixel_count > _MAX_IMAGE_PIXELS:
            raise ValueError(
                f"Image too large: {img.width}x{img.height} ({pixel_count:,} pixels). "
                f"Maximum: {_MAX_IMAGE_PIXELS:,} pixels."
            )

        # Validate image format — reject unknown formats (img.format is None
        # for raw streams) and explicitly unsupported ones.
        if not img.format or img.format not in _ALLOWED_FORMATS:
            actual = img.format or "unknown"
            msg = (
                f"Unsupported image format: {actual}. "
                f"Supported: {', '.join(sorted(_ALLOWED_FORMATS))}"
            )
            raise ValueError(msg)

        # Downscale if too large
        max_dim = max(img.width, img.height)
        if max_dim > _MAX_IMAGE_PX:
            scale = _MAX_IMAGE_PX / max_dim
            new_w = max(1, int(img.width * scale))
            new_h = max(1, int(img.height * scale))
            img = img.resize((new_w, new_h), Image.Resampling.LANCZOS)

        # Extract alpha channel if present
        smask_data = None
        if img.mode in ("RGBA", "LA", "PA"):
            alpha = img.split()[-1]
            smask_data = zlib.compress(alpha.tobytes())
            img = img.convert("RGB")
        elif img.mode != "RGB":
            img = img.convert("RGB")

        rgb_data = zlib.compress(img.tobytes())

        return {
            "samples": rgb_data,
            "smask": smask_data,
            "width": img.width,
            "height": img.height,
            "bpc": 8,
        }
    finally:
        img.close()
