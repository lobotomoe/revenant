"""
revenant — Cross-platform Python client for ARX CoSign electronic signatures.

Signs PDF documents via the CoSign SOAP API (OASIS DSS standard).
No Windows required — works on macOS and Linux.
"""

from __future__ import annotations

from .api import sign, sign_detached
from .config.config import get_signer_name
from .constants import __version__
from .core.pdf import (
    POSITION_PRESETS,
    resolve_position,
    verify_all_embedded_signatures,
    verify_embedded_signature,
)
from .core.signing import (
    EmbeddedSignatureOptions,
    sign_data,
    sign_hash,
    sign_pdf_detached,
    sign_pdf_embedded,
)
from .errors import (
    AuthError,
    CertificateError,
    ConfigError,
    PDFError,
    RevenantError,
    ServerError,
    TLSError,
)

__all__ = [
    "POSITION_PRESETS",
    "AuthError",
    "CertificateError",
    "ConfigError",
    "EmbeddedSignatureOptions",
    "PDFError",
    "RevenantError",
    "ServerError",
    "TLSError",
    "__version__",
    "get_signer_name",
    "resolve_position",
    "sign",
    "sign_data",
    "sign_detached",
    "sign_hash",
    "sign_pdf_detached",
    "sign_pdf_embedded",
    "verify_all_embedded_signatures",
    "verify_embedded_signature",
]
