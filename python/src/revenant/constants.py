"""
Application-wide constants for Revenant.

All timeout values, size limits, and other magic numbers are centralized
here for easy maintenance and configuration.
"""

from __future__ import annotations

import importlib.metadata

try:
    __version__ = importlib.metadata.version("revenant")
except importlib.metadata.PackageNotFoundError:
    __version__ = "0.2.2"

__all__ = [
    "BYTES_PER_MB",
    "DEFAULT_MAX_RETRIES",
    "DEFAULT_POSITION",
    "DEFAULT_RETRY_BACKOFF",
    "DEFAULT_RETRY_DELAY",
    "DEFAULT_TIMEOUT_HTTP_GET",
    "DEFAULT_TIMEOUT_HTTP_POST",
    "DEFAULT_TIMEOUT_LEGACY_TLS",
    "DEFAULT_TIMEOUT_SOAP",
    "ENV_NAME",
    "ENV_PASS",
    "ENV_TIMEOUT",
    "ENV_URL",
    "ENV_USER",
    "MAX_RESPONSE_SIZE",
    "MAX_TIMEOUT",
    "MIN_SIGNATURE_B64_LEN",
    "MIN_TIMEOUT",
    "PDF_MAGIC",
    "PDF_WARN_SIZE",
    "RECV_BUFFER_SIZE",
    "SHA1_DIGEST_SIZE",
    "XML_PREVIEW_LENGTH",
    "__version__",
]

# ── Timeout values (seconds) ──────────────────────────────────────────

# SOAP signing operations timeout
DEFAULT_TIMEOUT_SOAP = 120

# HTTP GET request timeout (for discovery)
DEFAULT_TIMEOUT_HTTP_GET = 15

# HTTP POST request timeout (SOAP)
DEFAULT_TIMEOUT_HTTP_POST = 120

# Legacy TLS connection timeout
DEFAULT_TIMEOUT_LEGACY_TLS = 30


# ── Size units ────────────────────────────────────────────────────────

# Bytes per megabyte -- used for size limit formatting and calculations
BYTES_PER_MB = 1024 * 1024


# ── Size limits (bytes) ───────────────────────────────────────────────

# Maximum response body size for legacy TLS requests (50 MB)
MAX_RESPONSE_SIZE = 50 * 1024 * 1024

# Socket recv buffer size for legacy TLS
RECV_BUFFER_SIZE = 8192

# PDF file size warning threshold (35 MB)
# Server reliably handles up to 35 MB (5/5 stable). 36+ MB is flaky (~50% failure).
PDF_WARN_SIZE = 35 * 1024 * 1024


# ── Retry configuration ───────────────────────────────────────────────

# Maximum number of retry attempts on transient failures
DEFAULT_MAX_RETRIES = 3

# Initial delay between retries (seconds)
DEFAULT_RETRY_DELAY = 1.0

# Exponential backoff multiplier for retry delay
DEFAULT_RETRY_BACKOFF = 2.0


# ── Protocol constants ────────────────────────────────────────────────

# Minimum Base64 length to distinguish CMS signatures from error messages
# CoSign CMS signatures are typically 2500+ characters in Base64
MIN_SIGNATURE_B64_LEN = 50

# XML preview truncation length for error messages (characters)
XML_PREVIEW_LENGTH = 300

# SHA-1 digest size (bytes)
SHA1_DIGEST_SIZE = 20


# ── Environment variable names ──────────────────────────────────────

ENV_URL = "REVENANT_URL"
ENV_TIMEOUT = "REVENANT_TIMEOUT"
ENV_USER = "REVENANT_USER"
ENV_PASS = "REVENANT_PASS"
ENV_NAME = "REVENANT_NAME"


# ── Timeout validation ──────────────────────────────────────────────

MIN_TIMEOUT = 1
MAX_TIMEOUT = 3600


# ── Signature defaults ──────────────────────────────────────────────

# Default position preset for embedded signatures
DEFAULT_POSITION = "bottom-right"

# PDF file magic bytes
PDF_MAGIC = b"%PDF-"
