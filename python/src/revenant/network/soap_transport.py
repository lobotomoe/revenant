"""
SOAP-based signing transport implementation.

Implements SigningTransport protocol for CoSign SOAP services.
"""

from __future__ import annotations

import base64
import logging

from ..constants import PDF_MAGIC, SHA1_DIGEST_SIZE
from ..errors import PDFError, RevenantError
from .soap import (
    SIGNATURE_TYPE_CMS,
    ServerVerifyResult,
    build_enum_certificates_envelope,
    build_sign_envelope,
    build_sign_hash_envelope,
    build_verify_envelope,
    parse_enum_certificates_response,
    parse_sign_response,
    parse_verify_response,
    send_soap,
)

_logger = logging.getLogger(__name__)


class SoapSigningTransport:
    """SOAP-based implementation of SigningTransport protocol.

    Communicates with CoSign SOAP endpoints for remote signing operations.
    """

    def __init__(self, url: str) -> None:
        """
        Initialize SOAP transport.

        Args:
            url: CoSign SOAP endpoint URL (e.g., https://host/SAPIWS/DSS.asmx).
        """
        self.url = url

    def _send_and_parse(self, envelope: str, timeout: int) -> bytes:
        """Send a SOAP envelope and parse the CMS signature from the response."""
        _logger.debug("Sending SOAP request to %s (timeout=%ds)", self.url, timeout)
        response = send_soap(self.url, envelope, timeout=timeout)
        cms = parse_sign_response(response)
        _logger.info("Received CMS signature: %d bytes", len(cms))
        return cms

    def sign_data(self, data: bytes, username: str, password: str, timeout: int) -> bytes:
        """Sign arbitrary data via CoSign Document API."""
        if not data:
            raise RevenantError("Cannot sign empty data.")

        _logger.info("Signing data via SOAP: %d bytes", len(data))
        data_b64 = base64.b64encode(data).decode("ascii")
        envelope = build_sign_envelope(username, password, SIGNATURE_TYPE_CMS, data_b64)
        return self._send_and_parse(envelope, timeout)

    def sign_hash(self, hash_bytes: bytes, username: str, password: str, timeout: int) -> bytes:
        """Sign a pre-computed hash via CoSign DocumentHash API."""
        if len(hash_bytes) != SHA1_DIGEST_SIZE:
            raise RevenantError(
                f"Expected {SHA1_DIGEST_SIZE}-byte SHA-1 hash, got {len(hash_bytes)} bytes."
            )

        _logger.debug("Signing SHA-1 hash via SOAP: %d bytes", len(hash_bytes))
        hash_b64 = base64.b64encode(hash_bytes).decode("ascii")
        envelope = build_sign_hash_envelope(username, password, SIGNATURE_TYPE_CMS, hash_b64)
        return self._send_and_parse(envelope, timeout)

    def sign_pdf_detached(
        self, pdf_bytes: bytes, username: str, password: str, timeout: int
    ) -> bytes:
        """Sign a complete PDF document via CoSign Document API."""
        if not pdf_bytes or not pdf_bytes.startswith(PDF_MAGIC):
            raise PDFError("Input does not appear to be a PDF file.")

        _logger.info("Signing PDF (detached) via SOAP: %d bytes", len(pdf_bytes))
        pdf_b64 = base64.b64encode(pdf_bytes).decode("ascii")
        envelope = build_sign_envelope(username, password, SIGNATURE_TYPE_CMS, pdf_b64)
        return self._send_and_parse(envelope, timeout)


def verify_pdf_server(url: str, pdf_bytes: bytes, timeout: int) -> ServerVerifyResult:
    """Verify a signed PDF via server-side DssVerify.

    No authentication required. Never raises -- all errors are captured
    in the returned ServerVerifyResult.

    Args:
        url: CoSign SOAP endpoint URL.
        pdf_bytes: The signed PDF to verify.
        timeout: Request timeout in seconds.

    Returns:
        ServerVerifyResult with verification outcome.
    """
    try:
        _logger.info("Server-side verify: %d bytes, url=%s", len(pdf_bytes), url)
        pdf_b64 = base64.b64encode(pdf_bytes).decode("ascii")
        envelope = build_verify_envelope(pdf_b64)
        response = send_soap(url, envelope, action="DssVerify", timeout=timeout)
        return parse_verify_response(response)
    except (RevenantError, ValueError, TypeError, OSError) as e:
        _logger.warning("Server verify failed: %s", e)
        return ServerVerifyResult(valid=False, error=str(e))


def enum_certificates(url: str, username: str, password: str, timeout: int) -> list[bytes]:
    """Enumerate user certificates via SAPI enum-certificates.

    Returns list of DER-encoded X.509 certificates.

    Args:
        url: CoSign SOAP endpoint URL.
        username: Revenant username.
        password: Revenant password.
        timeout: Request timeout in seconds.

    Returns:
        List of DER-encoded X.509 certificate bytes.

    Raises:
        AuthError: If credentials are wrong.
        ServerError: If the server returned an error.
        RevenantError: If the response cannot be parsed.
        TLSError: On connection issues.
    """
    _logger.info("Enumerating certificates: url=%s", url)
    envelope = build_enum_certificates_envelope(username, password)
    response = send_soap(url, envelope, timeout=timeout)
    return parse_enum_certificates_response(response)
