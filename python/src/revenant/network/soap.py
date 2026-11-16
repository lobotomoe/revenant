# SPDX-License-Identifier: Apache-2.0
"""
SOAP transport and XML parsing for CoSign API.

Standard servers use urllib (system TLS).  EKENG's ca.gov.am requires
TLS 1.0 + RC4-MD5 via tlslite-ng; callers pass ``rc4=True`` for that.
"""

from __future__ import annotations

import logging

from ..constants import DEFAULT_MAX_RETRIES, DEFAULT_TIMEOUT_HTTP_POST
from .soap_envelope import (
    SIGNATURE_TYPE_CMS,
    SIGNATURE_TYPE_ENUM_CERTS,
    SIGNATURE_TYPE_FIELD_VERIFY,
    SIGNATURE_TYPE_XMLDSIG,
    build_change_password_envelope,
    build_enum_certificates_envelope,
    build_sign_envelope,
    build_sign_hash_envelope,
    build_verify_envelope,
    xml_escape,
)
from .soap_parsers import (
    ServerVerifyResult,
    parse_change_password_response,
    parse_enum_certificates_response,
    parse_sign_response,
    parse_verify_response,
)
from .transport import http_post

_logger = logging.getLogger(__name__)

__all__ = [
    "SIGNATURE_TYPE_CMS",
    "SIGNATURE_TYPE_ENUM_CERTS",
    "SIGNATURE_TYPE_FIELD_VERIFY",
    "SIGNATURE_TYPE_XMLDSIG",
    "ServerVerifyResult",
    "build_change_password_envelope",
    "build_enum_certificates_envelope",
    "build_sign_envelope",
    "build_sign_hash_envelope",
    "build_verify_envelope",
    "parse_change_password_response",
    "parse_enum_certificates_response",
    "parse_sign_response",
    "parse_verify_response",
    "send_soap",
    "xml_escape",
]


def send_soap(
    url: str,
    envelope: str,
    action: str = "DssSign",
    timeout: int = DEFAULT_TIMEOUT_HTTP_POST,
    max_retries: int = DEFAULT_MAX_RETRIES,
) -> str:
    """
    Send a SOAP request to a CoSign endpoint.

    TLS mode (standard or legacy) is determined automatically by the
    transport layer based on the target host.

    ``max_retries`` bounds transport-level retries. A request that must not
    reach the server twice (a password change) passes 0.

    Returns the response body as string.
    Raises TLSError on connection issues, RevenantError on failures.
    """
    _logger.debug("SOAP request: action=%s, url=%s, timeout=%ds", action, url, timeout)
    headers = {
        "Content-Type": "text/xml; charset=utf-8",
        "SOAPAction": f"http://arx.com/SAPIWS/DSS/1.0/{action}",
    }
    body = envelope.encode("utf-8")
    _logger.debug("Request body: %d bytes", len(body))
    response = http_post(
        url,
        body,
        headers=headers,
        timeout=timeout,
        max_retries=max_retries,
    )
    decoded = response.decode("utf-8", errors="replace")
    _logger.debug("SOAP response: %d bytes", len(decoded))
    return decoded
