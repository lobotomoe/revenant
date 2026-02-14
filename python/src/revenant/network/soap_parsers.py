"""SOAP response parsers for CoSign API."""

from __future__ import annotations

import base64
import binascii
import logging
import re
from dataclasses import dataclass
from xml.etree.ElementTree import ParseError as _XMLParseError

import defusedxml.ElementTree as ET

from ..constants import MIN_SIGNATURE_B64_LEN, XML_PREVIEW_LENGTH
from ..errors import AuthError, RevenantError, ServerError

_logger = logging.getLogger(__name__)

# ResultMinor URN suffix indicating authentication failure (language-independent)
_AUTH_MINOR_SUFFIX = ":AuthenticationError"

# Regex patterns for redacting credentials from XML previews in error messages
_REDACT_PASSWORD_PATTERN = r"<[\w:]*LogonPassword>[^<]*</[\w:]*LogonPassword>"
_REDACT_PASSWORD_REPLACEMENT = "<LogonPassword>[REDACTED]</LogonPassword>"
_REDACT_NAME_PATTERN = r"<(\w+:)?Name>[^<]*</(\w+:)?Name>"
_REDACT_NAME_REPLACEMENT = "<Name>[REDACTED]</Name>"


def _strip_namespace(tag: str) -> str:
    """Strip XML namespace prefix from a tag name."""
    return tag.split("}")[-1] if "}" in tag else tag


def _is_auth_error(result_minor: str | None, msg: str) -> bool:
    """Detect authentication failures by ResultMinor URN or message keywords."""
    return (
        bool(result_minor and result_minor.endswith(_AUTH_MINOR_SUFFIX))
        or "password" in msg.lower()
        or "user name" in msg.lower()
    )


def _redact_and_truncate_xml(xml_str: str) -> str:
    """Redact credentials from XML and truncate to preview length.

    Used in error messages to prevent leaking passwords in logs/exceptions.
    """
    redacted = re.sub(_REDACT_PASSWORD_PATTERN, _REDACT_PASSWORD_REPLACEMENT, xml_str)
    redacted = re.sub(_REDACT_NAME_PATTERN, _REDACT_NAME_REPLACEMENT, redacted)
    return redacted[:XML_PREVIEW_LENGTH]


def parse_sign_response(xml_str: str) -> bytes:
    """
    Parse the DssSign SOAP response.

    Returns:
        bytes -- the CMS/PKCS#7 signature blob on success.

    Raises:
        AuthError -- if credentials are wrong.
        ServerError -- if the server returned an error.
        RevenantError -- if the response cannot be parsed.
    """
    try:
        root = ET.fromstring(xml_str)
    except _XMLParseError as e:
        _logger.exception("Invalid XML response")
        # Truncate raw XML for error message — avoid leaking credentials
        # that might be echoed back by the server.
        safe_preview = _redact_and_truncate_xml(xml_str[:500])
        raise RevenantError(f"Invalid XML response: {e}\nRaw: {safe_preview}") from e

    result_major = None
    result_minor = None
    result_message = None
    cms_b64 = None

    for elem in root.iter():
        tag = _strip_namespace(elem.tag)
        text = (elem.text or "").strip()

        if tag == "ResultMajor" and text:
            result_major = text
        elif tag == "ResultMinor" and text:
            result_minor = text
        elif tag == "ResultMessage" and text:
            result_message = text
        elif (
            tag in ("Base64Data", "Base64Signature") and text and len(text) > MIN_SIGNATURE_B64_LEN
        ):
            cms_b64 = text

    _logger.debug(
        "Parsed response: major=%s, minor=%s, message=%s, has_cms=%s",
        result_major,
        result_minor,
        result_message,
        cms_b64 is not None,
    )

    if result_major and result_major.endswith(":Success"):
        if not cms_b64:
            _logger.error("Server returned Success but no signature data")
            raise ServerError("Server returned Success but no signature data.")
        try:
            cms = base64.b64decode(cms_b64)
        except binascii.Error as e:
            raise RevenantError(f"Invalid Base64 in server response: {e}") from e
        _logger.debug("Decoded CMS signature: %d bytes", len(cms))
        return cms

    msg = result_message or result_minor or result_major or "Unknown error"

    if _is_auth_error(result_minor, msg):
        _logger.warning("Authentication failed: %s", msg)
        raise AuthError(f"Authentication failed: {msg}")

    _logger.error("Signing failed: %s", msg)
    raise ServerError(f"Signing failed: {msg}")


def parse_enum_certificates_response(xml_str: str) -> list[bytes]:
    """Parse the enum-certificates SOAP response.

    Returns:
        List of DER-encoded X.509 certificates.

    Raises:
        AuthError: If credentials are wrong.
        ServerError: If the server returned an error.
        RevenantError: If the response cannot be parsed.
    """
    try:
        root = ET.fromstring(xml_str)
    except _XMLParseError as e:
        _logger.exception("Invalid XML in enum-certificates response")
        safe_preview = _redact_and_truncate_xml(xml_str[:500])
        raise RevenantError(f"Invalid XML response: {e}\nRaw: {safe_preview}") from e

    result_major = None
    result_minor = None
    result_message = None
    certs_b64: list[str] = []

    for elem in root.iter():
        tag = _strip_namespace(elem.tag)
        text = (elem.text or "").strip()

        if tag == "ResultMajor" and text:
            result_major = text
        elif tag == "ResultMinor" and text:
            result_minor = text
        elif tag == "ResultMessage" and text:
            result_message = text
        elif tag == "AvailableCertificate" and text:
            certs_b64.append(text)

    if result_major and result_major.endswith(":Success"):
        certs: list[bytes] = []
        for cert_b64 in certs_b64:
            try:
                certs.append(base64.b64decode(cert_b64))
            except binascii.Error as e:  # noqa: PERF203 -- try-except skips individual malformed certificates
                _logger.warning("Skipping malformed certificate Base64: %s", e)
        _logger.debug("enum-certificates: %d certificates returned", len(certs))
        return certs

    msg = result_message or result_minor or result_major or "Unknown error"

    if _is_auth_error(result_minor, msg):
        _logger.warning("Authentication failed: %s", msg)
        raise AuthError(f"Authentication failed: {msg}")

    _logger.error("enum-certificates failed: %s", msg)
    raise ServerError(f"enum-certificates failed: {msg}")


@dataclass
class ServerVerifyResult:
    """Result of a server-side DssVerify operation.

    On success: valid=True, signer_name/sign_time/certificate_status populated.
    On failure: valid=False, error describes what went wrong.
    """

    valid: bool
    signer_name: str | None = None
    sign_time: str | None = None
    certificate_status: str | None = None
    error: str | None = None


def parse_verify_response(xml_str: str) -> ServerVerifyResult:
    """Parse a DssVerify SOAP response.

    Never raises -- returns a ServerVerifyResult with ``error`` set
    on any failure (malformed XML, server error, etc.).
    """
    try:
        root = ET.fromstring(xml_str)
    except _XMLParseError as e:
        _logger.exception("Invalid XML in verify response")
        return ServerVerifyResult(valid=False, error=f"Invalid XML response: {e}")

    result_major = None
    result_message = None
    signer_name = None
    sign_time = None
    cert_status = None

    for elem in root.iter():
        tag = _strip_namespace(elem.tag)
        text = (elem.text or "").strip()

        if tag == "ResultMajor" and text:
            result_major = text
        elif tag == "ResultMessage" and text:
            result_message = text
        elif tag == "SignedFieldInfo":
            signer_name = elem.get("SignerName")
            sign_time = elem.get("SignatureTime")
        elif tag == "FieldStatus":
            cert_status = elem.get("CertificateStatus")

    if result_major and result_major.endswith(":Success"):
        _logger.debug("Server verify success: signer=%s", signer_name)
        return ServerVerifyResult(
            valid=True,
            signer_name=signer_name,
            sign_time=sign_time,
            certificate_status=cert_status,
        )

    error_msg = result_message or "Server returned non-success result"
    _logger.warning("Server verify failed: %s", error_msg)
    return ServerVerifyResult(valid=False, error=error_msg)
