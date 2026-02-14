# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false
"""Legacy TLS transport using tlslite-ng.

Some CoSign appliances (notably EKENG's ca.gov.am) require TLSv1.0 with
RC4-MD5 -- a cipher suite removed from OpenSSL 3.x.  This module provides
a raw HTTP-over-TLS implementation using tlslite-ng's pure-Python TLS stack.

Used internally by ``transport.py`` when a host requires legacy TLS.
"""

from __future__ import annotations

import logging
import socket
import time
from typing import Literal
from urllib.parse import urlparse

from tlslite import HandshakeSettings, TLSConnection
from tlslite.errors import BaseTLSException

from ..constants import (
    BYTES_PER_MB,
    DEFAULT_TIMEOUT_LEGACY_TLS,
    MAX_RESPONSE_SIZE,
    RECV_BUFFER_SIZE,
)
from ..errors import RevenantError, TLSError

_logger = logging.getLogger(__name__)

# Standard HTTP(S) ports -- used to decide Host header format
_STANDARD_PORTS = (80, 443)


def make_legacy_settings() -> HandshakeSettings:
    """Build TLS 1.0 + RC4 handshake settings for legacy appliances."""
    settings = HandshakeSettings()
    settings.cipherNames = ["rc4"]
    settings.macNames = ["md5", "sha"]
    settings.minVersion = (3, 1)  # TLS 1.0
    # maxVersion left at default (3,4) -- server negotiates down to TLS 1.0
    return settings


def _parse_status_code(status_line: str) -> int:
    """Parse HTTP status code from a status line like 'HTTP/1.0 200 OK'.

    Raises:
        TLSError: If the status line cannot be parsed.
    """
    parts = status_line.split(maxsplit=2)
    if len(parts) >= 2:
        try:
            return int(parts[1])
        except ValueError:
            pass
    raise TLSError(f"Cannot parse HTTP status line: {status_line!r}")


def legacy_request(
    method: Literal["GET", "POST"],
    url: str,
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
    timeout: int = DEFAULT_TIMEOUT_LEGACY_TLS,
) -> bytes:
    """
    Send an HTTP request over legacy TLS (TLS 1.0 + RC4) using tlslite-ng.

    Used for appliances whose TLS stack requires RC4-MD5 -- a cipher
    removed from OpenSSL 3.x.

    Args:
        method: HTTP method (GET, POST).
        url: Target URL.
        body: Request body (for POST).
        headers: Additional HTTP headers.
        timeout: Socket timeout in seconds.

    Returns:
        Response body as bytes.

    Raises:
        TLSError: On connection or TLS handshake failures.
    """
    parsed = urlparse(url)
    host = parsed.hostname
    port = parsed.port or 443
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    if not host:
        raise TLSError(f"Invalid URL: {url}")

    _logger.debug("%s %s (host=%s, port=%d, timeout=%ds)", method, url, host, port, timeout)

    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except TimeoutError as exc:
        raise TLSError(
            f"Connection timed out after {timeout}s. Is the server reachable?",
            retryable=True,
        ) from exc
    except OSError as exc:
        raise TLSError(
            f"Cannot connect to {host}:{port}: {exc}",
            retryable=True,
        ) from exc

    try:
        tls = TLSConnection(sock)
        # IIS 5.1 closes TCP without sending TLS close_notify alert.
        # Without this flag, recv() raises TLSAbruptCloseError on last read.
        tls.ignoreAbruptClose = True
        # NOTE: tlslite-ng does NOT verify the server certificate by default.
        # This is a known limitation for legacy TLS connections.  The target
        # servers (EKENG ca.gov.am) are accessed over a government intranet
        # and require RC4-MD5 which precludes modern certificate validation.
        tls.handshakeClientCert(settings=make_legacy_settings())
        _logger.warning(
            "Using legacy TLS (TLS 1.0 + RC4) for %s:%d. "
            "This cipher suite is deprecated and only used for backward compatibility.",
            host,
            port,
        )

        response_body = _send_and_receive(tls, method, host, port, path, body, headers, timeout)
    except (TLSError, RevenantError):
        raise
    except TimeoutError as exc:
        raise TLSError(
            f"Connection timed out after {timeout}s. Is the server reachable?",
            retryable=True,
        ) from exc
    except (OSError, ConnectionError) as exc:
        raise TLSError(
            f"Connection to {host}:{port} failed: {exc}",
            retryable=True,
        ) from exc
    except BaseTLSException as exc:
        raise TLSError(f"TLS error with {host}:{port}: {exc}") from exc
    else:
        return response_body
    finally:
        sock.close()


def _validate_header_value(name: str, value: str) -> str:
    """Reject header values containing CR/LF to prevent HTTP header injection (CWE-113)."""
    if "\r" in value or "\n" in value:
        raise TLSError(f"HTTP header '{name}' contains invalid CR/LF characters")
    return value


def _send_and_receive(
    tls: TLSConnection,
    method: str,
    host: str,
    port: int,
    path: str,
    body: bytes | None,
    headers: dict[str, str] | None,
    timeout: int = DEFAULT_TIMEOUT_LEGACY_TLS,
) -> bytes:
    """Build HTTP request, send it, and parse the response.

    Args:
        tls: Established TLS connection.
        method: HTTP method.
        host: Target hostname.
        port: Target port.
        path: Request path (including query string).
        body: Request body (for POST).
        headers: Additional HTTP headers.
        timeout: Wall-clock timeout for the entire response read.

    Returns:
        Response body as bytes.

    Raises:
        TLSError: On protocol or size-limit violations.
        RevenantError: On non-2xx HTTP status.
    """
    # Build raw HTTP/1.0 request.  HTTP/1.0 avoids chunked encoding
    # and Expect:100-continue issues with IIS 5.1 on the EKENG appliance.
    host_header = f"{host}:{port}" if port not in _STANDARD_PORTS else host
    all_headers: dict[str, str] = {"Host": host_header, "Connection": "close"}
    if body is not None:
        all_headers["Content-Length"] = str(len(body))
    if headers:
        all_headers.update(headers)

    # Validate all header values to prevent CRLF injection (CWE-113).
    # Raw HTTP construction makes this critical -- unlike urllib which
    # validates internally, we build request bytes manually.
    header_lines = "".join(
        f"{k}: {_validate_header_value(k, v)}\r\n" for k, v in all_headers.items()
    )
    request_bytes = f"{method} {path} HTTP/1.0\r\n{header_lines}\r\n".encode()
    if body:
        request_bytes += body

    tls.sendall(request_bytes)

    # Read full response (server closes connection after HTTP/1.0)
    raw = _read_response(tls, host, port, timeout)

    # Split headers from body
    header_end = raw.find(b"\r\n\r\n")
    if header_end == -1:
        raise TLSError(f"Invalid HTTP response from {host}:{port}")

    response_body = raw[header_end + 4 :]
    status_line = raw[: raw.find(b"\r\n")].decode("utf-8", errors="replace")
    _logger.debug("%s -> %s (%d bytes)", method, status_line, len(response_body))

    # Validate HTTP status code
    status_code = _parse_status_code(status_line)
    if status_code < 200 or status_code >= 300:
        raise RevenantError(f"HTTP {status_code} from {host}:{port}: {status_line}")

    return response_body


def _read_response(
    tls: TLSConnection, host: str, port: int, timeout: int = DEFAULT_TIMEOUT_LEGACY_TLS
) -> bytes:
    """Read full TLS response with size limit and wall-clock timeout."""
    chunks: list[bytes] = []
    total_size = 0
    deadline = time.monotonic() + timeout
    while True:
        if time.monotonic() > deadline:
            raise TLSError(
                f"Response from {host}:{port} exceeded {timeout}s wall-clock timeout",
                retryable=True,
            )
        chunk = tls.recv(RECV_BUFFER_SIZE)
        if not chunk:
            break
        total_size += len(chunk)
        if total_size > MAX_RESPONSE_SIZE:
            raise TLSError(
                f"Response from {host}:{port} exceeds {MAX_RESPONSE_SIZE // BYTES_PER_MB} MB limit"
            )
        chunks.append(chunk)
    return b"".join(chunks)
