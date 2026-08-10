# SPDX-License-Identifier: Apache-2.0
"""
HTTP transport for CoSign.

Some CoSign appliances require TLSv1.0 with RC4-MD5 -- a cipher suite removed
from OpenSSL 3.x -- and are reached through ``tlslite-ng`` instead of the
system SSL stack.  Everything else goes over standard HTTPS via
``urllib.request``.

Which of the two a host gets is declared, never inferred.  A profile that
needs the legacy transport says so and names the server's pinned key; a host
nobody declared is reached over standard HTTPS or not at all.  Falling back to
the legacy transport when standard HTTPS fails would mean answering a failed
certificate check -- the one signal that something is wrong -- by switching to
a transport that performs no certificate check, which is why no such fallback
exists.

Public API:
- http_get / http_post for HTTP requests
- get_host_tls_info for TLS mode information
- Automatic retry with exponential backoff
"""

from __future__ import annotations

__all__ = ["get_host_tls_info", "http_get", "http_post", "register_host_tls"]

import logging
import time
import urllib.error
import urllib.request
from typing import TYPE_CHECKING, Protocol, TypeVar
from urllib.parse import urlparse

from ..constants import (
    BYTES_PER_MB,
    DEFAULT_MAX_RETRIES,
    DEFAULT_RETRY_BACKOFF,
    DEFAULT_RETRY_DELAY,
    DEFAULT_TIMEOUT_HTTP_GET,
    DEFAULT_TIMEOUT_HTTP_POST,
    MAX_RESPONSE_SIZE,
    RECV_BUFFER_SIZE,
)
from ..errors import RevenantError, TLSError
from .legacy_tls import legacy_request

if TYPE_CHECKING:
    import http.client
    from collections.abc import Callable

_T = TypeVar("_T")

_logger = logging.getLogger(__name__)


# ── Per-host TLS mode registry ───────────────────────────────────────
#
# Maps hostname -> the pinned keys the legacy transport must see there.
# A host is present only because a profile declared it; absence means
# standard HTTPS.

_host_legacy_pins: dict[str, tuple[str, ...]] = {}


def register_host_tls(host: str, legacy: bool, pins: tuple[str, ...] = ()) -> None:
    """
    Register a host's declared TLS requirement.

    This is a low-level function used by the config layer. UI code should
    call config.register_active_profile_tls() instead.

    Args:
        host: Hostname (e.g. "ca.gov.am").
        legacy: True if the host requires legacy TLS (tlslite-ng),
            False for standard HTTPS.
        pins: Accepted server keys for the legacy transport.

    Raises:
        TLSError: If legacy TLS is declared without a pinned key.
    """
    if not legacy:
        _host_legacy_pins.pop(host, None)
        _logger.debug("Registered TLS mode for %s: standard", host)
        return
    if not pins:
        raise TLSError(
            f"Legacy TLS was declared for {host} without a pinned server key. "
            "That transport cannot authenticate the server on its own, so a "
            "pin is required."
        )
    _host_legacy_pins[host] = pins
    _logger.debug("Registered TLS mode for %s: legacy, %d pinned key(s)", host, len(pins))


def get_host_tls_info(host: str) -> str:
    """
    Get a human-readable TLS mode description for a host.

    Returns:
        "Legacy TLS (RC4, pinned key)" for a declared legacy host,
        "Standard HTTPS" otherwise.
    """
    if host in _host_legacy_pins:
        return "Legacy TLS (RC4, pinned key)"
    return "Standard HTTPS"


def _resolve_host(url: str) -> str:
    """Extract hostname from URL.

    Raises:
        RevenantError: If the URL has no hostname.
    """
    host = urlparse(url).hostname
    if not host:
        raise RevenantError(f"Cannot extract hostname from URL: {url}")
    return host


def _require_https_url(url: str) -> None:
    """Reject non-HTTPS URLs to prevent credential leakage over plaintext.

    Raises:
        RevenantError: If the URL scheme is not https.
    """
    scheme = urlparse(url).scheme.lower()
    if scheme != "https":
        raise RevenantError(
            f"Only HTTPS URLs are allowed (got {scheme}://). "
            "Credentials must not be sent over unencrypted connections."
        )


# ── Retry logic ──────────────────────────────────────────────────────


def _is_retryable_error(exc: RevenantError) -> bool:
    """Check if an error is transient and worth retrying."""
    if isinstance(exc, TLSError):
        return exc.retryable
    return False


def _with_retry(
    fn: Callable[[], _T],
    max_retries: int = DEFAULT_MAX_RETRIES,
    delay: float = DEFAULT_RETRY_DELAY,
    backoff: float = DEFAULT_RETRY_BACKOFF,
    operation: str = "request",
) -> _T:
    """
    Execute a function with exponential backoff retry.

    Args:
        fn: Function to execute (takes no arguments, returns result).
        max_retries: Maximum number of retry attempts.
        delay: Initial delay between retries in seconds.
        backoff: Multiplier for delay after each retry.
        operation: Description of operation for logging.

    Returns:
        Result from successful fn() call.

    Raises:
        Last exception if all retries fail.
    """
    last_exc: RevenantError | None = None
    current_delay = delay

    for attempt in range(max_retries + 1):
        try:
            return fn()
        except RevenantError as exc:  # noqa: PERF203 -- try-except is the retry mechanism
            last_exc = exc
            if attempt >= max_retries or not _is_retryable_error(exc):
                raise

            _logger.warning(
                "%s failed (attempt %d/%d): %s. Retrying in %.1fs...",
                operation.capitalize(),
                attempt + 1,
                max_retries + 1,
                exc,
                current_delay,
            )
            time.sleep(current_delay)
            current_delay *= backoff

    # Should not reach here, but satisfy type checker
    if last_exc is not None:
        raise last_exc
    raise RuntimeError("Retry logic error")


# ── Standard HTTPS (urllib) ──────────────────────────────────────────


class _Readable(Protocol):
    def read(self, amt: int = ...) -> bytes: ...


def _read_with_limit(response: _Readable, url: str) -> bytes:
    """Read an HTTP response body with size limit to prevent memory exhaustion."""
    chunks: list[bytes] = []
    total_size = 0
    while True:
        chunk = response.read(RECV_BUFFER_SIZE)
        if not chunk:
            break
        total_size += len(chunk)
        if total_size > MAX_RESPONSE_SIZE:
            raise RevenantError(
                f"Response from {url} exceeds {MAX_RESPONSE_SIZE // BYTES_PER_MB} MB limit"
            )
        chunks.append(chunk)
    return b"".join(chunks)


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Redirect handler that refuses HTTPS to HTTP downgrades."""

    def redirect_request(  # type: ignore[override]  # urllib stubs use incompatible signature
        self,
        req: urllib.request.Request,
        fp: http.client.HTTPResponse,
        code: int,
        msg: str,
        headers: http.client.HTTPMessage,
        newurl: str,
    ) -> urllib.request.Request | None:
        parsed_orig = urlparse(req.full_url)
        parsed_new = urlparse(newurl)
        if parsed_orig.scheme == "https" and parsed_new.scheme == "http":
            raise RevenantError(f"Refused redirect from HTTPS to HTTP: {newurl}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_safe_opener = urllib.request.build_opener(_SafeRedirectHandler)


def _safe_urlopen(
    url_or_request: str | urllib.request.Request, *, timeout: int
) -> http.client.HTTPResponse:
    """Open a URL/Request with safe redirect handling.

    Refuses HTTPS to HTTP downgrades. Thin wrapper to simplify testing.
    """
    return _safe_opener.open(url_or_request, timeout=timeout)


def _urllib_get(url: str, timeout: int = DEFAULT_TIMEOUT_HTTP_GET) -> bytes:
    """Fetch a URL via urllib.request (standard HTTPS)."""
    _logger.debug("GET %s (urllib, timeout=%ds)", url, timeout)
    try:
        with _safe_urlopen(url, timeout=timeout) as response:
            data = _read_with_limit(response, url)
            _logger.debug("GET %s -> %d bytes", url, len(data))
            return data
    except urllib.error.URLError as exc:
        # SSL errors should be TLSError so auto-detect can fall back to legacy
        reason = str(exc.reason) if exc.reason else str(exc)
        if "ssl" in reason.lower() or "certificate" in reason.lower():
            raise TLSError(
                f"SSL error: {url}: {exc}",
                retryable=True,
            ) from exc
        raise RevenantError(f"HTTP request failed: {url}: {exc}") from exc
    except TimeoutError as exc:
        raise TLSError(
            f"Connection timed out after {timeout}s: {url}",
            retryable=True,
        ) from exc


def _urllib_post(
    url: str,
    body: bytes,
    headers: dict[str, str] | None = None,
    timeout: int = DEFAULT_TIMEOUT_HTTP_POST,
) -> bytes:
    """Send a POST via urllib.request (standard HTTPS)."""
    _logger.debug("POST %s (urllib, timeout=%ds, %d bytes)", url, timeout, len(body))
    req = urllib.request.Request(url, data=body, method="POST")  # noqa: S310 -- URL is validated as HTTPS by _require_https_url in caller
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    try:
        with _safe_urlopen(req, timeout=timeout) as response:
            data = _read_with_limit(response, url)
            _logger.debug("POST %s -> %d bytes", url, len(data))
            return data
    except urllib.error.URLError as exc:
        reason = str(exc.reason) if exc.reason else str(exc)
        if "ssl" in reason.lower() or "certificate" in reason.lower():
            raise TLSError(
                f"SSL error: {url}: {exc}",
                retryable=True,
            ) from exc
        raise RevenantError(f"HTTP POST failed: {url}: {exc}") from exc
    except TimeoutError as exc:
        raise TLSError(
            f"Connection timed out after {timeout}s: {url}",
            retryable=True,
        ) from exc


# ── Public API ───────────────────────────────────────────────────────


def http_get(
    url: str,
    *,
    timeout: int = DEFAULT_TIMEOUT_HTTP_GET,
    max_retries: int = DEFAULT_MAX_RETRIES,
) -> bytes:
    """
    Fetch a URL over the transport its host was registered with.

    Hosts a profile declared as legacy use tlslite-ng against their pinned
    key; every other host uses standard HTTPS. A standard HTTPS failure is
    reported, never answered by retrying without certificate validation.

    Args:
        url: Target URL.
        timeout: HTTP timeout in seconds.
        max_retries: Maximum retry attempts on transient failures.

    Returns:
        Response body as bytes.

    Raises:
        TLSError: On connection/TLS issues, or if a pinned key does not match.
        RevenantError: On HTTP failures.
    """
    _require_https_url(url)
    host = _resolve_host(url)
    pins = _host_legacy_pins.get(host)

    def _do_get() -> bytes:
        if pins is None:
            return _urllib_get(url, timeout=timeout)
        return legacy_request("GET", url, timeout=timeout, pins=pins)

    if max_retries > 0:
        return _with_retry(_do_get, max_retries=max_retries, operation=f"GET {url}")
    return _do_get()


def http_post(
    url: str,
    body: bytes,
    *,
    headers: dict[str, str] | None = None,
    timeout: int = DEFAULT_TIMEOUT_HTTP_POST,
    max_retries: int = DEFAULT_MAX_RETRIES,
) -> bytes:
    """
    Send an HTTP POST over the transport its host was registered with.

    Hosts a profile declared as legacy use tlslite-ng against their pinned
    key; every other host uses standard HTTPS. A standard HTTPS failure is
    reported, never answered by retrying without certificate validation.

    Args:
        url: Target URL.
        body: Request body bytes.
        headers: Additional HTTP headers.
        timeout: HTTP timeout in seconds.
        max_retries: Maximum retry attempts on transient failures.

    Returns:
        Response body as bytes.

    Raises:
        TLSError: On connection/TLS issues, or if a pinned key does not match.
        RevenantError: On HTTP failures.
    """
    _require_https_url(url)
    host = _resolve_host(url)
    pins = _host_legacy_pins.get(host)

    def _do_post() -> bytes:
        if pins is None:
            return _urllib_post(url, body, headers=headers, timeout=timeout)
        return legacy_request("POST", url, body=body, headers=headers, timeout=timeout, pins=pins)

    if max_retries > 0:
        return _with_retry(_do_post, max_retries=max_retries, operation=f"POST {url}")
    return _do_post()
