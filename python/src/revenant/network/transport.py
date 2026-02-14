"""
HTTP transport for CoSign.

Some CoSign appliances (notably EKENG's ca.gov.am) require TLSv1.0 with
RC4-MD5 -- a cipher suite removed from OpenSSL 3.x.  This module auto-detects
the TLS mode for each host on first contact:

- **Standard HTTPS** via ``urllib.request`` (fast, uses system SSL).
- **Legacy TLS** via ``tlslite-ng`` (pure-Python, supports RC4).

TLS mode can be pre-registered via config.register_active_profile_tls() to
skip the auto-detection probe.

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


# ── Per-host TLS mode cache ──────────────────────────────────────────
#
# Maps hostname -> True (legacy TLS needed) or False (standard HTTPS).
# Populated either by register_host_tls() for known servers, or by
# auto-detection in http_get() on first contact with an unknown host.

_host_legacy_tls: dict[str, bool] = {}


def register_host_tls(host: str, legacy: bool) -> None:
    """
    Pre-register a host's TLS requirement.

    This is a low-level function used by the config layer. UI code should
    call config.register_active_profile_tls() instead.

    Args:
        host: Hostname (e.g. "ca.gov.am").
        legacy: True if the host requires legacy TLS (tlslite-ng),
            False for standard HTTPS.
    """
    _host_legacy_tls[host] = legacy
    _logger.debug("Registered TLS mode for %s: %s", host, "legacy" if legacy else "standard")


def get_host_tls_info(host: str) -> str | None:
    """
    Get a human-readable TLS mode description for a host.

    Returns:
        "Legacy TLS (RC4)", "Standard HTTPS", or None if not yet detected.
    """
    mode = _host_legacy_tls.get(host)
    if mode is None:
        return None
    return "Legacy TLS (RC4)" if mode else "Standard HTTPS"


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
        raise RevenantError(f"HTTP POST failed: {url}: {exc}") from exc
    except TimeoutError as exc:
        raise TLSError(
            f"Connection timed out after {timeout}s: {url}",
            retryable=True,
        ) from exc


# ── Auto-detection ───────────────────────────────────────────────────


def _auto_detect_get(url: str, host: str, timeout: int) -> bytes:
    """
    Try standard HTTPS first; if SSL fails, fall back to legacy TLS.

    Only falls back on connection/TLS errors. Auth and server errors
    are propagated immediately -- falling back to a different transport
    won't fix bad credentials or server-side rejections.

    Legacy TLS fallback is only attempted for hosts that have been
    pre-registered via register_host_tls(). Unknown hosts that fail
    standard HTTPS will not silently downgrade to insecure legacy TLS.

    Caches the result for future requests to the same host.
    """
    try:
        result = _urllib_get(url, timeout=timeout)
    except TLSError:
        _logger.debug("Standard HTTPS failed for %s", host)
    except RevenantError:
        # Non-TLS errors (HTTP 4xx/5xx, auth errors, etc.) -- don't fall back.
        # If standard HTTPS connected but the server rejected the request,
        # legacy TLS won't help.
        raise
    else:
        _host_legacy_tls[host] = False
        _logger.info("Auto-detected TLS for %s: standard HTTPS", host)
        return result

    # Only attempt legacy TLS if this host was pre-registered as legacy.
    # Never silently downgrade to unverified TLS for unknown hosts.
    if host not in _host_legacy_tls:
        raise TLSError(
            f"HTTPS connection to {host} failed. If this server requires "
            f"legacy TLS (RC4), register it via server profile configuration.",
            retryable=False,
        )

    result = legacy_request("GET", url, timeout=timeout)
    _host_legacy_tls[host] = True
    _logger.info("Auto-detected TLS for %s: legacy TLS (RC4)", host)
    return result


# ── Public API ───────────────────────────────────────────────────────


def http_get(
    url: str,
    *,
    timeout: int = DEFAULT_TIMEOUT_HTTP_GET,
    max_retries: int = DEFAULT_MAX_RETRIES,
) -> bytes:
    """
    Fetch a URL with automatic TLS mode detection and retry.

    TLS mode is resolved per-host: pre-registered hosts use their known
    mode; unknown hosts are probed (standard HTTPS first, then legacy).

    Args:
        url: Target URL.
        timeout: HTTP timeout in seconds.
        max_retries: Maximum retry attempts on transient failures.

    Returns:
        Response body as bytes.

    Raises:
        TLSError: On connection/TLS issues.
        RevenantError: On HTTP failures.
    """
    _require_https_url(url)
    host = _resolve_host(url)
    legacy = _host_legacy_tls.get(host)

    # Unknown host -- auto-detect on first request
    if legacy is None:
        return _auto_detect_get(url, host, timeout)

    # Known standard host -- with retry on transient failures
    if not legacy:

        def _do_std_get() -> bytes:
            return _urllib_get(url, timeout=timeout)

        if max_retries > 0:
            return _with_retry(_do_std_get, max_retries=max_retries, operation=f"GET {url}")
        return _do_std_get()

    # Known legacy host -- with retry
    def _do_get() -> bytes:
        return legacy_request("GET", url, timeout=timeout)

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
    Send an HTTP POST with automatic TLS mode selection and retry.

    The host's TLS mode must already be known (via register_host_tls or
    a prior http_get auto-detection).  Unknown hosts default to standard
    HTTPS.

    Args:
        url: Target URL.
        body: Request body bytes.
        headers: Additional HTTP headers.
        timeout: HTTP timeout in seconds.
        max_retries: Maximum retry attempts on transient failures.

    Returns:
        Response body as bytes.

    Raises:
        TLSError: On connection/TLS issues.
        RevenantError: On HTTP failures.
    """
    _require_https_url(url)
    host = _resolve_host(url)
    legacy = _host_legacy_tls.get(host, False)

    def _do_post() -> bytes:
        if not legacy:
            return _urllib_post(url, body, headers=headers, timeout=timeout)
        return legacy_request("POST", url, body=body, headers=headers, timeout=timeout)

    if max_retries > 0:
        return _with_retry(_do_post, max_retries=max_retries, operation=f"POST {url}")
    return _do_post()
