"""Tests for revenant.network.transport -- TLS mode cache, http_get, http_post."""

from unittest.mock import MagicMock, patch

import pytest
from tlslite.errors import BaseTLSException

from revenant.errors import RevenantError, TLSError
from revenant.network import legacy_tls, transport


def _make_urllib_response(data: bytes) -> MagicMock:
    """Build a mock urllib response that works with chunked read()."""
    mock = MagicMock()
    mock.read.side_effect = [data, b""]
    mock.__enter__ = MagicMock(return_value=mock)
    mock.__exit__ = MagicMock(return_value=False)
    return mock


@pytest.fixture(autouse=True)
def _clear_tls_cache():
    """Ensure clean TLS mode cache for each test."""
    transport._host_legacy_tls.clear()
    yield
    transport._host_legacy_tls.clear()


# ── register_host_tls / get_host_tls_info ────────────────────────────


def test_register_host_tls_legacy():
    transport.register_host_tls("ca.gov.am", True)
    assert transport.get_host_tls_info("ca.gov.am") == "Legacy TLS (RC4)"


def test_register_host_tls_standard():
    transport.register_host_tls("example.com", False)
    assert transport.get_host_tls_info("example.com") == "Standard HTTPS"


def test_get_host_tls_info_unknown():
    assert transport.get_host_tls_info("unknown.com") is None


# ── http_get (legacy path) ───────────────────────────────────────────


def test_http_get_legacy_success():
    transport.register_host_tls("example.com", True)
    with patch.object(transport, "legacy_request", return_value=b"response body"):
        result = transport.http_get("https://example.com:8080/path")
        assert result == b"response body"


def test_http_get_legacy_timeout():
    transport.register_host_tls("example.com", True)
    with (
        patch.object(
            transport,
            "legacy_request",
            side_effect=TLSError("Connection timed out", retryable=True),
        ),
        pytest.raises(TLSError, match="timed out"),
    ):
        transport.http_get("https://example.com:8080/path", max_retries=0)


def test_http_get_legacy_retries_on_transient_error():
    transport.register_host_tls("example.com", True)
    call_count = 0

    def _failing_then_ok(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count < 2:
            raise TLSError("Connection reset", retryable=True)
        return b"ok"

    with (
        patch.object(transport, "legacy_request", side_effect=_failing_then_ok),
        patch("time.sleep"),
    ):
        result = transport.http_get("https://example.com", max_retries=3)
        assert result == b"ok"
        assert call_count == 2


def test_http_get_legacy_no_retry_on_permanent_error():
    transport.register_host_tls("example.com", True)
    with (
        patch.object(
            transport,
            "legacy_request",
            side_effect=TLSError("TLS handshake failed", retryable=False),
        ),
        pytest.raises(TLSError, match="handshake"),
    ):
        transport.http_get("https://example.com", max_retries=3)


# ── http_get (urllib / standard path) ────────────────────────────────


def test_http_get_standard_success():
    transport.register_host_tls("ca.example.com", False)
    mock_response = _make_urllib_response(b"standard response")

    with patch.object(transport, "_safe_urlopen", return_value=mock_response):
        result = transport.http_get("https://ca.example.com/cert.crl")
        assert result == b"standard response"


def test_http_get_standard_failure():
    import urllib.error

    transport.register_host_tls("ca.example.com", False)
    with (
        patch.object(
            transport,
            "_safe_urlopen",
            side_effect=urllib.error.URLError("Connection refused"),
        ),
        pytest.raises(RevenantError, match="Connection refused"),
    ):
        transport.http_get("https://ca.example.com/cert.crl")


# ── http_get (auto-detect) ──────────────────────────────────────────


def test_http_get_auto_detect_standard():
    """Unknown host: urllib succeeds -> cache as standard."""
    mock_response = _make_urllib_response(b"auto response")

    with patch.object(transport, "_safe_urlopen", return_value=mock_response):
        result = transport.http_get("https://new-server.com/path")
        assert result == b"auto response"
    assert transport._host_legacy_tls["new-server.com"] is False


def test_http_get_auto_detect_legacy():
    """Pre-registered legacy host: urllib fails -> fallback to legacy, cache as legacy."""
    import urllib.error

    # Host must be pre-registered for legacy TLS fallback to occur
    transport.register_host_tls("old-server.com", True)

    with (
        patch.object(
            transport,
            "_safe_urlopen",
            side_effect=urllib.error.URLError("SSL error"),
        ),
        patch.object(transport, "legacy_request", return_value=b"legacy response"),
    ):
        result = transport.http_get("https://old-server.com/path")
        assert result == b"legacy response"
    assert transport._host_legacy_tls["old-server.com"] is True


def test_http_get_auto_detect_unknown_no_legacy_fallback():
    """Unknown host: urllib fails -> no silent fallback to legacy TLS."""
    import urllib.error

    with (
        patch.object(
            transport,
            "_safe_urlopen",
            side_effect=urllib.error.URLError("SSL error"),
        ),
        pytest.raises(TLSError, match="legacy TLS"),
    ):
        transport.http_get("https://unknown-server.com/path")


# ── http_post (legacy path) ─────────────────────────────────────────


def test_http_post_legacy_success():
    transport.register_host_tls("example.com", True)
    with patch.object(transport, "legacy_request", return_value=b"response") as mock_req:
        result = transport.http_post(
            "https://example.com:8080/api",
            b"request body",
            headers={"Content-Type": "text/xml"},
        )
        assert result == b"response"
        mock_req.assert_called_once_with(
            "POST",
            "https://example.com:8080/api",
            body=b"request body",
            headers={"Content-Type": "text/xml"},
            timeout=120,
        )


def test_http_post_legacy_timeout():
    transport.register_host_tls("example.com", True)
    with (
        patch.object(
            transport,
            "legacy_request",
            side_effect=TLSError("timed out", retryable=True),
        ),
        pytest.raises(TLSError, match="timed out"),
    ):
        transport.http_post("https://example.com", b"body", max_retries=0)


# ── http_post (standard path) ───────────────────────────────────────


def test_http_post_standard_success():
    transport.register_host_tls("standard.example.com", False)
    mock_response = _make_urllib_response(b"urllib post response")

    with patch.object(transport, "_safe_urlopen", return_value=mock_response):
        result = transport.http_post(
            "https://standard.example.com/api",
            b"request body",
            headers={"Content-Type": "text/xml"},
        )
        assert result == b"urllib post response"


def test_http_post_unknown_host_defaults_standard():
    """Unknown host: POST defaults to standard HTTPS."""
    mock_response = _make_urllib_response(b"default response")

    with patch.object(transport, "_safe_urlopen", return_value=mock_response):
        result = transport.http_post(
            "https://unknown.example.com/api",
            b"body",
        )
        assert result == b"default response"


# ── legacy_request internals ─────────────────────────────────────────


def test_legacy_request_invalid_url():
    with pytest.raises(TLSError, match="Invalid URL"):
        legacy_tls.legacy_request("GET", "not-a-url")


def test_legacy_request_connection_refused():
    with (
        patch("socket.create_connection", side_effect=OSError("Connection refused")),
        pytest.raises(TLSError, match="Cannot connect"),
    ):
        legacy_tls.legacy_request("GET", "https://unreachable.example.com:8080/path")


def test_legacy_request_socket_timeout():
    with (
        patch("socket.create_connection", side_effect=TimeoutError("timed out")),
        pytest.raises(TLSError, match="timed out") as exc_info,
    ):
        legacy_tls.legacy_request("GET", "https://example.com:8080/path")
    assert exc_info.value.retryable is True


def test_legacy_request_tls_handshake_failure():
    mock_sock = MagicMock()
    mock_tls = MagicMock()
    mock_tls.handshakeClientCert.side_effect = BaseTLSException("handshake failed")

    with (
        patch("socket.create_connection", return_value=mock_sock),
        patch.object(legacy_tls, "TLSConnection", return_value=mock_tls),
        pytest.raises(TLSError, match="TLS error"),
    ):
        legacy_tls.legacy_request("GET", "https://example.com:8080/path")
    mock_sock.close.assert_called_once()


def test_legacy_request_success():
    mock_sock = MagicMock()
    mock_tls = MagicMock()

    # Simulate HTTP/1.0 response: headers + body
    http_response = b"HTTP/1.0 200 OK\r\nContent-Type: text/xml\r\n\r\nresponse data"
    mock_tls.recv.side_effect = [http_response, b""]

    with (
        patch("socket.create_connection", return_value=mock_sock),
        patch.object(legacy_tls, "TLSConnection", return_value=mock_tls),
    ):
        result = legacy_tls.legacy_request(
            "POST",
            "https://example.com:8080/api?WSDL",
            body=b"body",
            headers={"X-Test": "1"},
        )
        assert result == b"response data"
        mock_tls.handshakeClientCert.assert_called_once()
        mock_tls.sendall.assert_called_once()

        # Verify the raw HTTP request contains the right parts
        sent_data = mock_tls.sendall.call_args[0][0]
        assert b"POST /api?WSDL HTTP/1.0\r\n" in sent_data
        assert b"X-Test: 1\r\n" in sent_data
        assert b"Host: example.com:8080\r\n" in sent_data
        assert sent_data.endswith(b"body")
        mock_sock.close.assert_called_once()


# ── _with_retry ──────────────────────────────────────────────────────


def test_retry_exhaustion():
    call_count = 0

    def _always_fail():
        nonlocal call_count
        call_count += 1
        raise TLSError("transient", retryable=True)

    with patch("time.sleep"), pytest.raises(TLSError, match="transient"):
        transport._with_retry(_always_fail, max_retries=2)
    # initial + 2 retries = 3 calls
    assert call_count == 3


def test_retry_exponential_backoff():
    delays = []

    def _always_fail():
        raise TLSError("transient", retryable=True)

    with patch("time.sleep", side_effect=lambda d: delays.append(d)), pytest.raises(TLSError):
        transport._with_retry(_always_fail, max_retries=3, delay=1.0, backoff=2.0)

    assert delays == [1.0, 2.0, 4.0]


# ── _require_https_url ──────────────────────────────────────────────


@pytest.mark.parametrize(
    "url",
    ["http://example.com", "ftp://example.com/path"],
    ids=["http", "ftp"],
)
def test_require_https_rejects_non_https(url):
    with pytest.raises(RevenantError, match="Only HTTPS URLs are allowed"):
        transport._require_https_url(url)


def test_require_https_accepts_https():
    transport._require_https_url("https://example.com")  # should not raise


# ── _resolve_host ───────────────────────────────────────────────────


def test_resolve_host_empty_hostname():
    with pytest.raises(RevenantError, match="Cannot extract hostname"):
        transport._resolve_host("https:///path")


# ── _is_retryable_error ────────────────────────────────────────────


def test_non_tls_error_not_retryable():
    assert transport._is_retryable_error(RevenantError("generic")) is False


def test_tls_error_non_retryable():
    assert transport._is_retryable_error(TLSError("permanent", retryable=False)) is False


def test_tls_error_retryable():
    assert transport._is_retryable_error(TLSError("transient", retryable=True)) is True


# ── _read_with_limit ────────────────────────────────────────────────


def test_read_with_limit_oversized():
    from revenant.constants import MAX_RESPONSE_SIZE

    mock_resp = MagicMock()
    # Return chunks that exceed the limit
    chunk_size = 1024 * 1024  # 1MB per chunk
    num_chunks = (MAX_RESPONSE_SIZE // chunk_size) + 2
    mock_resp.read.side_effect = [b"\x00" * chunk_size] * num_chunks

    with pytest.raises(RevenantError, match=r"exceeds.*limit"):
        transport._read_with_limit(mock_resp, "https://example.com")


# ── _urllib_get error paths ─────────────────────────────────────────


def test_http_get_ssl_error_raises_tls_error():
    import urllib.error

    transport.register_host_tls("ssl-fail.com", False)
    with (
        patch.object(
            transport,
            "_safe_urlopen",
            side_effect=urllib.error.URLError("SSL: CERTIFICATE_VERIFY_FAILED"),
        ),
        pytest.raises(TLSError, match="SSL error"),
    ):
        transport.http_get("https://ssl-fail.com/path", max_retries=0)


def test_http_get_timeout_raises_tls_error():
    transport.register_host_tls("timeout.com", False)
    with (
        patch.object(
            transport,
            "_safe_urlopen",
            side_effect=TimeoutError("timed out"),
        ),
        pytest.raises(TLSError, match="timed out"),
    ):
        transport.http_get("https://timeout.com/path", max_retries=0)


# ── _urllib_post error paths ────────────────────────────────────────


def test_http_post_url_error():
    import urllib.error

    transport.register_host_tls("post-fail.com", False)
    with (
        patch.object(
            transport,
            "_safe_urlopen",
            side_effect=urllib.error.URLError("Connection refused"),
        ),
        pytest.raises(RevenantError, match="POST failed"),
    ):
        transport.http_post("https://post-fail.com/api", b"body", max_retries=0)


def test_http_post_timeout():
    transport.register_host_tls("post-timeout.com", False)
    with (
        patch.object(
            transport,
            "_safe_urlopen",
            side_effect=TimeoutError("timed out"),
        ),
        pytest.raises(TLSError, match="timed out"),
    ):
        transport.http_post("https://post-timeout.com/api", b"body", max_retries=0)


# ── http_post max_retries=0 ────────────────────────────────────────


def test_http_post_no_retries():
    transport.register_host_tls("no-retry.com", False)
    mock_response = _make_urllib_response(b"no retry response")

    with patch.object(transport, "_safe_urlopen", return_value=mock_response):
        result = transport.http_post("https://no-retry.com/api", b"body", max_retries=0)
        assert result == b"no retry response"


# ── http_get max_retries=0 for standard host ───────────────────────


def test_http_get_standard_no_retries():
    transport.register_host_tls("std-host.com", False)
    mock_response = _make_urllib_response(b"no retry get")

    with patch.object(transport, "_safe_urlopen", return_value=mock_response):
        result = transport.http_get("https://std-host.com/path", max_retries=0)
        assert result == b"no retry get"


# ── auto-detect non-TLS error propagation ───────────────────────────


def test_auto_detect_propagates_non_tls_error():
    """Non-TLS RevenantError during auto-detect should propagate, not fall back."""
    with (
        patch.object(
            transport,
            "_urllib_get",
            side_effect=RevenantError("HTTP 403 Forbidden"),
        ),
        pytest.raises(RevenantError, match="403 Forbidden"),
    ):
        transport.http_get("https://forbidden-server.com/path")


# ── _parse_status_code edge cases ─────────────────────────────────


def test_parse_status_code_success():
    assert legacy_tls._parse_status_code("HTTP/1.0 200 OK") == 200


def test_parse_status_code_error():
    assert legacy_tls._parse_status_code("HTTP/1.1 500 Internal Server Error") == 500


def test_parse_status_code_no_reason():
    assert legacy_tls._parse_status_code("HTTP/1.0 204") == 204


def test_parse_status_code_malformed():
    with pytest.raises(TLSError, match="Cannot parse HTTP status"):
        legacy_tls._parse_status_code("garbage")


def test_parse_status_code_empty():
    with pytest.raises(TLSError, match="Cannot parse HTTP status"):
        legacy_tls._parse_status_code("")


def test_parse_status_code_non_numeric():
    with pytest.raises(TLSError, match="Cannot parse HTTP status"):
        legacy_tls._parse_status_code("HTTP/1.0 abc OK")


# ── CRLF injection prevention ─────────────────────────────────────


def test_validate_header_rejects_crlf():
    with pytest.raises(TLSError, match="invalid CR/LF"):
        legacy_tls._validate_header_value("X-Test", "value\r\nInjected: true")


def test_validate_header_rejects_newline():
    with pytest.raises(TLSError, match="invalid CR/LF"):
        legacy_tls._validate_header_value("X-Test", "value\nInjected: true")


def test_validate_header_accepts_clean_value():
    result = legacy_tls._validate_header_value("Content-Type", "text/xml; charset=utf-8")
    assert result == "text/xml; charset=utf-8"


# ── Non-2xx status handling ───────────────────────────────────────


def test_legacy_request_non_2xx_status():
    """HTTP 500 response should raise RevenantError."""
    mock_sock = MagicMock()
    mock_tls = MagicMock()

    http_response = b"HTTP/1.0 500 Internal Server Error\r\nContent-Type: text/xml\r\n\r\nerror"
    mock_tls.recv.side_effect = [http_response, b""]

    with (
        patch("socket.create_connection", return_value=mock_sock),
        patch.object(legacy_tls, "TLSConnection", return_value=mock_tls),
        pytest.raises(RevenantError, match="HTTP 500"),
    ):
        legacy_tls.legacy_request("GET", "https://example.com/path")


# ── _SafeRedirectHandler ────────────────────────────────────────


def test_safe_redirect_refuses_https_to_http():
    """Redirect from HTTPS to HTTP should raise RevenantError."""
    import urllib.request

    handler = transport._SafeRedirectHandler()
    req = urllib.request.Request("https://example.com/path")
    with pytest.raises(RevenantError, match="Refused redirect from HTTPS to HTTP"):
        handler.redirect_request(
            req, MagicMock(), 301, "Moved", MagicMock(), "http://evil.com/steal"
        )


def test_safe_redirect_allows_https_to_https():
    """Redirect from HTTPS to HTTPS should be allowed."""
    import urllib.request

    handler = transport._SafeRedirectHandler()
    req = urllib.request.Request("https://example.com/old")
    # Should not raise -- returns a new Request object
    result = handler.redirect_request(
        req, MagicMock(), 301, "Moved", MagicMock(), "https://example.com/new"
    )
    assert result is not None
