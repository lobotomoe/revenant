"""
Network-level server discovery for CoSign setup.

Provides server ping (WSDL check).  For identity discovery and
cert extraction, see ``revenant.core.cert_info``.
"""

from __future__ import annotations

__all__ = [
    "ping_server",
]

from ..constants import DEFAULT_TIMEOUT_HTTP_GET
from ..errors import RevenantError, TLSError
from .transport import http_get

# ── Server ping ──────────────────────────────────────────────────────


def ping_server(url: str, timeout: int = DEFAULT_TIMEOUT_HTTP_GET) -> tuple[bool, str]:
    """
    Check if a URL points to a CoSign DSS endpoint by fetching its WSDL.

    TLS mode (standard or legacy) is auto-detected by the transport layer
    based on the target host.  No authentication required.

    Args:
        url: SOAP endpoint URL (e.g. ``https://host:port/SAPIWS/DSS.asmx``).
        timeout: HTTP timeout in seconds.

    Returns:
        (ok, info) where *ok* is bool and *info* is a status string.
    """
    wsdl_url = url.rstrip("/")
    if "?" not in wsdl_url:
        wsdl_url += "?WSDL"

    try:
        raw = http_get(wsdl_url, timeout=timeout)
    except TLSError as exc:
        return False, str(exc)
    except RevenantError as exc:
        return False, f"Connection failed: {exc}"

    body = raw.decode("utf-8", errors="replace")

    # Check for CoSign/DSS markers in the WSDL
    if "DssSign" in body and "SAPIWS" in body:
        return True, "CoSign DSS endpoint confirmed"

    if "<wsdl:" in body or "<definitions" in body:
        return True, "WSDL found (may not be CoSign)"

    return False, "Not a recognized CoSign endpoint"
