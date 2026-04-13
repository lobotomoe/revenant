# SPDX-License-Identifier: Apache-2.0
"""
ETSI Trust Service List (TSL) parser and cache.

Fetches and parses TSL XML documents (ETSI TS 119 612) to extract
trust anchor certificates.  Used for PKI chain validation against
a country's trusted CA list.
"""

from __future__ import annotations

import base64
import logging
import threading
import time
from dataclasses import dataclass

from ..constants import TSL_CACHE_TTL, TSL_FETCH_TIMEOUT

_logger = logging.getLogger(__name__)

# ETSI TSL XML namespace
_TSL_NS = "http://uri.etsi.org/02231/v2#"

# Service type URI suffixes that indicate a qualified CA
_CA_SERVICE_TYPE = "CA/QC"

# Active service status URI suffixes
_ACTIVE_STATUSES = frozenset({"granted", "accredited", "undersupervision"})


@dataclass(frozen=True, slots=True)
class TrustAnchor:
    """A trusted service entry extracted from a TSL."""

    subject_name: str
    service_name: str
    service_type: str
    status: str
    cert_der: bytes


@dataclass(frozen=True, slots=True)
class TrustStore:
    """Parsed trust anchors from a TSL, with metadata."""

    anchors: tuple[TrustAnchor, ...]
    ca_anchors: tuple[TrustAnchor, ...]
    scheme_operator: str
    tsl_url: str
    fetched_at: float


# ── XML helpers ──────────────────────────────────────────────────────


def _tag(local: str) -> str:
    """Build a namespaced tag for ElementTree lookup."""
    return f"{{{_TSL_NS}}}{local}"


def _text(el: object, path: str) -> str:
    """Extract text from a child element, or return empty string."""
    from xml.etree.ElementTree import Element

    if not isinstance(el, Element):
        return ""
    child = el.find(path)
    return (child.text or "").strip() if child is not None else ""


def _extract_service_type_suffix(uri: str) -> str:
    """Extract the meaningful suffix from a service type URI.

    Example: "http://uri.etsi.org/TrstSvc/Svctype/CA/QC" -> "CA/QC"
    """
    marker = "/Svctype/"
    idx = uri.find(marker)
    if idx >= 0:
        return uri[idx + len(marker) :]
    return uri


def _extract_status_suffix(uri: str) -> str:
    """Extract the status keyword from a status URI.

    Example: ".../Svcstatus/granted" -> "granted"
    """
    return uri.rsplit("/", 1)[-1] if "/" in uri else uri


def _is_active_status(status_suffix: str) -> bool:
    return status_suffix.lower() in _ACTIVE_STATUSES


# ── TSL parsing ──────────────────────────────────────────────────────


def parse_tsl(xml_bytes: bytes, tsl_url: str = "") -> TrustStore:
    """Parse an ETSI TSL XML document into a TrustStore.

    Pure function -- no I/O.  Uses defusedxml for safe parsing.

    Args:
        xml_bytes: Raw XML content.
        tsl_url: URL the TSL was fetched from (stored in result).

    Returns:
        TrustStore with all extracted trust anchors.

    Raises:
        ValueError: If the XML cannot be parsed.
    """
    import defusedxml.ElementTree as DET

    root = DET.fromstring(xml_bytes)

    # Scheme operator name
    operator_path = f"{_tag('SchemeInformation')}/{_tag('SchemeOperatorName')}/{_tag('Name')}"
    scheme_operator = _text(root, operator_path) or "Unknown"

    # Find all TSPService elements
    anchors: list[TrustAnchor] = []

    for svc_info in root.iter(_tag("ServiceInformation")):
        type_uri = _text(svc_info, _tag("ServiceTypeIdentifier"))
        service_type = _extract_service_type_suffix(type_uri)

        name_el = svc_info.find(f"{_tag('ServiceName')}/{_tag('Name')}")
        service_name = (name_el.text or "").strip() if name_el is not None else ""

        status_uri = _text(svc_info, _tag("ServiceStatus"))
        status = _extract_status_suffix(status_uri)

        if not _is_active_status(status):
            _logger.debug("Skipping inactive service %s (status=%s)", service_name, status)
            continue

        # Extract X509Certificate elements from DigitalId
        for digital_id in svc_info.iter(_tag("DigitalId")):
            cert_el = digital_id.find(_tag("X509Certificate"))
            if cert_el is None or not cert_el.text:
                continue

            cert_b64 = cert_el.text.strip()
            try:
                cert_der = base64.b64decode(cert_b64)
            except Exception:
                _logger.warning("Failed to decode certificate in service %s", service_name)
                continue

            # Extract subject name from sibling DigitalId if available
            subject_name = ""
            parent = svc_info.find(_tag("ServiceDigitalIdentity"))
            if parent is not None:
                for did in parent.iter(_tag("DigitalId")):
                    subj_el = did.find(_tag("X509SubjectName"))
                    if subj_el is not None and subj_el.text:
                        subject_name = subj_el.text.strip()
                        break

            anchors.append(
                TrustAnchor(
                    subject_name=subject_name,
                    service_name=service_name,
                    service_type=service_type,
                    status=status,
                    cert_der=cert_der,
                )
            )

    ca_anchors = tuple(a for a in anchors if a.service_type == _CA_SERVICE_TYPE)

    _logger.info(
        "Parsed TSL: %d anchors (%d CA), operator=%s",
        len(anchors),
        len(ca_anchors),
        scheme_operator,
    )

    return TrustStore(
        anchors=tuple(anchors),
        ca_anchors=ca_anchors,
        scheme_operator=scheme_operator,
        tsl_url=tsl_url,
        fetched_at=time.monotonic(),
    )


# ── Fetching ─────────────────────────────────────────────────────────


def fetch_trust_store(tsl_url: str, *, timeout: int = TSL_FETCH_TIMEOUT) -> TrustStore:
    """Fetch a TSL from a URL and parse it.

    Args:
        tsl_url: HTTPS URL of the TSL XML document.
        timeout: HTTP request timeout in seconds.

    Returns:
        Parsed TrustStore.

    Raises:
        RevenantError: On network or parse failure.
    """
    from ..network.transport import http_get

    _logger.info("Fetching TSL from %s", tsl_url)
    xml_bytes = http_get(tsl_url, timeout=timeout)
    return parse_tsl(xml_bytes, tsl_url=tsl_url)


# ── Cache ────────────────────────────────────────────────────────────

_cache: dict[str, TrustStore] = {}
_cache_lock = threading.Lock()


def get_trust_store(tsl_url: str, *, ttl: int = TSL_CACHE_TTL) -> TrustStore | None:
    """Get a cached TrustStore, fetching if needed.

    Returns None on fetch failure (logs warning, does not raise).

    Args:
        tsl_url: HTTPS URL of the TSL XML document.
        ttl: Cache time-to-live in seconds.

    Returns:
        TrustStore or None if unavailable.
    """
    now = time.monotonic()

    with _cache_lock:
        cached = _cache.get(tsl_url)
        if cached is not None and (now - cached.fetched_at) < ttl:
            return cached

    # Fetch outside the lock to avoid blocking other threads
    try:
        store = fetch_trust_store(tsl_url)
    except Exception:
        _logger.warning("Failed to fetch TSL from %s", tsl_url, exc_info=True)
        # Return stale cache if available
        with _cache_lock:
            return _cache.get(tsl_url)

    with _cache_lock:
        _cache[tsl_url] = store

    return store


def clear_cache() -> None:
    """Clear the TSL cache (for testing)."""
    with _cache_lock:
        _cache.clear()
