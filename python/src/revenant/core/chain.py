# SPDX-License-Identifier: Apache-2.0
# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false
"""
PKI certificate chain validation against a Trust Service List.

Extracts all certificates from a CMS SignedData blob, builds the
certificate chain, and validates it against trust anchors from a TSL.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import datetime

from ..constants import MAX_AIA_FETCHES
from .tsl import TrustStore, get_trust_store

_logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class ChainResult:
    """Result of PKI certificate chain validation."""

    chain_valid: bool | None
    trust_anchor: str | None
    chain_depth: int
    details: list[str] = field(default_factory=list)


# ── Certificate extraction from CMS ─────────────────────────────────


def _extract_all_certs_from_cms(cms_der: bytes) -> list[object]:
    """Extract all X.509 certificates from a CMS SignedData blob.

    Returns a list of asn1crypto.x509.Certificate objects.
    """
    from asn1crypto import cms as asn1_cms

    ci = asn1_cms.ContentInfo.load(cms_der)
    signed_data = ci["content"]
    certs_set = signed_data["certificates"]

    if certs_set is None:
        return []

    result = []
    for i in range(len(certs_set)):
        choice = certs_set[i]
        if choice.name == "certificate":
            result.append(choice.chosen)
    return result


def _get_ski(cert: object) -> bytes | None:
    """Get Subject Key Identifier from a cert."""
    ski_val = cert.key_identifier_value  # pyright: ignore[reportAttributeAccessIssue]
    if ski_val is not None:
        raw = ski_val.native  # pyright: ignore[reportAttributeAccessIssue]
        return bytes(raw) if raw else None
    return None


def _get_aki_key_id(cert: object) -> bytes | None:
    """Get Authority Key Identifier key_id from a cert."""
    aki_val = cert.authority_key_identifier_value  # pyright: ignore[reportAttributeAccessIssue]
    if aki_val is not None:
        key_id = aki_val["key_identifier"].native  # pyright: ignore[reportIndexIssue]
        return bytes(key_id) if key_id else None
    return None


def _get_subject_dn(cert: object) -> str:
    """Get human-readable subject DN."""
    return cert.subject.human_friendly  # pyright: ignore[reportAttributeAccessIssue]


def _get_issuer_dn(cert: object) -> str:
    """Get human-readable issuer DN."""
    return cert.issuer.human_friendly  # pyright: ignore[reportAttributeAccessIssue]


def _is_self_signed(cert: object) -> bool:
    """Check if a cert is self-signed."""
    return cert.self_signed in ("maybe", True)  # pyright: ignore[reportAttributeAccessIssue]


# ── AIA fetching ─────────────────────────────────────────────────────


def _get_aia_ca_issuer_urls(cert: object) -> list[str]:
    """Extract CA issuer URLs from the Authority Information Access extension."""
    aia = cert.authority_information_access_value  # pyright: ignore[reportAttributeAccessIssue]
    if aia is None:
        return []

    urls: list[str] = []
    for desc in aia:
        method = desc["access_method"].native
        if method == "ca_issuers":
            loc = desc["access_location"]
            if loc.name == "uniform_resource_identifier":
                urls.append(loc.chosen.native)
    return urls


def _fetch_intermediate_cert(url: str) -> object | None:
    """Fetch a single intermediate CA certificate via AIA URL.

    Returns an asn1crypto.x509.Certificate or None on failure.
    """
    from asn1crypto import x509 as asn1_x509

    from ..network.transport import http_get

    try:
        _logger.debug("Fetching intermediate cert from %s", url)
        cert_der = http_get(url, timeout=15)
        return asn1_x509.Certificate.load(cert_der)
    except Exception:
        _logger.debug("Failed to fetch intermediate from %s", url, exc_info=True)
        return None


# ── Chain building ───────────────────────────────────────────────────


def _build_chain(
    leaf: object,
    pool: list[object],
) -> list[object]:
    """Build a certificate chain from leaf to root using SKI/AKI matching.

    Fetches missing intermediates via AIA if needed.

    Args:
        leaf: The end-entity (signer) certificate.
        pool: All certificates available (from CMS + trust store).

    Returns:
        Ordered chain from leaf to root (or as far as we could build).
    """
    chain = [leaf]
    current = leaf
    fetched = 0

    for _ in range(20):  # safety limit
        if _is_self_signed(current):
            break

        aki = _get_aki_key_id(current)
        if aki is None:
            break

        # Search pool for issuer by SKI match
        issuer = None
        for candidate in pool:
            candidate_ski = _get_ski(candidate)
            if candidate_ski == aki and candidate is not current:
                issuer = candidate
                break

        # If not found in pool, try AIA
        if issuer is None and fetched < MAX_AIA_FETCHES:
            for url in _get_aia_ca_issuer_urls(current):
                fetched_cert = _fetch_intermediate_cert(url)
                if fetched_cert is not None:
                    fetched += 1
                    pool.append(fetched_cert)
                    fetched_ski = _get_ski(fetched_cert)
                    if fetched_ski == aki:
                        issuer = fetched_cert
                        break

        if issuer is None:
            break

        chain.append(issuer)
        current = issuer

    return chain


# ── Chain validation ─────────────────────────────────────────────────


def _validate_with_cryptography(
    leaf_der: bytes,
    intermediate_ders: list[bytes],
    anchor_ders: list[bytes],
    check_time: datetime.datetime | None = None,
) -> bool:
    """Validate a certificate chain using the cryptography library.

    Args:
        leaf_der: DER-encoded leaf certificate.
        intermediate_ders: DER-encoded intermediate certificates.
        anchor_ders: DER-encoded trust anchor certificates.
        check_time: Time to validate against (None = now).

    Returns:
        True if chain is valid.

    Raises:
        Exception: On validation failure or unsupported cert format.
    """
    from cryptography.x509 import load_der_x509_certificate
    from cryptography.x509 import verification as x509_verify

    anchors = [load_der_x509_certificate(d) for d in anchor_ders]
    store = x509_verify.Store(anchors)

    builder = x509_verify.PolicyBuilder().store(store)
    if check_time is not None:
        builder = builder.time(check_time)

    verifier = builder.build_client_verifier()

    leaf_cert = load_der_x509_certificate(leaf_der)
    intermediates = [load_der_x509_certificate(d) for d in intermediate_ders]

    verifier.verify(leaf_cert, intermediates)
    return True


def _find_matching_anchor(
    chain: list[object],
    trust_store: TrustStore,
) -> str | None:
    """Find which trust anchor the chain terminates at.

    Returns the service name of the matching anchor, or None.
    """
    if not chain:
        return None

    # Check each cert in the chain against CA anchors by SKI
    for cert in chain:
        cert_ski = _get_ski(cert)
        if cert_ski is None:
            continue
        for anchor in trust_store.ca_anchors:
            from asn1crypto import x509 as asn1_x509

            anchor_cert = asn1_x509.Certificate.load(anchor.cert_der)
            anchor_ski = _get_ski(anchor_cert)
            if anchor_ski == cert_ski:
                return anchor.service_name

    # Fallback: check by issuer DN matching
    for cert in chain:
        issuer_dn = _get_issuer_dn(cert)
        for anchor in trust_store.ca_anchors:
            if anchor.subject_name and anchor.subject_name in issuer_dn:
                return anchor.service_name

    return None


# ── Public API ───────────────────────────────────────────────────────


def validate_chain(
    cms_der: bytes,
    trust_store: TrustStore,
) -> ChainResult:
    """Validate the certificate chain in a CMS blob against a trust store.

    Args:
        cms_der: DER-encoded CMS/PKCS#7 blob.
        trust_store: Parsed trust anchors.

    Returns:
        ChainResult with validation outcome.
    """
    details: list[str] = []

    # Extract all certs from CMS
    try:
        cms_certs = _extract_all_certs_from_cms(cms_der)
    except Exception:
        _logger.debug("Failed to extract certs from CMS", exc_info=True)
        return ChainResult(
            chain_valid=None,
            trust_anchor=None,
            chain_depth=0,
            details=["Chain: failed to parse CMS certificates"],
        )

    if not cms_certs:
        return ChainResult(
            chain_valid=None,
            trust_anchor=None,
            chain_depth=0,
            details=["Chain: no certificates in CMS"],
        )

    leaf = cms_certs[0]
    details.append(f"Chain: signer cert: {_get_subject_dn(leaf)}")

    # Build the pool: CMS certs + trust anchor certs
    from asn1crypto import x509 as asn1_x509

    pool = list(cms_certs)
    pool.extend(asn1_x509.Certificate.load(a.cert_der) for a in trust_store.ca_anchors)

    # Build the chain
    chain = _build_chain(leaf, pool)
    chain_depth = len(chain)
    subjects = [_get_subject_dn(c) for c in chain]

    if chain_depth > 1:
        details.append(f"Chain: depth {chain_depth}: {' -> '.join(subjects)}")

    # Find matching trust anchor
    anchor_name = _find_matching_anchor(chain, trust_store)

    if anchor_name is None:
        details.append(f"Chain: no trusted CA found (operator: {trust_store.scheme_operator})")
        return ChainResult(
            chain_valid=False, trust_anchor=None, chain_depth=chain_depth, details=details
        )

    # Cryptographic chain verification
    try:
        leaf_der = leaf.dump()  # pyright: ignore[reportAttributeAccessIssue]
        intermediate_ders = [c.dump() for c in chain[1:]]  # pyright: ignore[reportAttributeAccessIssue]
        anchor_ders = [a.cert_der for a in trust_store.ca_anchors]

        _validate_with_cryptography(leaf_der, intermediate_ders, anchor_ders)
        details.append(f"Chain: trusted ({anchor_name}, {trust_store.scheme_operator})")
        return ChainResult(
            chain_valid=True, trust_anchor=anchor_name, chain_depth=chain_depth, details=details
        )
    except Exception as exc:
        _logger.debug("Cryptographic chain verification failed: %s", exc)
        # Fallback: trust based on SKI/AKI match alone
        details.append(
            f"Chain: anchor matched ({anchor_name}) but cryptographic verification failed"
        )
        return ChainResult(
            chain_valid=None, trust_anchor=anchor_name, chain_depth=chain_depth, details=details
        )


def validate_chain_for_profile(
    cms_der: bytes,
    tsl_url: str,
) -> ChainResult:
    """High-level: fetch trust store and validate chain.

    Args:
        cms_der: DER-encoded CMS/PKCS#7 blob.
        tsl_url: TSL URL from the server profile.

    Returns:
        ChainResult with validation outcome.
    """
    store = get_trust_store(tsl_url)
    if store is None:
        return ChainResult(
            chain_valid=None,
            trust_anchor=None,
            chain_depth=0,
            details=["Chain: trust store unavailable"],
        )

    return validate_chain(cms_der, store)
