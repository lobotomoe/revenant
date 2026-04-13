# SPDX-License-Identifier: Apache-2.0
"""Tests for chain validation integration in verify.py.

Covers the tsl_url parameter paths in _verify_signature_match and
verify_detached_signature.
"""

from __future__ import annotations

from unittest.mock import patch

from revenant.core.chain import ChainResult
from revenant.core.pdf.verify import verify_detached_signature

from ._cert_factory import build_cms_with_certs, make_leaf, make_root_ca


def _make_detached_cms(data: bytes = b"test document") -> tuple[bytes, bytes]:
    """Build (data, cms_der) for detached signature tests."""
    root_cert, root_key = make_root_ca()
    leaf_cert, leaf_key = make_leaf(root_cert, root_key)
    cms_der = build_cms_with_certs(leaf_cert, leaf_key, data=data)
    return data, cms_der


# ── verify_detached_signature with tsl_url ──────────────────────────


def test_verify_detached_chain_trusted():
    """Chain validation returns trusted."""
    data, cms_der = _make_detached_cms()

    chain_result = ChainResult(
        chain_valid=True,
        trust_anchor="TestCA",
        chain_depth=2,
        details=["Chain: trusted (TestCA)"],
    )

    with patch(
        "revenant.core.chain.validate_chain_for_profile",
        return_value=chain_result,
    ):
        result = verify_detached_signature(data, cms_der, tsl_url="https://example.com/tsl.xml")

    assert result["chain_valid"] is True
    assert result["trust_anchor"] == "TestCA"
    assert result["trust_status"] == "trusted"


def test_verify_detached_chain_untrusted():
    """Chain validation returns untrusted."""
    data, cms_der = _make_detached_cms()

    chain_result = ChainResult(
        chain_valid=False,
        trust_anchor=None,
        chain_depth=1,
        details=["Chain: no trusted CA"],
    )

    with patch(
        "revenant.core.chain.validate_chain_for_profile",
        return_value=chain_result,
    ):
        result = verify_detached_signature(data, cms_der, tsl_url="https://example.com/tsl.xml")

    assert result["chain_valid"] is False
    assert result["trust_status"] == "untrusted"


def test_verify_detached_chain_exception():
    """Chain validation exception should be non-fatal."""
    data, cms_der = _make_detached_cms()

    with patch(
        "revenant.core.chain.validate_chain_for_profile",
        side_effect=RuntimeError("fetch failed"),
    ):
        result = verify_detached_signature(data, cms_der, tsl_url="https://example.com/tsl.xml")

    assert result["chain_valid"] is None
    assert result["trust_status"] == "unknown"
    assert any("unavailable" in d for d in result["details"])


def test_verify_detached_no_tsl_url():
    """Without tsl_url, chain validation should be skipped."""
    data, cms_der = _make_detached_cms()
    result = verify_detached_signature(data, cms_der, tsl_url=None)
    assert result["chain_valid"] is None
    assert result["trust_status"] == "unknown"


def test_verify_detached_bad_asn1_tag():
    """CMS not starting with 0x30 should flag structure error."""
    cms_der = b"\xff" * 200
    result = verify_detached_signature(b"data", cms_der)
    assert result["structure_ok"] is False
    assert any("ASN.1" in d for d in result["details"])


def test_verify_detached_signer_name():
    """Detached verify should extract signer name."""
    data, cms_der = _make_detached_cms()
    result = verify_detached_signature(data, cms_der)
    assert result["signer"] is not None
