# SPDX-License-Identifier: Apache-2.0
"""Regression tests for cryptographic CMS signature verification."""

from __future__ import annotations

import io
from pathlib import Path

import pikepdf
import pytest
from asn1crypto import cms as asn1_cms

from revenant.core.pdf import (
    compute_byterange_hash,
    insert_cms,
    prepare_pdf_with_sig_field,
    verify_detached_signature,
    verify_embedded_signature,
)

from ._cert_factory import build_cms_with_certs, make_leaf, make_root_ca

_PKI_TESTDATA = (
    Path(__file__).resolve().parents[2] / "rust/crates/revenant-sign-core/src/pki/testdata"
)


def _real_cms(data: bytes) -> bytes:
    root_cert, root_key = make_root_ca()
    leaf_cert, leaf_key = make_leaf(root_cert, root_key)
    return build_cms_with_certs(leaf_cert, leaf_key, data=data)


def _fixture(name: str) -> bytes:
    return (_PKI_TESTDATA / name).read_bytes()


def _forge_signature(cms_der: bytes) -> bytes:
    content_info = asn1_cms.ContentInfo.load(cms_der)
    signer_info = content_info["content"]["signer_infos"][0]
    signature = bytearray(signer_info["signature"].native)
    signature[0] ^= 0x01
    signer_info["signature"] = bytes(signature)
    return content_info.dump(force=True)


def _without_signed_attribute(cms_der: bytes, oid: str) -> bytes:
    content_info = asn1_cms.ContentInfo.load(cms_der)
    signer_info = content_info["content"]["signer_infos"][0]
    signer_info["signed_attrs"] = asn1_cms.CMSAttributes(
        [attr for attr in signer_info["signed_attrs"] if attr["type"].dotted != oid]
    )
    return content_info.dump(force=True)


def test_detached_accepts_genuine_cms_signature():
    data = b"genuine detached document"
    result = verify_detached_signature(data, _real_cms(data))

    assert result["structure_ok"] is True
    assert result["hash_ok"] is True
    assert result["signature_valid"] is True
    assert result["valid"] is True
    assert "Signature OK -- signer signature verifies" in result["details"]


@pytest.mark.parametrize(
    "fixture_name",
    ["cms_ess_v1.der", "cms_ess_v2.der", "cms_ess_v2_sha384.der"],
)
def test_detached_accepts_matching_ess_certificate_binding(
    fixture_name: str,
):
    result = verify_detached_signature(b"test data", _fixture(fixture_name))

    assert result["signature_valid"] is True
    assert result["valid"] is True


@pytest.mark.parametrize(
    "fixture_name",
    ["cms_ess_v1_substituted.der", "cms_ess_v2_substituted.der"],
)
def test_detached_rejects_ess_certificate_substitution(
    fixture_name: str,
):
    result = verify_detached_signature(b"test data", _fixture(fixture_name))

    assert result["hash_ok"] is True
    assert result["signature_valid"] is None
    assert result["valid"] is False
    assert result["signer"] is not None
    assert result["signer"]["name"] == "Substituted Identity"
    assert (
        "Signature not verified (signingCertificate attribute names a different certificate)"
        in result["details"]
    )


def test_detached_rejects_malformed_ess_certificate_binding():
    result = verify_detached_signature(b"test data", _fixture("cms_ess_v1_malformed.der"))

    assert result["hash_ok"] is True
    assert result["signature_valid"] is None
    assert result["valid"] is False
    assert (
        "Signature not verified (signingCertificate attribute could not be parsed)"
        in result["details"]
    )


def test_detached_rejects_forged_signature_with_matching_digest():
    data = b"digest still matches this document"
    cms_der = _forge_signature(_real_cms(data))
    result = verify_detached_signature(data, cms_der)

    assert result["structure_ok"] is True
    assert result["hash_ok"] is True
    assert result["signature_valid"] is False
    assert result["valid"] is False
    assert (
        "Signature INVALID -- does not verify against the signer certificate" in result["details"]
    )


def test_missing_mandatory_content_type_fails_closed():
    data = b"missing content type"
    cms_der = _without_signed_attribute(_real_cms(data), "1.2.840.113549.1.9.3")
    result = verify_detached_signature(data, cms_der)

    assert result["hash_ok"] is True
    assert result["signature_valid"] is None
    assert result["valid"] is False
    assert (
        "Signature not verified (contentType attribute missing or duplicated)" in result["details"]
    )


def test_missing_signer_certificate_fails_closed():
    data = b"missing signer certificate"
    content_info = asn1_cms.ContentInfo.load(_real_cms(data))
    content_info["content"]["certificates"] = None
    result = verify_detached_signature(data, content_info.dump(force=True))

    assert result["hash_ok"] is True
    assert result["signature_valid"] is None
    assert result["valid"] is False
    assert (
        "Signature not verified (signer certificate not embedded or ambiguous)" in result["details"]
    )


def test_embedded_accepts_genuine_cms_signature():
    pdf = pikepdf.Pdf.new()
    pdf.add_blank_page()
    stream = io.BytesIO()
    pdf.save(stream)

    prepared, hex_start, hex_len = prepare_pdf_with_sig_field(
        stream.getvalue(),
        visible=False,
    )
    signed_data = prepared[:hex_start] + prepared[hex_start + hex_len + 1 :]
    signed_pdf = insert_cms(prepared, hex_start, hex_len, _real_cms(signed_data))

    result = verify_embedded_signature(signed_pdf)
    assert result["structure_ok"] is True
    assert result["hash_ok"] is True
    assert result["signature_valid"] is True
    assert result["valid"] is True


def test_expected_hash_cannot_hide_different_signed_message_digest():
    pdf = pikepdf.Pdf.new()
    pdf.add_blank_page()
    stream = io.BytesIO()
    pdf.save(stream)

    prepared, hex_start, hex_len = prepare_pdf_with_sig_field(
        stream.getvalue(),
        visible=False,
    )
    expected_hash = compute_byterange_hash(prepared, hex_start, hex_len)
    cms_for_different_data = _real_cms(b"different document")
    signed_pdf = insert_cms(prepared, hex_start, hex_len, cms_for_different_data)

    result = verify_embedded_signature(signed_pdf, expected_hash=expected_hash)
    assert result["structure_ok"] is True
    assert result["hash_ok"] is False
    assert result["signature_valid"] is True
    assert result["valid"] is False
    assert any("SHA-1 matches expected" in detail for detail in result["details"])
    assert any(
        "CMS messageDigest" in detail and "MISMATCH" in detail for detail in result["details"]
    )


def test_multicertificate_cms_reports_the_certificate_named_by_signer_info():
    cms_der = _fixture("cms_chain3.der")
    result = verify_detached_signature(b"test data", cms_der)

    assert result["valid"] is True
    assert result["signature_valid"] is True
    assert result["signer"] is not None
    assert result["signer"]["name"] == "Test Signer"


def test_accepts_cosign_digest_algorithm_quirk():
    data = b"CoSign compatibility"
    content_info = asn1_cms.ContentInfo.load(_real_cms(data))
    signer_info = content_info["content"]["signer_infos"][0]
    signer_info["digest_algorithm"]["algorithm"] = "1.2.840.113549.1.1.11"

    result = verify_detached_signature(data, content_info.dump(force=True))
    assert result["hash_ok"] is True
    assert result["signature_valid"] is True
    assert result["valid"] is True


def test_accepts_cosign_digest_quirk_with_bare_rsa_signature_algorithm():
    data = b"CoSign bare RSA compatibility"
    content_info = asn1_cms.ContentInfo.load(_real_cms(data))
    signer_info = content_info["content"]["signer_infos"][0]
    signer_info["digest_algorithm"]["algorithm"] = "1.2.840.113549.1.1.11"
    signer_info["signature_algorithm"]["algorithm"] = "1.2.840.113549.1.1.1"

    result = verify_detached_signature(data, content_info.dump(force=True))
    assert result["hash_ok"] is True
    assert result["signature_valid"] is True
    assert result["valid"] is True


def test_rejects_conflicting_combined_signature_algorithm():
    data = b"conflicting signature algorithm"
    content_info = asn1_cms.ContentInfo.load(_real_cms(data))
    signer_info = content_info["content"]["signer_infos"][0]
    signer_info["signature_algorithm"]["algorithm"] = "1.2.840.113549.1.1.13"

    result = verify_detached_signature(data, content_info.dump(force=True))
    assert result["hash_ok"] is True
    assert result["signature_valid"] is None
    assert result["valid"] is False
    assert (
        "Signature not verified (signatureAlgorithm conflicts with digestAlgorithm)"
        in result["details"]
    )
