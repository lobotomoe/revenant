# SPDX-License-Identifier: Apache-2.0
"""Regression tests for cryptographic CMS signature verification."""

from __future__ import annotations

import datetime
import io
from pathlib import Path
from typing import ClassVar, Literal

import pikepdf
import pytest
from asn1crypto import algos as asn1_algos
from asn1crypto import cms as asn1_cms
from asn1crypto import core as asn1_core
from asn1crypto import x509 as asn1_x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

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

_OID_SIGNING_CERTIFICATE = "1.2.840.113549.1.9.16.2.12"
_OID_SIGNING_CERTIFICATE_V2 = "1.2.840.113549.1.9.16.2.47"


class _EssCertId(asn1_core.Sequence):
    _fields: ClassVar[list[object]] = [
        ("cert_hash", asn1_core.OctetString),
        ("issuer_serial", asn1_core.Any, {"optional": True}),
    ]


class _EssCertIds(asn1_core.SequenceOf):
    _child_spec = _EssCertId


class _SigningCertificate(asn1_core.Sequence):
    _fields: ClassVar[list[object]] = [
        ("certs", _EssCertIds),
        ("policies", asn1_core.Any, {"optional": True}),
    ]


class _EssCertIdV2(asn1_core.Sequence):
    _fields: ClassVar[list[object]] = [
        (
            "hash_algorithm",
            asn1_algos.DigestAlgorithm,
            {"default": {"algorithm": "sha256"}},
        ),
        ("cert_hash", asn1_core.OctetString),
        ("issuer_serial", asn1_core.Any, {"optional": True}),
    ]


class _EssCertIdsV2(asn1_core.SequenceOf):
    _child_spec = _EssCertIdV2


class _SigningCertificateV2(asn1_core.Sequence):
    _fields: ClassVar[list[object]] = [
        ("certs", _EssCertIdsV2),
        ("policies", asn1_core.Any, {"optional": True}),
    ]


def _real_cms(data: bytes) -> bytes:
    root_cert, root_key = make_root_ca()
    leaf_cert, leaf_key = make_leaf(root_cert, root_key)
    return build_cms_with_certs(leaf_cert, leaf_key, data=data)


def _digest(data: bytes, algorithm: hashes.HashAlgorithm) -> bytes:
    digest = hashes.Hash(algorithm)
    digest.update(data)
    return digest.finalize()


def _ess_bound_cms(
    data: bytes,
    version: Literal["v1", "v2"],
    *,
    v2_hash: str | None = None,
    malformed: bool = False,
) -> tuple[bytes, x509.Certificate, rsa.RSAPrivateKey]:
    root_cert, root_key = make_root_ca()
    leaf_cert, leaf_key = make_leaf(root_cert, root_key)
    content_info = asn1_cms.ContentInfo.load(
        build_cms_with_certs(leaf_cert, leaf_key, data=data)
    )
    signer_info = content_info["content"]["signer_infos"][0]

    if malformed:
        binding_value: asn1_core.Asn1Value = asn1_core.OctetString(b"not a sequence")
    else:
        cert_der = leaf_cert.public_bytes(serialization.Encoding.DER)
        if version == "v1":
            # RFC 2634 fixes ESSCertID v1 to SHA-1.
            cert_hash = _digest(cert_der, hashes.SHA1())  # noqa: S303
            binding_value = _SigningCertificate({"certs": [{"cert_hash": cert_hash}]})
        else:
            hash_name = v2_hash or "sha256"
            hash_type = {
                "sha256": hashes.SHA256,
                "sha384": hashes.SHA384,
            }[hash_name]
            cert_id: dict[str, object] = {"cert_hash": _digest(cert_der, hash_type())}
            if v2_hash is not None:
                cert_id["hash_algorithm"] = {"algorithm": v2_hash}
            binding_value = _SigningCertificateV2({"certs": [cert_id]})

    oid = _OID_SIGNING_CERTIFICATE if version == "v1" else _OID_SIGNING_CERTIFICATE_V2
    binding_attr = asn1_cms.CMSAttribute(
        {"type": oid, "values": [asn1_core.Any(binding_value)]}
    )
    signer_info["signed_attrs"] = asn1_cms.CMSAttributes(
        [*signer_info["signed_attrs"], binding_attr]
    )
    signed_attrs = bytearray(signer_info["signed_attrs"].dump(force=True))
    signed_attrs[0] = 0x31
    signer_info["signature"] = leaf_key.sign(
        bytes(signed_attrs),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    return content_info.dump(force=True), leaf_cert, leaf_key


def _replacement_certificate(
    original: x509.Certificate,
    signer_key: rsa.RSAPrivateKey,
) -> x509.Certificate:
    rogue_issuer_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Substituted Identity")]))
        .issuer_name(original.issuer)
        .public_key(signer_key.public_key())
        .serial_number(original.serial_number)
        .not_valid_before(datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc))
        .not_valid_after(datetime.datetime(2032, 1, 1, tzinfo=datetime.timezone.utc))
        .sign(rogue_issuer_key, hashes.SHA256())
    )


def _replace_embedded_certificate(cms_der: bytes, certificate: x509.Certificate) -> bytes:
    content_info = asn1_cms.ContentInfo.load(cms_der)
    asn1_certificate = asn1_x509.Certificate.load(
        certificate.public_bytes(serialization.Encoding.DER)
    )
    content_info["content"]["certificates"] = asn1_cms.CertificateSet(
        [asn1_cms.CertificateChoices(name="certificate", value=asn1_certificate)]
    )
    return content_info.dump(force=True)


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
    ("version", "v2_hash"),
    [("v1", None), ("v2", None), ("v2", "sha384")],
)
def test_detached_accepts_matching_ess_certificate_binding(
    version: Literal["v1", "v2"],
    v2_hash: str | None,
):
    data = b"ESS-bound detached document"
    cms_der, _, _ = _ess_bound_cms(data, version, v2_hash=v2_hash)

    result = verify_detached_signature(data, cms_der)

    assert result["signature_valid"] is True
    assert result["valid"] is True


@pytest.mark.parametrize("version", ["v1", "v2"])
def test_detached_rejects_ess_certificate_substitution(
    version: Literal["v1", "v2"],
):
    data = b"certificate substitution"
    cms_der, original_cert, signer_key = _ess_bound_cms(data, version)
    replacement = _replacement_certificate(original_cert, signer_key)
    substituted_cms = _replace_embedded_certificate(cms_der, replacement)

    result = verify_detached_signature(data, substituted_cms)

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
    data = b"malformed ESS binding"
    cms_der, _, _ = _ess_bound_cms(data, "v1", malformed=True)

    result = verify_detached_signature(data, cms_der)

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
    cms_der = (_PKI_TESTDATA / "cms_chain3.der").read_bytes()
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
