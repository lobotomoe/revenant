# SPDX-License-Identifier: Apache-2.0
"""Tests for revenant.core.pdf.ltv -- LTV status detection."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from revenant.core.pdf.ltv import check_ltv_status


def _mock_ci(sd_items: dict) -> MagicMock:
    """Build a mock ContentInfo -> content -> signed_data with __getitem__."""
    mock_sd = MagicMock()
    mock_sd.__getitem__ = lambda self, key: sd_items.get(key, MagicMock())
    mock_ci = MagicMock()
    mock_ci.__getitem__ = lambda self, key: mock_sd if key == "content" else MagicMock()
    return mock_ci


def _mock_signer(
    *, signed_oids: list[str] | None = None, unsigned_oids: list[str] | None = None
) -> MagicMock:
    """Build a mock signer_info with signed/unsigned attrs."""

    def make_attrs(oids):
        if oids is None:
            return None
        attrs = []
        for oid in oids:
            attr = MagicMock()
            attr.__getitem__ = lambda self, key, o=oid: (
                MagicMock(dotted=o) if key == "type" else MagicMock()
            )
            attrs.append(attr)
        return attrs

    signer = MagicMock()
    items = {
        "signed_attrs": make_attrs(signed_oids),
        "unsigned_attrs": make_attrs(unsigned_oids),
    }
    signer.__getitem__ = lambda self, key: items.get(key, MagicMock())
    return signer


def test_ltv_unparsable_cms():
    """Completely invalid CMS data should return ltv_enabled=False."""
    result = check_ltv_status(b"not cms")
    assert result.ltv_enabled is False
    assert any("Cannot parse" in d for d in result.details)


def test_ltv_no_revocation_data():
    """Real CMS with no revocation data."""
    from ._cert_factory import build_cms_with_certs, make_leaf, make_root_ca

    root_cert, root_key = make_root_ca()
    leaf_cert, leaf_key = make_leaf(root_cert, root_key)
    cms_der = build_cms_with_certs(leaf_cert, leaf_key)

    result = check_ltv_status(cms_der)
    assert result.ltv_enabled is False
    assert result.has_crl is False
    assert result.has_ocsp is False
    assert any("No signed revocation" in d for d in result.details)


def test_ltv_with_crls():
    """Embedded CRLs are reported but never counted as evidence.

    The ``crls`` field sits beside the signature, not inside it: RFC 5652 signs
    the signed attributes, so anyone can add entries here afterwards.
    """
    from ._cert_factory import build_cms_with_certs, make_leaf, make_root_ca

    root_cert, root_key = make_root_ca()
    leaf_cert, leaf_key = make_leaf(root_cert, root_key)
    cms_der = build_cms_with_certs(leaf_cert, leaf_key)

    mock_crls = MagicMock()
    mock_crls.__len__ = lambda self: 2
    mock_crls.__bool__ = lambda self: True

    ci = _mock_ci({"crls": mock_crls, "signer_infos": []})

    with patch("asn1crypto.cms.ContentInfo.load", return_value=ci):
        result = check_ltv_status(cms_der)

    assert result.has_crl is True
    assert result.ltv_enabled is False
    assert result.has_unauthenticated_material is True
    assert any("outside the signature" in d for d in result.details)


def _cms_with_archival(*, signed: bool, value_der: bytes) -> bytes:
    """Real CMS carrying a RevocationInfoArchival attribute with a chosen value."""
    from asn1crypto import cms as asn1_cms
    from asn1crypto import core

    from ._cert_factory import build_cms_with_certs, make_leaf, make_root_ca

    root_cert, root_key = make_root_ca()
    leaf_cert, leaf_key = make_leaf(root_cert, root_key)
    content_info = asn1_cms.ContentInfo.load(build_cms_with_certs(leaf_cert, leaf_key))
    signer_info = content_info["content"]["signer_infos"][0]
    attribute = asn1_cms.CMSAttribute(
        {
            "type": asn1_cms.CMSAttributeType("1.2.840.113583.1.1.8"),
            "values": [core.Any.load(value_der)],
        }
    )
    field = "signed_attrs" if signed else "unsigned_attrs"
    signer_info[field] = asn1_cms.CMSAttributes([attribute])
    return content_info.dump(force=True)


#: RevocationInfoArchival ::= SEQUENCE { ocsp [1] SEQUENCE OF ... }
_ARCHIVAL_WITH_OCSP = bytes.fromhex("3007a1053003020101")


def test_ltv_archival_in_signed_attributes_counts():
    result = check_ltv_status(_cms_with_archival(signed=True, value_der=_ARCHIVAL_WITH_OCSP))

    assert result.ltv_enabled is True
    assert result.has_revocation_archival is True
    assert result.has_ocsp is True


def test_ltv_archival_in_unsigned_attributes_is_not_evidence():
    """The reported attack: an unsigned attribute is stapled on after signing.

    Nothing in an unsigned attribute is covered by the signer's signature, so a
    third party can add one to a finished document without breaking it.
    """
    result = check_ltv_status(_cms_with_archival(signed=False, value_der=_ARCHIVAL_WITH_OCSP))

    assert result.ltv_enabled is False
    assert result.has_unauthenticated_material is True
    assert any("outside the signature" in d for d in result.details)


def test_ltv_bogus_archival_value_is_not_evidence():
    """The OID is a label on a container; the contents decide what it holds."""
    bogus = b"\x04\x15bogus-not-ocsp-or-crl"

    result = check_ltv_status(_cms_with_archival(signed=True, value_der=bogus))

    assert result.ltv_enabled is False
    assert result.has_ocsp is False
    assert any("malformed" in d for d in result.details)


def test_ltv_unsigned_attrs_with_revocation_values():
    """Unsigned attribute with CAdES revocation values."""
    from ._cert_factory import build_cms_with_certs, make_leaf, make_root_ca

    root_cert, root_key = make_root_ca()
    leaf_cert, leaf_key = make_leaf(root_cert, root_key)
    cms_der = build_cms_with_certs(leaf_cert, leaf_key)

    signer = _mock_signer(unsigned_oids=["1.2.840.113549.1.9.16.2.24"])
    ci = _mock_ci({"crls": None, "signer_infos": [signer]})

    with patch("asn1crypto.cms.ContentInfo.load", return_value=ci):
        result = check_ltv_status(cms_der)

    assert any("CAdES revocation values" in d for d in result.details)


def test_ltv_signer_info_exception():
    """Exception in signer_infos access should be handled gracefully."""
    from ._cert_factory import build_cms_with_certs, make_leaf, make_root_ca

    root_cert, root_key = make_root_ca()
    leaf_cert, leaf_key = make_leaf(root_cert, root_key)
    cms_der = build_cms_with_certs(leaf_cert, leaf_key)

    # signer_infos that raises when iterated
    bad_infos = MagicMock()
    bad_infos.__bool__ = lambda self: True
    bad_infos.__getitem__ = MagicMock(side_effect=IndexError("bad"))

    ci = _mock_ci({"crls": None, "signer_infos": bad_infos})

    with patch("asn1crypto.cms.ContentInfo.load", return_value=ci):
        result = check_ltv_status(cms_der)

    assert result.ltv_enabled is False


def test_ltv_crl_access_error():
    """TypeError on crls access should be handled."""
    from ._cert_factory import build_cms_with_certs, make_leaf, make_root_ca

    root_cert, root_key = make_root_ca()
    leaf_cert, leaf_key = make_leaf(root_cert, root_key)
    cms_der = build_cms_with_certs(leaf_cert, leaf_key)

    mock_sd = MagicMock()
    # Make "crls" raise TypeError
    mock_sd.__getitem__ = MagicMock(side_effect=TypeError("bad crls"))

    mock_ci = MagicMock()
    mock_ci.__getitem__ = lambda self, key: mock_sd if key == "content" else MagicMock()

    with patch("asn1crypto.cms.ContentInfo.load", return_value=mock_ci):
        result = check_ltv_status(cms_der)

    # TypeError gets caught at the outer level, returns not parsable
    assert result.ltv_enabled is False
