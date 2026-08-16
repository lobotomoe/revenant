# SPDX-License-Identifier: Apache-2.0
# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false
"""LTV (Long Term Validation) status detection for CMS signatures.

Checks whether a CMS/PKCS#7 signature contains embedded revocation
data (CRL or OCSP responses) required for long-term validation.

EKENG CoSign signatures are NOT LTV-enabled -- they contain no embedded
revocation data.  This is expected behavior, not a defect.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

_logger = logging.getLogger(__name__)

# Adobe RevocationInfoArchival attribute OID
_OID_REVOCATION_INFO_ARCHIVAL = "1.2.840.113583.1.1.8"

# id-smime-aa-ets-revocationRefs (CAdES)  # noqa: ERA001
_OID_REVOCATION_REFS = "1.2.840.113549.1.9.16.2.22"

# id-smime-aa-ets-certValues (CAdES)  # noqa: ERA001
_OID_CERT_VALUES = "1.2.840.113549.1.9.16.2.23"

# id-smime-aa-ets-revocationValues (CAdES)  # noqa: ERA001
_OID_REVOCATION_VALUES = "1.2.840.113549.1.9.16.2.24"


@dataclass(frozen=True, slots=True)
class LtvStatus:
    """Result of LTV status check on a CMS signature."""

    #: True only when well-formed revocation material travels inside the signer's
    #: *signed* attributes, so the signer committed to it. Material anyone can
    #: append after the fact never raises this, whatever it claims to be.
    ltv_enabled: bool
    has_crl: bool
    has_ocsp: bool
    has_revocation_archival: bool
    #: Revocation material that is present but outside the signature: unsigned
    #: attributes and the ``crls`` field, neither of which the signer signed.
    #: Reported so it is visible, never counted as evidence.
    has_unauthenticated_material: bool
    details: list[str]


#: A universal, constructed SEQUENCE -- the outer shape of an Adobe
#: RevocationInfoArchival value (and of the CAdES revocation attributes).
_ASN1_UNIVERSAL_CLASS = 0
_ASN1_SEQUENCE_TAG = 16
_ASN1_CONSTRUCTED = 1


_ASN1_CONTEXT_CLASS = 2
#: RevocationInfoArchival ::= SEQUENCE { crl [0], ocsp [1], otherRevInfo [2] }
_ARCHIVAL_CRL_TAG = 0
_ARCHIVAL_OCSP_TAG = 1


def _revocation_container_members(attr: object) -> tuple[bool, bool] | None:
    """Read an attribute value as revocation material: ``(has_crl, has_ocsp)``.

    ``None`` when the value is not that kind of structure at all. The OID proves
    nothing on its own: an attribute is a container, and whoever writes one
    chooses what goes inside. This says which members are present, not whether
    the revocation data inside them is genuine -- that check does not exist yet.
    """
    from asn1crypto import core

    values = attr["values"]  # pyright: ignore[reportIndexIssue]
    if not values:
        return None
    try:
        value = core.load(values[0].dump(), strict=True)
    except (ValueError, TypeError, IndexError):
        return None
    if not (
        value.class_ == _ASN1_UNIVERSAL_CLASS
        and value.tag == _ASN1_SEQUENCE_TAG
        and value.method == _ASN1_CONSTRUCTED
    ):
        return None

    present = _context_tags(value.contents)
    return _ARCHIVAL_CRL_TAG in present, _ARCHIVAL_OCSP_TAG in present


#: DER identifier octet: bits 8-7 are the class, bit 6 the constructed flag, and
#: bits 5-1 the tag number (X.690 8.1.2). 0x1F in the tag bits means the number
#: continues into further octets, which this structure never uses.
_DER_CLASS_MASK = 0xC0
_DER_CONTEXT_CLASS = 0x80
_DER_TAG_MASK = 0x1F
_DER_LONG_FORM_TAG = 0x1F
_DER_LONG_FORM_LENGTH = 0x80
_DER_LENGTH_COUNT_MASK = 0x7F
#: Enough for any sane member; a longer length field means the value is not one.
_DER_MAX_LENGTH_OCTETS = 4


def _context_tags(contents: bytes) -> set[int]:
    """Tag numbers of the immediate context-class children of a DER structure.

    A deliberately small reader: asn1crypto will not decode a bare context-tagged
    element without a full spec, and specifying RevocationInfoArchival properly
    trips over its own handling of consecutive optional explicit fields -- an
    archival carrying only OCSP, the ordinary Adobe shape, fails to parse. Only
    the member framing is read here; nothing inside a member is interpreted.
    """
    tags: set[int] = set()
    offset = 0
    while offset < len(contents):
        identifier = contents[offset]
        tag_number = identifier & _DER_TAG_MASK
        offset += 1
        if tag_number == _DER_LONG_FORM_TAG or offset >= len(contents):
            break
        length_octet = contents[offset]
        offset += 1
        if length_octet & _DER_LONG_FORM_LENGTH:
            count = length_octet & _DER_LENGTH_COUNT_MASK
            if count == 0 or count > _DER_MAX_LENGTH_OCTETS or offset + count > len(contents):
                break
            length = int.from_bytes(contents[offset : offset + count], "big")
            offset += count
        else:
            length = length_octet
        if identifier & _DER_CLASS_MASK == _DER_CONTEXT_CLASS:
            tags.add(tag_number)
        offset += length
    return tags


def check_ltv_status(cms_der: bytes) -> LtvStatus:
    """Check whether a CMS signature carries long-term-validation evidence.

    Only material the signer actually signed can count as evidence. The CMS
    ``crls`` field and the signer's *unsigned* attributes are outside the
    signature: a third party can add either to a finished document without
    invalidating it, so they are reported as present and explicitly not counted.

    Note that this reports the *presence* of well-formed material, not its
    validity: the responses and CRLs are not yet checked against the signer's
    chain, so a true ``ltv_enabled`` means "the signer embedded revocation
    evidence", not "the evidence was verified".

    Args:
        cms_der: DER-encoded CMS/PKCS#7 signature blob.

    Returns:
        LtvStatus with flags indicating what revocation data is present.
    """
    details: list[str] = []
    has_crl = False
    has_ocsp = False
    has_revocation_archival = False
    has_unauthenticated_material = False
    authenticated_material = False

    try:
        from asn1crypto import cms as asn1_cms

        content_info = asn1_cms.ContentInfo.load(cms_der)
        signed_data = content_info["content"]
    except (ValueError, TypeError, KeyError, OSError) as e:
        _logger.debug("Cannot parse CMS for LTV check: %s", e)
        details.append("Cannot parse CMS structure for LTV check")
        return LtvStatus(
            ltv_enabled=False,
            has_crl=False,
            has_ocsp=False,
            has_revocation_archival=False,
            has_unauthenticated_material=False,
            details=details,
        )

    # The crls field sits beside the signature rather than inside it: RFC 5652
    # puts the signature over the signed attributes, never over this collection.
    # Anyone can add or drop entries here without disturbing the signature.
    try:
        crls = signed_data["crls"]
        if crls is not None and len(crls) > 0:
            has_crl = True
            has_unauthenticated_material = True
            details.append(f"Embedded CRLs: {len(crls)} (outside the signature, not counted)")
    except (KeyError, TypeError, ValueError):
        pass

    # Check signer attributes for revocation-related OIDs
    revocation_oids = {
        _OID_REVOCATION_INFO_ARCHIVAL: "Adobe RevocationInfoArchival",
        _OID_REVOCATION_REFS: "CAdES revocation references",
        _OID_REVOCATION_VALUES: "CAdES revocation values",
    }

    try:
        signer_infos = signed_data["signer_infos"]
        if signer_infos:
            signer_info = signer_infos[0]

            # Signed attributes are the signature input, so what is found here is
            # material the signer committed to.
            signed_attrs = signer_info["signed_attrs"]
            if signed_attrs is not None:
                for attr in signed_attrs:
                    oid = attr["type"].dotted
                    if oid not in revocation_oids:
                        continue
                    members = _revocation_container_members(attr)
                    if members is None:
                        details.append(
                            f"Signed attribute: {revocation_oids[oid]} (malformed, not counted)"
                        )
                        continue
                    member_crl, member_ocsp = members
                    details.append(f"Signed attribute: {revocation_oids[oid]}")
                    authenticated_material = True
                    has_crl = has_crl or member_crl
                    has_ocsp = has_ocsp or member_ocsp
                    if oid == _OID_REVOCATION_INFO_ARCHIVAL:
                        has_revocation_archival = True

            # Unsigned attributes are not covered by the signature: a third party
            # can staple one onto a finished document. Whatever they carry is
            # reported and never counted.
            unsigned_attrs = signer_info["unsigned_attrs"]
            if unsigned_attrs is not None:
                for attr in unsigned_attrs:
                    oid = attr["type"].dotted
                    if oid not in revocation_oids:
                        continue
                    has_unauthenticated_material = True
                    details.append(
                        f"Unsigned attribute: {revocation_oids[oid]} "
                        "(outside the signature, not counted)"
                    )
    except (KeyError, TypeError, ValueError, IndexError):
        _logger.debug("Cannot check signer attributes for LTV", exc_info=True)

    ltv_enabled = authenticated_material

    if not ltv_enabled:
        details.append("No signed revocation data (CRL/OCSP)")

    return LtvStatus(
        ltv_enabled=ltv_enabled,
        has_crl=has_crl,
        has_ocsp=has_ocsp,
        has_revocation_archival=has_revocation_archival,
        has_unauthenticated_material=has_unauthenticated_material,
        details=details,
    )
