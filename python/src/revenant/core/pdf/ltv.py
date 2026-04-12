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

    ltv_enabled: bool
    has_crl: bool
    has_ocsp: bool
    has_revocation_archival: bool
    details: list[str]


def check_ltv_status(cms_der: bytes) -> LtvStatus:
    """Check if a CMS signature contains LTV (Long Term Validation) data.

    Inspects the CMS SignedData structure for:
    1. Embedded CRLs in the ``crls`` field
    2. OCSP responses (via Adobe RevocationInfoArchival or CAdES attributes)
    3. Revocation references in signed/unsigned attributes

    Args:
        cms_der: DER-encoded CMS/PKCS#7 signature blob.

    Returns:
        LtvStatus with flags indicating what revocation data is present.
    """
    details: list[str] = []
    has_crl = False
    has_ocsp = False
    has_revocation_archival = False

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
            details=details,
        )

    # Check for embedded CRLs
    try:
        crls = signed_data["crls"]
        if crls is not None and len(crls) > 0:
            has_crl = True
            details.append(f"Embedded CRLs: {len(crls)}")
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

            # Check signed attributes
            signed_attrs = signer_info["signed_attrs"]
            if signed_attrs is not None:
                for attr in signed_attrs:
                    oid = attr["type"].dotted
                    if oid in revocation_oids:
                        details.append(f"Signed attribute: {revocation_oids[oid]}")
                        if oid == _OID_REVOCATION_INFO_ARCHIVAL:
                            has_revocation_archival = True
                            has_ocsp = True

            # Check unsigned attributes
            unsigned_attrs = signer_info["unsigned_attrs"]
            if unsigned_attrs is not None:
                for attr in unsigned_attrs:
                    oid = attr["type"].dotted
                    if oid in revocation_oids:
                        details.append(f"Unsigned attribute: {revocation_oids[oid]}")
                        if oid == _OID_REVOCATION_INFO_ARCHIVAL:
                            has_revocation_archival = True
                            has_ocsp = True
    except (KeyError, TypeError, ValueError, IndexError):
        _logger.debug("Cannot check signer attributes for LTV", exc_info=True)

    ltv_enabled = has_crl or has_ocsp or has_revocation_archival

    if not ltv_enabled:
        details.append("No embedded revocation data (CRL/OCSP)")

    return LtvStatus(
        ltv_enabled=ltv_enabled,
        has_crl=has_crl,
        has_ocsp=has_ocsp,
        has_revocation_archival=has_revocation_archival,
        details=details,
    )
