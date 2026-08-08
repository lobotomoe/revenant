# SPDX-License-Identifier: Apache-2.0
# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false, reportIndexIssue=false, reportAttributeAccessIssue=false
"""Certificate selection helpers for CMS ``SignedData`` values."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from asn1crypto import cms as asn1_cms
    from asn1crypto import x509 as asn1_x509

_logger = logging.getLogger(__name__)


def x509_certificates(signed_data: asn1_cms.SignedData) -> list[asn1_x509.Certificate]:
    """Return parseable embedded X.509 certificates, ignoring other choices."""
    certificates = signed_data["certificates"]
    if not certificates:
        return []

    result: list[asn1_x509.Certificate] = []
    for choice in certificates:
        if choice.name != "certificate":
            continue
        try:
            cert = choice.chosen
            _ = cert.native
        except Exception:
            _logger.debug("Ignoring malformed embedded X.509 certificate", exc_info=True)
            continue
        result.append(cert)
    return result


def find_signer_certificate(
    signed_data: asn1_cms.SignedData,
    signer_info: asn1_cms.SignerInfo | None = None,
) -> asn1_x509.Certificate | None:
    """Find exactly one certificate identified by a CMS ``SignerInfo.sid``.

    Certificate order is not meaningful in CMS because the collection is a
    ``SET OF``.  Returning ``None`` for zero or multiple matches lets callers
    fail closed instead of attributing a signature to an unrelated certificate.
    """
    if signer_info is None:
        signer_infos = signed_data["signer_infos"]
        if not signer_infos:
            return None
        signer_info = signer_infos[0]

    if signer_info is None:  # Defensive narrowing for incomplete third-party stubs.
        return None
    sid = signer_info["sid"]
    matches: list[asn1_x509.Certificate] = []
    for cert in x509_certificates(signed_data):
        if sid.name == "issuer_and_serial_number":
            issuer_and_serial = sid.chosen
            if (
                cert.issuer == issuer_and_serial["issuer"]
                and cert.serial_number == issuer_and_serial["serial_number"].native
            ):
                matches.append(cert)
        elif sid.name == "subject_key_identifier" and cert.key_identifier == sid.chosen.native:
            matches.append(cert)

    return matches[0] if len(matches) == 1 else None
