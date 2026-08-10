# SPDX-License-Identifier: Apache-2.0
"""Proof that a signing service returned a signature over what was submitted.

A signing call that reports success while handing back bytes nobody checked is,
from the caller's side, indistinguishable from one that worked -- the failure
only surfaces later, in whatever verifier the document eventually reaches. So
every response a workflow is about to return passes through here first: the CMS
must parse, carry the signer's certificate, and verify as a signature over
exactly the bytes that were sent.

This deliberately says nothing about *who* signed. Whether the certificate is
one worth trusting is a chain question, answered separately and reported rather
than enforced; binding the response to the request is the part that has to hold
for every profile, online or offline.

Submitting a document and submitting its digest are different situations, so
they are different functions. With the content in hand the binding can be
proven. With only a digest it cannot: what a service signs in response to a
pre-computed digest is service-defined, and services differ. That gap is
reported rather than papered over.
"""

from __future__ import annotations

__all__ = ["check_response_over_content", "check_response_over_digest"]

import logging

from ..errors import SigningResponseError
from .pdf.cms_info import extract_digest_info
from .pdf.cms_signature import verify_signer_signature
from .pdf.verify import verify_detached_signature

_logger = logging.getLogger(__name__)


def check_response_over_content(cms_der: bytes, content: bytes, operation: str) -> None:
    """Raise unless the response is a valid signature over exactly *content*.

    Args:
        cms_der: The CMS/PKCS#7 blob the transport returned.
        content: The exact bytes submitted for signing.
        operation: Name of the signing operation, for the error message.

    Raises:
        SigningResponseError: If the response is not a signature, or does not
            cover the submitted bytes.
    """
    result = verify_detached_signature(content, cms_der)
    if result["valid"]:
        _logger.debug("%s: response verified against %d submitted bytes", operation, len(content))
        return

    detail_str = "\n  ".join(result["details"])
    _logger.error("%s: response verification failed: %s", operation, detail_str)
    raise SigningResponseError(
        f"{operation}: the signing service's response is not a valid signature over "
        f"the {len(content)} bytes submitted:\n  {detail_str}\n"
        "Nothing was saved."
    )


def check_response_over_digest(cms_der: bytes, digest: bytes, operation: str) -> None:
    """Raise unless the response is a genuine signature; report what it binds.

    Only a digest was submitted, so there is no content to verify the signature
    against and no way to prove the response covers the document that digest
    came from. What is provable -- that the response is a real signature by the
    certificate it carries -- is required. What is not provable is reported: if
    the signed ``messageDigest`` differs from the digest submitted, the service
    did not treat it as a pre-computed digest, and the signature must not be
    attached to the document it was taken from.

    Args:
        cms_der: The CMS/PKCS#7 blob the transport returned.
        digest: The digest submitted for signing.
        operation: Name of the signing operation, for the error message.

    Raises:
        SigningResponseError: If the response is not a verifiable signature.
    """
    signature = verify_signer_signature(cms_der, None)
    if signature.valid is not True:
        raise SigningResponseError(
            f"{operation}: the signing service returned a response that is not a "
            f"verifiable signature ({signature.describe()}). "
            "Nothing was saved."
        )

    digest_info = extract_digest_info(cms_der)
    if digest_info is None:
        # A signature that verified without content signed its signed attributes,
        # and those must carry exactly one well-formed messageDigest -- the
        # verifier rejects them otherwise. Its absence here means two readings of
        # the same CMS disagree, which is our bug, not a service quirk.
        raise SigningResponseError(
            f"{operation}: the response verified as a signature but declares no "
            "messageDigest; the CMS could not be read consistently. Nothing was saved."
        )

    _, signed_digest = digest_info
    if signed_digest == digest:
        _logger.debug("%s: response binds the submitted digest", operation)
        return

    _logger.warning(
        "%s: the signing service signed the submitted digest as content rather than "
        "treating it as a pre-computed digest -- the response binds %s, not the %s "
        "that was submitted. It is a valid signature, but not one that can be "
        "attached to the document that digest came from; use sign_data on the "
        "document itself for that.",
        operation,
        signed_digest.hex(),
        digest.hex(),
    )
