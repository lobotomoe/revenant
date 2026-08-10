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
"""

from __future__ import annotations

__all__ = ["check_signing_response"]

import logging

from ..errors import SigningResponseError
from .pdf.cms_signature import verify_signer_signature
from .pdf.verify import verify_detached_signature

_logger = logging.getLogger(__name__)


def check_signing_response(
    cms_der: bytes,
    *,
    signed_content: bytes | None,
    operation: str,
) -> None:
    """Raise unless the signing service's response is a usable signature.

    Args:
        cms_der: The CMS/PKCS#7 blob the transport returned.
        signed_content: The exact bytes submitted for signing, when the request
            determines them. The response must then verify as a signature over
            those bytes. Pass None only where the submitted material does not
            determine the signed content -- the signature itself is still
            verified, but nothing ties it to a particular document.
        operation: Name of the signing operation, for the error message.

    Raises:
        SigningResponseError: If the response is not a signature, or does not
            cover the submitted bytes.
    """
    if signed_content is None:
        signature = verify_signer_signature(cms_der, None)
        if signature.valid is True:
            _logger.debug("%s: response signature verified", operation)
            return
        raise SigningResponseError(
            f"{operation}: the signing service returned a response that is not a "
            f"verifiable signature ({signature.describe()}). "
            "Nothing was saved."
        )

    result = verify_detached_signature(signed_content, cms_der)
    if result["valid"]:
        _logger.debug(
            "%s: response verified against %d submitted bytes", operation, len(signed_content)
        )
        return

    detail_str = "\n  ".join(result["details"])
    _logger.error("%s: response verification failed: %s", operation, detail_str)
    raise SigningResponseError(
        f"{operation}: the signing service's response is not a valid signature over "
        f"the {len(signed_content)} bytes submitted:\n  {detail_str}\n"
        "Nothing was saved."
    )
