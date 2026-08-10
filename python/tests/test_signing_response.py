"""Tests for revenant.core.signing_response — binding a response to its request."""

from __future__ import annotations

import pytest

from revenant.core.signing_response import check_signing_response
from revenant.errors import SigningResponseError

from .conftest import FAKE_CMS


def test_accepts_a_signature_over_the_submitted_bytes(cms_signer):
    content = b"the exact bytes that were submitted"
    check_signing_response(cms_signer(content), signed_content=content, operation="sign_data")


def test_rejects_a_signature_over_different_bytes(cms_signer):
    elsewhere = cms_signer(b"some other document")
    with pytest.raises(SigningResponseError, match="17 bytes submitted"):
        check_signing_response(
            elsewhere, signed_content=b"what we asked for", operation="sign_data"
        )


def test_rejects_filler_bytes_shaped_like_der():
    with pytest.raises(SigningResponseError, match="not a valid signature"):
        check_signing_response(FAKE_CMS, signed_content=b"content", operation="sign_pdf_detached")


def test_rejects_a_truncated_response(cms_signer):
    cms = cms_signer(b"content")
    with pytest.raises(SigningResponseError):
        check_signing_response(
            cms[: len(cms) // 2], signed_content=b"content", operation="sign_data"
        )


def test_a_tampered_signature_is_rejected(cms_signer):
    """Flip one bit deep in the signature, leaving the structure intact."""
    content = b"the exact bytes that were submitted"
    cms = bytearray(cms_signer(content))
    cms[-1] ^= 0x01
    with pytest.raises(SigningResponseError):
        check_signing_response(bytes(cms), signed_content=content, operation="sign_data")


def test_without_submitted_content_the_signature_alone_must_still_verify(cms_signer):
    check_signing_response(
        cms_signer(b"anything at all"), signed_content=None, operation="sign_hash"
    )

    with pytest.raises(SigningResponseError, match="verifiable signature"):
        check_signing_response(FAKE_CMS, signed_content=None, operation="sign_hash")
