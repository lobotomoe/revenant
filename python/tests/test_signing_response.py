"""Tests for revenant.core.signing_response — binding a response to its request."""

from __future__ import annotations

import hashlib

import pytest

from revenant.core.signing_response import (
    check_response_over_content,
    check_response_over_digest,
)
from revenant.errors import SigningResponseError

from .conftest import FAKE_CMS


def test_accepts_a_signature_over_the_submitted_bytes(cms_signer):
    content = b"the exact bytes that were submitted"
    check_response_over_content(cms_signer(content), content, "sign_data")


def test_rejects_a_signature_over_different_bytes(cms_signer):
    elsewhere = cms_signer(b"some other document")
    with pytest.raises(SigningResponseError, match="17 bytes submitted"):
        check_response_over_content(elsewhere, b"what we asked for", "sign_data")


def test_rejects_filler_bytes_shaped_like_der():
    with pytest.raises(SigningResponseError, match="not a valid signature"):
        check_response_over_content(FAKE_CMS, b"content", "sign_pdf_detached")


def test_rejects_a_truncated_response(cms_signer):
    cms = cms_signer(b"content")
    with pytest.raises(SigningResponseError):
        check_response_over_content(cms[: len(cms) // 2], b"content", "sign_data")


def test_a_tampered_signature_is_rejected(cms_signer):
    """Flip one bit deep in the signature, leaving the structure intact."""
    content = b"the exact bytes that were submitted"
    cms = bytearray(cms_signer(content))
    cms[-1] ^= 0x01
    with pytest.raises(SigningResponseError):
        check_response_over_content(bytes(cms), content, "sign_data")


def test_a_digest_response_must_still_be_a_real_signature():
    with pytest.raises(SigningResponseError, match="verifiable signature"):
        check_response_over_digest(FAKE_CMS, b"\x00" * 20, "sign_hash")


def test_a_digest_response_binding_the_digest_is_accepted_quietly(cms_signer, caplog):
    """A service that honours the pre-computed digest warrants no warning."""
    import unittest.mock

    digest = hashlib.sha1(b"document").digest()
    cms = cms_signer(b"document")
    with (
        unittest.mock.patch(
            "revenant.core.signing_response.extract_digest_info",
            return_value=("sha1", digest),
        ),
        caplog.at_level("WARNING"),
    ):
        check_response_over_digest(cms, digest, "sign_hash")
    assert caplog.text == ""


def test_a_response_without_a_message_digest_is_a_bug_not_a_quirk(cms_signer):
    """A verified signature must have carried a messageDigest; absence is ours."""
    import unittest.mock

    digest = b"\xab" * 20
    with (
        unittest.mock.patch(
            "revenant.core.signing_response.extract_digest_info", return_value=None
        ),
        pytest.raises(SigningResponseError, match="could not be read consistently"),
    ):
        check_response_over_digest(cms_signer(digest), digest, "sign_hash")


def test_a_digest_response_binding_something_else_is_accepted_but_warns(cms_signer, caplog):
    """The signature is genuine and the submitted bytes were signed -- but it
    cannot be attached to the document the digest came from, so say so."""
    digest = b"\xab" * 20
    cms = cms_signer(digest)
    with caplog.at_level("WARNING"):
        check_response_over_digest(cms, digest, "sign_hash")
    assert "as content rather than treating it as a pre-computed digest" in caplog.text
