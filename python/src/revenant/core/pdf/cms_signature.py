# SPDX-License-Identifier: Apache-2.0
# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false, reportIndexIssue=false, reportAttributeAccessIssue=false
"""Cryptographic verification of CMS ``SignerInfo`` signatures.

The PDF verifier checks two independent properties: the CMS ``messageDigest``
must match the document's ByteRange, and the signature over the DER-encoded
signed attributes must verify with the certificate identified by ``SignerInfo``.
This module implements the second check and deliberately fails closed whenever
the CMS cannot be verified.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from asn1crypto import cms as asn1_cms
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from ..cms_certificates import find_signer_certificate
from .cms_info import resolve_hash_algo

_logger = logging.getLogger(__name__)

_OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
_OID_CONTENT_TYPE = "1.2.840.113549.1.9.3"
_OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"

_RSA_SIGNATURE_OIDS = {
    "1.2.840.113549.1.1.1",  # rsaEncryption (hash is in digestAlgorithm)
    "1.2.840.113549.1.1.5",  # sha1WithRSAEncryption
    "1.2.840.113549.1.1.11",  # sha256WithRSAEncryption
    "1.2.840.113549.1.1.12",  # sha384WithRSAEncryption
    "1.2.840.113549.1.1.13",  # sha512WithRSAEncryption
}

_HASH_ALGORITHMS: dict[str, type[hashes.HashAlgorithm]] = {
    "sha1": hashes.SHA1,
    "sha256": hashes.SHA256,
    "sha384": hashes.SHA384,
    "sha512": hashes.SHA512,
}


@dataclass(frozen=True)
class SignatureVerification:
    """Tri-state CMS signature result.

    ``valid`` is ``None`` when verification could not be performed (for
    example, because the signer certificate or algorithm is unsupported).
    Both ``False`` and ``None`` fail the overall verification verdict.
    """

    valid: bool | None
    reason: str | None = None

    def describe(self) -> str:
        """Return a stable, human-readable diagnostic line."""
        if self.valid is True:
            return "Signature OK -- signer signature verifies"
        if self.valid is False:
            return "Signature INVALID -- does not verify against the signer certificate"
        reason = self.reason or "verification unavailable"
        return f"Signature not verified ({reason})"


def _unverifiable(reason: str) -> SignatureVerification:
    return SignatureVerification(valid=None, reason=reason)


def _resolve_digest_algorithm(signer_info: asn1_cms.SignerInfo) -> hashes.HashAlgorithm | None:
    algo_id = signer_info["digest_algorithm"]["algorithm"]
    algo_name = resolve_hash_algo(algo_id.native)
    if algo_name is None:
        algo_name = resolve_hash_algo(algo_id.dotted)
    hash_type = _HASH_ALGORITHMS.get(algo_name) if algo_name is not None else None
    return hash_type() if hash_type is not None else None


def _validate_signed_attributes(
    signed_data: asn1_cms.SignedData,
    signer_info: asn1_cms.SignerInfo,
    digest_algorithm: hashes.HashAlgorithm,
) -> str | None:
    """Validate mandatory signed attributes and their cardinality."""
    signed_attrs = signer_info["signed_attrs"]
    if signed_attrs.native is None:
        return "no signed attributes"

    content_type_attrs = [attr for attr in signed_attrs if attr["type"].dotted == _OID_CONTENT_TYPE]
    if len(content_type_attrs) != 1 or len(content_type_attrs[0]["values"]) != 1:
        return "contentType attribute missing or duplicated"

    try:
        signed_content_type = content_type_attrs[0]["values"][0].dotted
        encapsulated_content_type = signed_data["encap_content_info"]["content_type"].dotted
    except (AttributeError, KeyError, TypeError, IndexError):
        return "contentType attribute is malformed"
    if signed_content_type != encapsulated_content_type:
        return "contentType attribute is inconsistent"

    digest_attrs = [attr for attr in signed_attrs if attr["type"].dotted == _OID_MESSAGE_DIGEST]
    if len(digest_attrs) != 1 or len(digest_attrs[0]["values"]) != 1:
        return "messageDigest attribute missing or duplicated"
    digest_value = digest_attrs[0]["values"][0].native
    if not isinstance(digest_value, bytes) or len(digest_value) != digest_algorithm.digest_size:
        return "messageDigest attribute is malformed"

    return None


def _signed_attributes_der(signer_info: asn1_cms.SignerInfo) -> bytes | None:
    """Encode signed attributes using the universal SET OF tag required by CMS."""
    signed_attrs = signer_info["signed_attrs"]
    encoded = bytearray(signed_attrs.dump(force=True))
    if not encoded:
        return None
    if encoded[0] == 0xA0:  # [0] IMPLICIT in SignerInfo
        encoded[0] = 0x31  # universal SET OF for the signature input
    elif encoded[0] != 0x31:
        return None
    return bytes(encoded)


def verify_signer_signature(cms_der: bytes) -> SignatureVerification:
    """Verify the first CMS signer's RSA PKCS#1 v1.5 signature.

    Certificate-chain trust is intentionally not checked here; the caller
    reports it separately. Unsupported algorithms, missing certificates, and
    malformed CMS values are reported as unverifiable and never accepted.
    """
    try:
        content_info = asn1_cms.ContentInfo.load(cms_der, strict=True)
        if content_info["content_type"].dotted != _OID_SIGNED_DATA:
            return _unverifiable("CMS content is not SignedData")

        signed_data = content_info["content"]
        signer_infos = signed_data["signer_infos"]
        if not signer_infos:
            return _unverifiable("no SignerInfo present")
        signer_info = signer_infos[0]

        digest_algorithm = _resolve_digest_algorithm(signer_info)
        if digest_algorithm is None:
            return _unverifiable("unrecognized digest algorithm")

        signature_oid = signer_info["signature_algorithm"]["algorithm"].dotted
        if signature_oid not in _RSA_SIGNATURE_OIDS:
            return _unverifiable("non-RSA signer is unsupported")

        attr_error = _validate_signed_attributes(signed_data, signer_info, digest_algorithm)
        if attr_error is not None:
            return _unverifiable(attr_error)

        signer_cert = find_signer_certificate(signed_data, signer_info)
        if signer_cert is None:
            return _unverifiable("signer certificate not embedded or ambiguous")

        signed_attrs_der = _signed_attributes_der(signer_info)
        if signed_attrs_der is None:
            return _unverifiable("cannot encode signed attributes")

        certificate = x509.load_der_x509_certificate(signer_cert.dump())
        public_key = certificate.public_key()
        if not isinstance(public_key, rsa.RSAPublicKey):
            return _unverifiable("signer public key is not RSA")

        public_key.verify(
            signer_info["signature"].native,
            signed_attrs_der,
            padding.PKCS1v15(),
            digest_algorithm,
        )
    except InvalidSignature:
        return SignatureVerification(valid=False)
    except Exception:
        # CMS is untrusted input and verification APIs promise a verdict rather
        # than a parser exception. Log diagnostics and fail closed.
        _logger.debug("Could not verify CMS signer signature", exc_info=True)
        return _unverifiable("CMS signature check failed")

    return SignatureVerification(valid=True)
