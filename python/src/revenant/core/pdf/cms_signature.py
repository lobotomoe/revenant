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

import hmac
import logging
from dataclasses import dataclass
from typing import ClassVar, Literal

from asn1crypto import algos as asn1_algos
from asn1crypto import cms as asn1_cms
from asn1crypto import core as asn1_core
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import load_der_public_key

from ..cms_certificates import find_signer_certificate
from .cms_info import resolve_hash_algo

_logger = logging.getLogger(__name__)

_OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
_OID_CONTENT_TYPE = "1.2.840.113549.1.9.3"
_OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
_TAG_CONTEXT_0_CONSTRUCTED = 0xA0  # [0] IMPLICIT, as signed attrs appear in SignerInfo
_TAG_SET_OF = 0x31  # universal SET OF, as required for the signature input

# Diagnostics are surfaced to users through VerificationResult.details.
_MAX_REASON_LENGTH = 160

_OID_SIGNING_CERTIFICATE = "1.2.840.113549.1.9.16.2.12"
_OID_SIGNING_CERTIFICATE_V2 = "1.2.840.113549.1.9.16.2.47"

_RSA_SIGNATURE_DIGESTS: dict[str, str | None] = {
    "1.2.840.113549.1.1.1": None,  # rsaEncryption (hash is in digestAlgorithm)
    "1.2.840.113549.1.1.5": "sha1",  # sha1WithRSAEncryption
    "1.2.840.113549.1.1.11": "sha256",  # sha256WithRSAEncryption
    "1.2.840.113549.1.1.12": "sha384",  # sha384WithRSAEncryption
    "1.2.840.113549.1.1.13": "sha512",  # sha512WithRSAEncryption
}

_HASH_ALGORITHMS: dict[str, type[hashes.HashAlgorithm]] = {
    "sha1": hashes.SHA1,
    "sha256": hashes.SHA256,
    "sha384": hashes.SHA384,
    "sha512": hashes.SHA512,
}


class _ESSCertID(asn1_core.Sequence):
    _fields: ClassVar[list[object]] = [
        ("cert_hash", asn1_core.OctetString),
        ("issuer_serial", asn1_core.Any, {"optional": True}),
    ]


class _ESSCertIDs(asn1_core.SequenceOf):
    _child_spec = _ESSCertID


class _SigningCertificate(asn1_core.Sequence):
    _fields: ClassVar[list[object]] = [
        ("certs", _ESSCertIDs),
        ("policies", asn1_core.Any, {"optional": True}),
    ]


class _ESSCertIDv2(asn1_core.Sequence):
    _fields: ClassVar[list[object]] = [
        (
            "hash_algorithm",
            asn1_algos.DigestAlgorithm,
            {"default": {"algorithm": "sha256"}},
        ),
        ("cert_hash", asn1_core.OctetString),
        ("issuer_serial", asn1_core.Any, {"optional": True}),
    ]


class _ESSCertIDsV2(asn1_core.SequenceOf):
    _child_spec = _ESSCertIDv2


class _SigningCertificateV2(asn1_core.Sequence):
    _fields: ClassVar[list[object]] = [
        ("certs", _ESSCertIDsV2),
        ("policies", asn1_core.Any, {"optional": True}),
    ]


@dataclass(frozen=True)
class SignatureVerification:
    """Tri-state CMS signature result.

    ``valid`` is ``None`` when verification could not be performed (for
    example, because the signer certificate or algorithm is unsupported).
    Both ``False`` and ``None`` fail the overall verification verdict.
    """

    valid: bool | None
    reason: str | None = None
    signer_certificate_bound: bool = False
    #: True when the CMS carries no signed attributes and the signature was
    #: verified over the caller-supplied content itself, so no separate digest
    #: exists to compare and the signature verdict is the integrity check.
    #: Never true for content the caller did not supply.
    covers_content: bool = False

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


def _describe_exception(error: Exception) -> str:
    """Render an exception compactly enough to sit in a user-facing detail line."""
    message = str(error).strip().replace("\n", " ")
    if len(message) > _MAX_REASON_LENGTH:
        message = message[: _MAX_REASON_LENGTH - 3] + "..."
    return f"{type(error).__name__}: {message}" if message else type(error).__name__


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


def _retag_as_set_of(encoded: bytes) -> bytes | None:
    """Replace the ``[0] IMPLICIT`` tag with the universal SET OF tag."""
    if not encoded:
        return None
    retagged = bytearray(encoded)
    if retagged[0] == _TAG_CONTEXT_0_CONSTRUCTED:
        retagged[0] = _TAG_SET_OF
    elif retagged[0] != _TAG_SET_OF:
        return None
    return bytes(retagged)


def _signed_attributes_signature_inputs(signer_info: asn1_cms.SignerInfo) -> list[bytes]:
    """Return the candidate byte strings the signer may have signed.

    RFC 5652 section 5.4 defines the signature input as the DER encoding of the
    signed attributes with the ``[0] IMPLICIT`` tag replaced by a universal
    ``SET OF`` tag.  Signers that emit a non-DER attribute ordering nevertheless
    sign the bytes they transmitted, so the as-transmitted encoding is tried
    first and the canonical DER re-encoding second.

    Accepting either encoding does not weaken the check: both encode the very
    same parsed attributes, and those attributes are validated independently by
    :func:`_validate_signed_attributes` before any signature is checked.
    """
    signed_attrs = signer_info["signed_attrs"]
    candidates: list[bytes] = []
    for encoded in (signed_attrs.dump(), signed_attrs.dump(force=True)):
        retagged = _retag_as_set_of(encoded)
        if retagged is not None and retagged not in candidates:
            candidates.append(retagged)
    return candidates


SigningCertificateBinding = Literal["absent", "match", "mismatch", "unparsable"]


def _single_signing_certificate_binding(
    binding_attr: asn1_cms.CMSAttribute,
    signer_cert_der: bytes,
) -> SigningCertificateBinding:
    """Evaluate one ESS certificate-binding attribute."""
    if len(binding_attr["values"]) != 1:
        return "unparsable"

    is_v2 = binding_attr["type"].dotted == _OID_SIGNING_CERTIFICATE_V2
    try:
        value_der = binding_attr["values"][0].dump()
        if is_v2:
            parsed = _SigningCertificateV2.load(value_der, strict=True)
            if not parsed["certs"]:
                return "unparsable"
            cert_id = parsed["certs"][0]
            algorithm_id = cert_id["hash_algorithm"]["algorithm"]
            algorithm_name = resolve_hash_algo(algorithm_id.native)
            if algorithm_name is None:
                algorithm_name = resolve_hash_algo(algorithm_id.dotted)
            hash_type = _HASH_ALGORITHMS.get(algorithm_name) if algorithm_name else None
            if hash_type is None:
                return "unparsable"
            hash_algorithm = hash_type()
        else:
            parsed = _SigningCertificate.load(value_der, strict=True)
            if not parsed["certs"]:
                return "unparsable"
            cert_id = parsed["certs"][0]
            # RFC 2634 fixes ESSCertID v1 to SHA-1, so there is no stronger
            # option inside this attribute, and refusing v1 outright is not open
            # to us either: real signers still emit it alone. It is checked
            # because checking beats ignoring, not because SHA-1 is sound -- a
            # certificate-hash binding does rest on collision resistance, so it
            # counts as defence in depth over chain validation rather than proof
            # by itself. Every binding present must match (see
            # _signing_certificate_binding), so a signer that also emits v2
            # cannot be satisfied by a v1 collision alone.
            hash_algorithm = hashes.SHA1()  # noqa: S303

        expected_hash = cert_id["cert_hash"].native
        if not isinstance(expected_hash, bytes):
            return "unparsable"
    except Exception:
        return "unparsable"

    digest = hashes.Hash(hash_algorithm)
    digest.update(signer_cert_der)
    if not hmac.compare_digest(digest.finalize(), expected_hash):
        return "mismatch"
    return "match"


def _signing_certificate_binding(
    signer_info: asn1_cms.SignerInfo,
    signer_cert_der: bytes,
) -> SigningCertificateBinding:
    """Classify all optional ESS certificate bindings against the signer cert."""
    signed_attrs = signer_info["signed_attrs"]
    binding_attrs = [
        attr
        for attr in signed_attrs
        if attr["type"].dotted in {_OID_SIGNING_CERTIFICATE, _OID_SIGNING_CERTIFICATE_V2}
    ]
    if not binding_attrs:
        return "absent"

    binding_oids = [attr["type"].dotted for attr in binding_attrs]
    if len(set(binding_oids)) != len(binding_oids):
        return "unparsable"

    statuses = [
        _single_signing_certificate_binding(binding_attr, signer_cert_der)
        for binding_attr in binding_attrs
    ]
    if "mismatch" in statuses:
        return "mismatch"
    if "unparsable" in statuses:
        return "unparsable"
    return "match"


def verify_signer_signature(
    cms_der: bytes,
    content: bytes | None = None,
) -> SignatureVerification:
    """Verify the first CMS signer's RSA PKCS#1 v1.5 signature.

    Certificate-chain trust is intentionally not checked here; the caller
    reports it separately. Unsupported algorithms, missing certificates, and
    malformed CMS values are reported as unverifiable and never accepted.

    Args:
        cms_der: DER-encoded CMS/PKCS#7 ``SignedData``.
        content: The detached content the signature covers. Consulted when the
            CMS carries no signed attributes -- RFC 5652 section 5.4 defines the
            signature input as the content itself in that case, and signers do
            issue documents in that shape. A CMS that also embeds its own content
            is rejected unless the two are byte-identical.
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
        if signature_oid not in _RSA_SIGNATURE_DIGESTS:
            return _unverifiable("non-RSA signer is unsupported")
        signature_digest = _RSA_SIGNATURE_DIGESTS[signature_oid]
        if signature_digest is not None and signature_digest != digest_algorithm.name:
            return _unverifiable("signatureAlgorithm conflicts with digestAlgorithm")

        # RFC 5652 section 5.4: the signature covers the DER-encoded signed
        # attributes when they are present, and the content itself when they are
        # not. The branch is taken strictly on presence -- a CMS that carries
        # signed attributes can never fall back to the content path, so a
        # malformed attribute set still fails closed.
        signed_attrs_present = signer_info["signed_attrs"].native is not None
        if signed_attrs_present:
            attr_error = _validate_signed_attributes(signed_data, signer_info, digest_algorithm)
            if attr_error is not None:
                return _unverifiable(attr_error)
            signature_inputs = _signed_attributes_signature_inputs(signer_info)
            if not signature_inputs:
                return _unverifiable("cannot encode signed attributes")
        else:
            # RFC 5652 section 5.4 makes the content itself the signature input,
            # which leaves the question of whose content. A CMS may carry its own
            # eContent, and a signature over those bytes says nothing about the
            # caller's. Preferring the embedded copy silently re-attributes the
            # verdict to data the signer never saw, so the caller's bytes win and
            # an embedded copy is only ever a duplicate of them.
            embedded = signed_data["encap_content_info"]["content"].native
            if content is not None and embedded is not None and embedded != content:
                return _unverifiable("embedded CMS content differs from the data being verified")
            body = content if content is not None else embedded
            if body is None:
                return _unverifiable("no signed attributes and no content to verify")
            signature_inputs = [body]

        # Without signed attributes there is no messageDigest for the caller to
        # re-check, so this flag is the whole integrity argument downstream. It
        # may only be raised when the bytes fed to the signature were the ones
        # the caller asked about.
        covers_caller_content = not signed_attrs_present and content is not None

        signer_cert = find_signer_certificate(signed_data, signer_info)
        if signer_cert is None:
            return _unverifiable("signer certificate not embedded or ambiguous")

        signer_cert_der = signer_cert.dump()
        # Only the public key is needed, so load the SubjectPublicKeyInfo rather
        # than the whole certificate. Signer certificates issued in the field
        # encode DN attributes such as emailAddress as a PrintableString
        # holding '@', which is outside that type's character set; a strict X.509
        # parser rejects the entire certificate over a field this check never
        # reads. Signature verification must not depend on decoding the subject DN.
        try:
            public_key = load_der_public_key(
                signer_cert["tbs_certificate"]["subject_public_key_info"].dump()
            )
        except (ValueError, UnsupportedAlgorithm):
            return _unverifiable("signer public key is unusable")
        if not isinstance(public_key, rsa.RSAPublicKey):
            return _unverifiable("signer public key is not RSA")

        signature = signer_info["signature"].native
        for signature_input in signature_inputs:
            try:
                public_key.verify(
                    signature,
                    signature_input,
                    padding.PKCS1v15(),
                    digest_algorithm,
                )
                break
            except InvalidSignature:
                continue
        else:
            return SignatureVerification(valid=False, covers_content=covers_caller_content)

        # An ESS binding lives in the signed attributes, so without them there is
        # nothing to bind the certificate beyond the signature itself.
        binding: SigningCertificateBinding = "absent"
        if signed_attrs_present:
            binding = _signing_certificate_binding(signer_info, signer_cert_der)
            if binding == "mismatch":
                return _unverifiable("signingCertificate attribute names a different certificate")
            if binding == "unparsable":
                return _unverifiable("signingCertificate attribute could not be parsed")
    except Exception as e:
        # CMS is untrusted input and this API promises a verdict rather than a
        # parser exception, so it fails closed.  The reason names the underlying
        # exception: an opaque "check failed" once masked a certificate-parsing
        # incompatibility that silently invalidated genuine signatures, and a
        # diagnostic nobody can read is how that reaches production unnoticed.
        _logger.warning("Could not verify CMS signer signature: %s", e, exc_info=True)
        return _unverifiable(f"CMS signature check failed -- {_describe_exception(e)}")

    return SignatureVerification(
        valid=True,
        signer_certificate_bound=binding == "match",
        covers_content=covers_caller_content,
    )
