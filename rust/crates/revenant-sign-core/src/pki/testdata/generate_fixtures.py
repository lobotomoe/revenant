#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Generate the DER certificate + CMS fixtures shared by all implementations.

These are deterministic test vectors produced by the *Python* `cryptography`
library, so the Rust reader/verifier is validated against an independent,
mature implementation (a real interop check, not Rust-writes/Rust-reads).

Validity windows are deliberately wide (2020..2099) so the fixtures do not
expire and cause spurious test failures.

Regenerate with:
    python/.venv/bin/python \\
        crates/revenant-sign-core/src/pki/testdata/generate_fixtures.py

Pass ``--ess-only`` to update only the shared ESS CMS fixtures.
Pass ``--identity-only`` to update only the signer-identity regression fixtures.
Pass ``--aia-only`` to update only the AIA chain-building regression fixture.
Pass ``--signer-only`` to update only the runtime test signer material.

``test_signer_key.der`` is a throwaway RSA key committed on purpose: the signing
tests must produce real signatures over data computed during the test run, which
no pre-built fixture can cover. It signs nothing outside this test suite, is not
trusted by any profile, and must never be reused.
"""

from __future__ import annotations

import argparse
import datetime
from pathlib import Path
from typing import ClassVar, Literal

from asn1crypto import algos as aalgos
from asn1crypto import cms as acms
from asn1crypto import core, crl as acrl, keys as akeys, x509 as ax509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

# Adobe RevocationInfoArchival attribute OID (used for the LTV-positive fixture).
OID_REVOCATION_INFO_ARCHIVAL = "1.2.840.113583.1.1.8"
OID_SIGNING_CERTIFICATE = "1.2.840.113549.1.9.16.2.12"
OID_SIGNING_CERTIFICATE_V2 = "1.2.840.113549.1.9.16.2.47"

# '@' is outside the PrintableString character set; see build_nonconforming_dn_cms.
NONCONFORMING_DN_EMAIL = "signer@example.com"

NOT_BEFORE = datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc)
NOT_AFTER = datetime.datetime(2099, 1, 1, tzinfo=datetime.timezone.utc)
OUT_DIR = Path(__file__).resolve().parent


class _EssCertId(core.Sequence):
    _fields: ClassVar[list[object]] = [
        ("cert_hash", core.OctetString),
        ("issuer_serial", core.Any, {"optional": True}),
    ]


class _EssCertIds(core.SequenceOf):
    _child_spec = _EssCertId


class _SigningCertificate(core.Sequence):
    _fields: ClassVar[list[object]] = [
        ("certs", _EssCertIds),
        ("policies", core.Any, {"optional": True}),
    ]


class _EssCertIdV2(core.Sequence):
    _fields: ClassVar[list[object]] = [
        (
            "hash_algorithm",
            aalgos.DigestAlgorithm,
            {"default": {"algorithm": "sha256"}},
        ),
        ("cert_hash", core.OctetString),
        ("issuer_serial", core.Any, {"optional": True}),
    ]


class _EssCertIdsV2(core.SequenceOf):
    _child_spec = _EssCertIdV2


class _SigningCertificateV2(core.Sequence):
    _fields: ClassVar[list[object]] = [
        ("certs", _EssCertIdsV2),
        ("policies", core.Any, {"optional": True}),
    ]


def _key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _ca_key_usage() -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=False,
        key_encipherment=False,
        content_commitment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=True,
        crl_sign=True,
        encipher_only=False,
        decipher_only=False,
    )


def make_root_ca(cn: str) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    key = _key()
    name = _name(cn)
    ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(_ca_key_usage(), critical=True)
        .add_extension(ski, critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return cert, key


def make_intermediate(
    issuer_cert: x509.Certificate, issuer_key: rsa.RSAPrivateKey, cn: str
) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    key = _key()
    ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(issuer_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(_ca_key_usage(), critical=True)
        .add_extension(ski, critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_cert.public_key()),
            critical=False,
        )
        .sign(issuer_key, hashes.SHA256())
    )
    return cert, key


def make_leaf(
    issuer_cert: x509.Certificate,
    issuer_key: rsa.RSAPrivateKey,
    cn: str,
    aia_url: str | None = None,
) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    key = _key()
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(issuer_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_cert.public_key()),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False
        )
    )
    if aia_url is not None:
        builder = builder.add_extension(
            x509.AuthorityInformationAccess(
                [
                    x509.AccessDescription(
                        x509.oid.AuthorityInformationAccessOID.CA_ISSUERS,
                        x509.UniformResourceIdentifier(aia_url),
                    )
                ]
            ),
            critical=False,
        )
    return builder.sign(issuer_key, hashes.SHA256()), key


def make_no_aki() -> x509.Certificate:
    """A cert with no AKI whose issuer != subject (chain building stops at 1)."""
    key = _key()
    return (
        x509.CertificateBuilder()
        .subject_name(_name("No AKI"))
        .issuer_name(_name("Other"))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .sign(key, hashes.SHA256())
    )


def to_der(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.DER)


def build_cms(
    leaf: x509.Certificate,
    leaf_key: rsa.RSAPrivateKey,
    extra: list[x509.Certificate] | None = None,
) -> bytes:
    builder = (
        pkcs7.PKCS7SignatureBuilder()
        .set_data(b"test data")
        .add_signer(leaf, leaf_key, hashes.SHA256())
    )
    for cert in extra or []:
        builder = builder.add_certificate(cert)
    return builder.sign(serialization.Encoding.DER, [pkcs7.PKCS7Options.Binary])


def _digest(data: bytes, algorithm: hashes.HashAlgorithm) -> bytes:
    digest = hashes.Hash(algorithm)
    digest.update(data)
    return digest.finalize()


def build_ess_bound_cms(
    signer: x509.Certificate,
    signer_key: rsa.RSAPrivateKey,
    version: Literal["v1", "v2"],
    *,
    v2_hash: Literal["sha384"] | None = None,
    malformed: bool = False,
) -> bytes:
    """Build a valid CMS whose signed attributes contain an ESS cert binding."""
    content_info = acms.ContentInfo.load(build_cms(signer, signer_key))
    signer_info = content_info["content"]["signer_infos"][0]

    if malformed:
        binding_value: core.Asn1Value = core.OctetString(b"not a sequence")
    else:
        cert_der = to_der(signer)
        if version == "v1":
            binding_value = _SigningCertificate(
                {"certs": [{"cert_hash": _digest(cert_der, hashes.SHA1())}]}
            )
        else:
            hash_algorithm: hashes.HashAlgorithm = (
                hashes.SHA384() if v2_hash == "sha384" else hashes.SHA256()
            )
            cert_id: dict[str, object] = {
                "cert_hash": _digest(cert_der, hash_algorithm)
            }
            if v2_hash is not None:
                cert_id["hash_algorithm"] = {"algorithm": v2_hash}
            binding_value = _SigningCertificateV2({"certs": [cert_id]})

    binding_oid = (
        OID_SIGNING_CERTIFICATE if version == "v1" else OID_SIGNING_CERTIFICATE_V2
    )
    binding_attr = acms.CMSAttribute(
        {"type": binding_oid, "values": [core.Any(binding_value)]}
    )
    signer_info["signed_attrs"] = acms.CMSAttributes(
        [*signer_info["signed_attrs"], binding_attr]
    )

    signed_attrs = bytearray(signer_info["signed_attrs"].dump(force=True))
    signed_attrs[0] = 0x31  # universal SET OF tag used as the signature input
    signer_info["signature"] = signer_key.sign(
        bytes(signed_attrs),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    return content_info.dump(force=True)


def replacement_certificate(
    original: x509.Certificate,
    signer_key: rsa.RSAPrivateKey,
    cn: str = "Substituted Identity",
) -> x509.Certificate:
    """Create a different identity with the same public key and CMS sid fields."""
    rogue_issuer_key = _key()
    return (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(original.issuer)
        .public_key(signer_key.public_key())
        .serial_number(original.serial_number)
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .sign(rogue_issuer_key, hashes.SHA256())
    )


def substitute_embedded_certificate(
    cms_der: bytes, replacement: x509.Certificate
) -> bytes:
    """Replace the embedded signer certificate without changing SignerInfo."""
    content_info = acms.ContentInfo.load(cms_der)
    asn1_certificate = ax509.Certificate.load(to_der(replacement))
    content_info["content"]["certificates"] = acms.CertificateSet(
        [acms.CertificateChoices(name="certificate", value=asn1_certificate)]
    )
    return content_info.dump(force=True)


def build_ski_selector_confusion_cms() -> bytes:
    """Build a CMS where extension-SKI and PKIjs key-hash selection diverge.

    The SignerInfo SID names the ``Claimed identity`` certificate through its
    Subject Key Identifier extension.  The signature was made by a different
    certificate whose public-key SHA-1 happens to equal that SID.  PKIjs 3.4.0
    selects the latter by hashing SubjectPublicKeyInfo instead of reading the
    certificate extension, which used to let verification and identity display
    use different certificates.
    """
    root, root_key = make_root_ca("Selector Test Root")
    actual_key = _key()
    actual_key_id = x509.SubjectKeyIdentifier.from_public_key(actual_key.public_key()).digest

    actual_cert = (
        x509.CertificateBuilder()
        .subject_name(_name("Actual signer"))
        .issuer_name(root.subject)
        .public_key(actual_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .add_extension(x509.SubjectKeyIdentifier(b"\x42" * 20), critical=False)
        .sign(root_key, hashes.SHA256())
    )

    claimed_key = _key()
    claimed_cert = (
        x509.CertificateBuilder()
        .subject_name(_name("Claimed identity"))
        .issuer_name(root.subject)
        .public_key(claimed_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .add_extension(x509.SubjectKeyIdentifier(actual_key_id), critical=False)
        .sign(root_key, hashes.SHA256())
    )

    content_info = acms.ContentInfo.load(build_cms(actual_cert, actual_key, [claimed_cert]))
    content_info["content"]["signer_infos"][0]["sid"] = acms.SignerIdentifier(
        name="subject_key_identifier",
        value=actual_key_id,
    )
    return content_info.dump(force=True)


def build_trusted_cert_listed_first_cms() -> bytes:
    """Build a CMS signed by an untrusted key that lists a trusted root first.

    The signature is made by a self-signed certificate no trust store knows, but
    the committed ``root.der`` anchor is placed ahead of it in ``certificates``.
    A verifier that reads the set positionally builds its chain from the anchor,
    reports the signature as trusted, and shows the anchor's identity as the
    signer. ``certificates`` is a SET OF, so position carries no such meaning.
    """
    attacker, attacker_key = make_root_ca("Untrusted Attacker Signer")
    trusted_root = ax509.Certificate.load((OUT_DIR / "root.der").read_bytes())

    content_info = acms.ContentInfo.load(build_cms(attacker, attacker_key))
    content_info["content"]["certificates"] = acms.CertificateSet(
        [
            acms.CertificateChoices(name="certificate", value=trusted_root),
            acms.CertificateChoices(
                name="certificate",
                value=ax509.Certificate.load(to_der(attacker)),
            ),
        ]
    )
    return content_info.dump(force=True)


def build_nonconforming_dn_cms() -> bytes:
    """Build a valid CMS whose signer certificate has a nonconforming subject DN.

    The ``emailAddress`` attribute is encoded as a ``PrintableString`` even though
    '@' lies outside that type's character set.  Production signer certificates
    (EKENG/CoSign among them) really are issued this way, and strict X.509 parsers
    reject the certificate as a whole over a field signature verification never
    reads.  A verifier must derive the signer's public key without decoding the
    subject DN, so this vector fails closed for any implementation that does not.

    ``cryptography`` refuses to emit such a certificate, so the TBS is assembled
    with asn1crypto, retagged, and only then signed -- the result is a genuinely
    self-consistent certificate rather than one with a broken signature.
    """
    key = _key()
    serial = 0x4E4F4E434F4E46  # "NONCONF"
    algorithm = aalgos.SignedDigestAlgorithm({"algorithm": "sha256_rsa"})
    name = ax509.Name.build(
        {"common_name": "Nonconforming DN Signer", "email_address": NONCONFORMING_DN_EMAIL}
    )
    spki = akeys.PublicKeyInfo.load(
        key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    tbs = ax509.TbsCertificate(
        {
            "version": "v3",
            "serial_number": serial,
            "signature": algorithm,
            "issuer": name,
            "subject": name,
            "subject_public_key_info": spki,
            "validity": ax509.Validity(
                {
                    # RFC 5280: dates through 2049 are UTCTime, later ones GeneralizedTime.
                    "not_before": ax509.Time({"utc_time": NOT_BEFORE}),
                    "not_after": ax509.Time({"general_time": NOT_AFTER}),
                }
            ),
        }
    )

    ia5_email = bytes([0x16, len(NONCONFORMING_DN_EMAIL)]) + NONCONFORMING_DN_EMAIL.encode()
    printable_email = bytes([0x13, len(NONCONFORMING_DN_EMAIL)]) + NONCONFORMING_DN_EMAIL.encode()
    tbs_der = tbs.dump()
    if ia5_email not in tbs_der:
        raise AssertionError("email attribute was not encoded as the expected IA5String")
    tbs_der = tbs_der.replace(ia5_email, printable_email)

    patched_tbs = ax509.TbsCertificate.load(tbs_der)
    cert = ax509.Certificate(
        {
            "tbs_certificate": patched_tbs,
            "signature_algorithm": algorithm,
            "signature_value": key.sign(tbs_der, padding.PKCS1v15(), hashes.SHA256()),
        }
    )
    # The SignerIdentifier must carry the retagged issuer bytes: implementations
    # that select the signer certificate by comparing encoded names would
    # otherwise find no match, masking what this vector is meant to exercise.
    issuer_name = patched_tbs["issuer"]

    content = b"test data"
    signed_attrs = acms.CMSAttributes(
        [
            acms.CMSAttribute({"type": "content_type", "values": [acms.ContentType("data")]}),
            acms.CMSAttribute(
                {"type": "message_digest", "values": [core.OctetString(_digest(content, hashes.SHA256()))]}
            ),
        ]
    )
    signature_input = bytearray(signed_attrs.dump(force=True))
    signature_input[0] = 0x31  # universal SET OF tag used as the signature input

    signer_info = acms.SignerInfo(
        {
            "version": "v1",
            "sid": acms.SignerIdentifier(
                name="issuer_and_serial_number",
                value=acms.IssuerAndSerialNumber(
                    {"issuer": issuer_name, "serial_number": serial}
                ),
            ),
            "digest_algorithm": aalgos.DigestAlgorithm({"algorithm": "sha256"}),
            "signed_attrs": signed_attrs,
            "signature_algorithm": aalgos.SignedDigestAlgorithm(
                {"algorithm": "rsassa_pkcs1v15"}
            ),
            "signature": key.sign(bytes(signature_input), padding.PKCS1v15(), hashes.SHA256()),
        }
    )

    return acms.ContentInfo(
        {
            "content_type": "signed_data",
            "content": acms.SignedData(
                {
                    "version": "v1",
                    "digest_algorithms": [aalgos.DigestAlgorithm({"algorithm": "sha256"})],
                    "encap_content_info": {"content_type": "data"},
                    "certificates": [cert],
                    "signer_infos": [signer_info],
                }
            ),
        }
        # Plain dump(): force=True would re-encode the certificate against the
        # asn1crypto spec and silently revert emailAddress to an IA5String,
        # destroying the very quirk this vector exists to capture.
    ).dump()


def _der_length(size: int) -> bytes:
    if size < 0x80:
        return bytes([size])
    encoded = size.to_bytes((size.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def build_der_signed_unsorted_transmitted_cms(
    signer: x509.Certificate,
    signer_key: rsa.RSAPrivateKey,
) -> bytes:
    """Build a CMS signed over canonical DER but transmitting another ordering.

    RFC 5652 section 5.4 defines the signature input as the DER encoding of the
    signed attributes, and a conforming signer transmits exactly those bytes.
    This vector separates the two so that verifiers relying solely on the
    as-transmitted encoding are caught: all implementations must agree that the
    signature is valid, since both encodings carry the same parsed attributes.
    """
    content_info = acms.ContentInfo.load(build_cms(signer, signer_key))
    signer_info = content_info["content"]["signer_infos"][0]

    canonical = bytearray(signer_info["signed_attrs"].dump(force=True))
    canonical[0] = 0x31  # universal SET OF tag used as the signature input

    members = [attribute.dump() for attribute in signer_info["signed_attrs"]]
    members.reverse()
    body = b"".join(members)
    transmitted = bytes([0x31]) + _der_length(len(body)) + body
    if transmitted == bytes(canonical):
        raise AssertionError("transmitted ordering must differ from canonical DER")

    signer_info["signed_attrs"] = acms.CMSAttributes.load(transmitted)
    signer_info["signature"] = signer_key.sign(
        bytes(canonical), padding.PKCS1v15(), hashes.SHA256()
    )
    # Plain dump(): force=True would re-sort the attributes back into DER order.
    return content_info.dump()


def build_no_signed_attrs_cms(
    signer: x509.Certificate,
    signer_key: rsa.RSAPrivateKey,
) -> bytes:
    """Build a detached CMS that carries no signed attributes at all.

    RFC 5652 section 5.4 makes ``signedAttrs`` optional: when it is absent the
    signature is computed over the content itself rather than over the encoded
    attributes. EKENG issues its credential documents in exactly this shape, so
    a verifier that requires signed attributes rejects genuine signatures.
    """
    content = b"test data"
    signer_info = acms.SignerInfo(
        {
            "version": "v1",
            "sid": acms.SignerIdentifier(
                name="issuer_and_serial_number",
                value=acms.IssuerAndSerialNumber(
                    {
                        "issuer": ax509.Certificate.load(to_der(signer))["tbs_certificate"][
                            "issuer"
                        ],
                        "serial_number": signer.serial_number,
                    }
                ),
            ),
            "digest_algorithm": aalgos.DigestAlgorithm({"algorithm": "sha256"}),
            "signature_algorithm": aalgos.SignedDigestAlgorithm({"algorithm": "rsassa_pkcs1v15"}),
            "signature": signer_key.sign(content, padding.PKCS1v15(), hashes.SHA256()),
        }
    )
    return acms.ContentInfo(
        {
            "content_type": "signed_data",
            "content": acms.SignedData(
                {
                    "version": "v1",
                    "digest_algorithms": [aalgos.DigestAlgorithm({"algorithm": "sha256"})],
                    "encap_content_info": {"content_type": "data"},
                    "certificates": [ax509.Certificate.load(to_der(signer))],
                    "signer_infos": [signer_info],
                }
            ),
        }
    ).dump()


ATTACHED_PAYLOAD = b"payload the signer actually signed"


def build_attached_no_signed_attrs_cms(
    signer: x509.Certificate,
    signer_key: rsa.RSAPrivateKey,
) -> bytes:
    """Build an attached CMS with no signed attributes, carrying its own content.

    The signature covers ``ATTACHED_PAYLOAD``, which travels inside the blob as
    ``encapContentInfo.eContent``. Nothing here is malformed -- this is the shape
    RFC 5652 section 5.4 describes for an attached signature. It is a fixture
    because a verifier that prefers the embedded copy over the caller's own bytes
    will report this signature as proof of a document it never covered.
    """
    signer_info = acms.SignerInfo(
        {
            "version": "v1",
            "sid": acms.SignerIdentifier(
                name="issuer_and_serial_number",
                value=acms.IssuerAndSerialNumber(
                    {
                        "issuer": ax509.Certificate.load(to_der(signer))["tbs_certificate"][
                            "issuer"
                        ],
                        "serial_number": signer.serial_number,
                    }
                ),
            ),
            "digest_algorithm": aalgos.DigestAlgorithm({"algorithm": "sha256"}),
            "signature_algorithm": aalgos.SignedDigestAlgorithm({"algorithm": "rsassa_pkcs1v15"}),
            "signature": signer_key.sign(ATTACHED_PAYLOAD, padding.PKCS1v15(), hashes.SHA256()),
        }
    )
    return acms.ContentInfo(
        {
            "content_type": "signed_data",
            "content": acms.SignedData(
                {
                    "version": "v1",
                    "digest_algorithms": [aalgos.DigestAlgorithm({"algorithm": "sha256"})],
                    "encap_content_info": {
                        "content_type": "data",
                        "content": ATTACHED_PAYLOAD,
                    },
                    "certificates": [ax509.Certificate.load(to_der(signer))],
                    "signer_infos": [signer_info],
                }
            ),
        }
    ).dump()


def write_test_signer_material() -> None:
    """Write a signer certificate together with its private key.

    Every other fixture here is a finished CMS blob, which is enough while the
    signed bytes are fixed. The signing workflow tests are not: they sign a PDF
    whose ByteRange is only known at test time, so the test transport has to
    produce a real signature over data this script never sees. Shipping the key
    lets it do that, and keeps the happy path a genuine signature rather than
    filler bytes that merely look like DER.
    """
    root, root_key = make_root_ca("Test Signer Root")
    signer, signer_key = make_leaf(root, root_key, "Test Runtime Signer")

    write("test_signer_cert.der", to_der(signer))
    write(
        "test_signer_key.der",
        signer_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ),
    )


def write_identity_hardening_fixtures() -> None:
    """Write CMS vectors for signer-certificate and identity regressions."""
    root, root_key = make_root_ca("Identity Test Root")
    signer, signer_key = make_leaf(root, root_key, "Original Display Identity")
    unbound_cms = build_cms(signer, signer_key)
    forged_identity = replacement_certificate(
        signer,
        signer_key,
        cn="Forged Display Identity",
    )

    write("cms_nonconforming_dn.der", build_nonconforming_dn_cms())
    write(
        "cms_der_signed_attrs.der",
        build_der_signed_unsorted_transmitted_cms(signer, signer_key),
    )
    write("cms_no_signed_attrs.der", build_no_signed_attrs_cms(signer, signer_key))
    write(
        "cms_no_attrs_attached.der",
        build_attached_no_signed_attrs_cms(signer, signer_key),
    )
    write("cms_ski_selector_confusion.der", build_ski_selector_confusion_cms())
    write("cms_trusted_cert_listed_first.der", build_trusted_cert_listed_first_cms())
    write(
        "cms_unbound_identity_substituted.der",
        substitute_embedded_certificate(unbound_cms, forged_identity),
    )


def write_aia_fixture() -> None:
    """Write a CMS whose signer certificate carries an AIA caIssuers URL.

    The issuing CA is deliberately left out of the blob, so the only way to
    reach it is the URL printed inside the certificate -- the shape that makes
    an implementation following AIA dial a host the document chose. The URL uses
    the reserved .invalid TLD (RFC 2606) so a regression cannot reach anything
    real. Chain building must stop at the missing issuer instead.
    """
    root, root_key = make_root_ca("AIA Test Root")
    signer, signer_key = make_leaf(root, root_key, "AIA Signer", "https://aia.invalid/inter.crt")
    write("cms_leaf_aia.der", build_cms(signer, signer_key))


def build_cms_with_crl(
    signer: x509.Certificate,
    signer_key: rsa.RSAPrivateKey,
    crl_issuer: x509.Certificate,
    crl_issuer_key: rsa.RSAPrivateKey,
) -> bytes:
    """A CMS blob carrying an embedded (empty) CRL -> LTV-enabled via `crls`."""
    crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(crl_issuer.subject)
        .last_update(NOT_BEFORE)
        .next_update(NOT_AFTER)
        .sign(crl_issuer_key, hashes.SHA256())
    )
    content_info = acms.ContentInfo.load(build_cms(signer, signer_key))
    signed_data = content_info["content"]
    crl_der = crl.public_bytes(serialization.Encoding.DER)
    signed_data["crls"] = acms.RevocationInfoChoices(
        [acms.RevocationInfoChoice({"crl": acrl.CertificateList.load(crl_der)})]
    )
    return content_info.dump()


def build_cms_with_archival(signer: x509.Certificate, signer_key: rsa.RSAPrivateKey) -> bytes:
    """A CMS blob whose SignerInfo carries an Adobe RevocationInfoArchival signed
    attribute -> LTV-enabled via a revocation attribute (OCSP)."""
    content_info = acms.ContentInfo.load(build_cms(signer, signer_key))
    signer_info = content_info["content"]["signer_infos"][0]
    existing = list(signer_info["signed_attrs"])
    archival = acms.CMSAttribute(
        {
            "type": OID_REVOCATION_INFO_ARCHIVAL,
            "values": [core.Any(core.OctetString(b"\x01"))],
        }
    )
    signer_info["signed_attrs"] = acms.CMSAttributes([*existing, archival])
    return content_info.dump()


def build_cms_with_unsigned_archival(
    signer: x509.Certificate,
    signer_key: rsa.RSAPrivateKey,
) -> bytes:
    """A CMS whose RevocationInfoArchival sits in the *unsigned* attributes.

    Unsigned attributes are outside the signature, so this is what an attacker
    staples onto a finished document: the signature still verifies and the blob
    now claims to carry revocation evidence the signer never saw.
    """
    content_info = acms.ContentInfo.load(build_cms(signer, signer_key))
    signer_info = content_info["content"]["signer_infos"][0]
    archival = acms.CMSAttribute(
        {
            "type": OID_REVOCATION_INFO_ARCHIVAL,
            "values": [core.Any(core.OctetString(b"\x01"))],
        }
    )
    signer_info["unsigned_attrs"] = acms.CMSAttributes([archival])
    return content_info.dump(force=True)


def write(name: str, data: bytes) -> None:
    (OUT_DIR / name).write_bytes(data)
    print(f"wrote {name} ({len(data)} bytes)")


def main(*, ess_only: bool = False, identity_only: bool = False, aia_only: bool = False) -> None:
    if identity_only:
        write_identity_hardening_fixtures()
        return
    if aia_only:
        write_aia_fixture()
        return

    root, root_key = make_root_ca("Test Root CA")
    inter, inter_key = make_intermediate(root, root_key, "Test Intermediate")
    leaf, leaf_key = make_leaf(inter, inter_key, "Test Signer")
    leaf_direct, leaf_direct_key = make_leaf(root, root_key, "Test Signer Direct")
    leaf_aia, _ = make_leaf(inter, inter_key, "Test Signer AIA", "http://example.com/inter.crt")
    root2, root2_key = make_root_ca("CA Two")
    leaf_root2, leaf_root2_key = make_leaf(root2, root2_key, "Untrusted Signer")
    no_aki = make_no_aki()

    if not ess_only:
        write("root.der", to_der(root))
        write("intermediate.der", to_der(inter))
        write("leaf.der", to_der(leaf))
        write("leaf_direct.der", to_der(leaf_direct))
        write("leaf_aia.der", to_der(leaf_aia))
        write("root2.der", to_der(root2))
        write("leaf_root2.der", to_der(leaf_root2))
        write("no_aki.der", to_der(no_aki))

        # CMS blobs. A SET OF is DER-sorted, so with extra certs the first is not
        # necessarily the signer. The chain fixture deliberately catches clients
        # that incorrectly rely on certificate order instead of SignerInfo.sid.
        write("cms_leaf_direct.der", build_cms(leaf_direct, leaf_direct_key))
        write("cms_leaf_root2.der", build_cms(leaf_root2, leaf_root2_key))
        write("cms_chain3.der", build_cms(leaf, leaf_key, [inter, root]))
        write_aia_fixture()

    ess_v1 = build_ess_bound_cms(leaf_direct, leaf_direct_key, "v1")
    ess_v2 = build_ess_bound_cms(leaf_direct, leaf_direct_key, "v2")
    replacement = replacement_certificate(leaf_direct, leaf_direct_key)
    write("cms_ess_v1.der", ess_v1)
    write("cms_ess_v2.der", ess_v2)
    write(
        "cms_ess_v2_sha384.der",
        build_ess_bound_cms(leaf_direct, leaf_direct_key, "v2", v2_hash="sha384"),
    )
    write(
        "cms_ess_v1_substituted.der",
        substitute_embedded_certificate(ess_v1, replacement),
    )
    write(
        "cms_ess_v2_substituted.der",
        substitute_embedded_certificate(ess_v2, replacement),
    )
    write(
        "cms_ess_v1_malformed.der",
        build_ess_bound_cms(leaf_direct, leaf_direct_key, "v1", malformed=True),
    )

    if not ess_only:
        # LTV-positive CMS fixtures for the `cms::ltv` scan (signatures are not
        # verified by the LTV check, only the presence of revocation data).
        write(
            "cms_with_crl.der",
            build_cms_with_crl(leaf_direct, leaf_direct_key, root, root_key),
        )
        write("cms_with_archival.der", build_cms_with_archival(leaf_direct, leaf_direct_key))
        write(
            "cms_with_unsigned_archival.der",
            build_cms_with_unsigned_archival(leaf_direct, leaf_direct_key),
        )
        write_identity_hardening_fixtures()
        write_test_signer_material()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--ess-only", action="store_true", help="write only ESS CMS fixtures")
    group.add_argument(
        "--identity-only",
        action="store_true",
        help="write only signer identity hardening fixtures",
    )
    group.add_argument(
        "--aia-only",
        action="store_true",
        help="write only the AIA chain-building regression fixture",
    )
    group.add_argument(
        "--signer-only",
        action="store_true",
        help="write only the runtime test signer certificate and key",
    )
    args = parser.parse_args()
    if args.signer_only:
        write_test_signer_material()
    else:
        main(
            ess_only=args.ess_only,
            identity_only=args.identity_only,
            aia_only=args.aia_only,
        )
