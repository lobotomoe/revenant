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
"""

from __future__ import annotations

import argparse
import datetime
from pathlib import Path
from typing import ClassVar, Literal

from asn1crypto import algos as aalgos
from asn1crypto import cms as acms
from asn1crypto import core, crl as acrl, x509 as ax509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

# Adobe RevocationInfoArchival attribute OID (used for the LTV-positive fixture).
OID_REVOCATION_INFO_ARCHIVAL = "1.2.840.113583.1.1.8"
OID_SIGNING_CERTIFICATE = "1.2.840.113549.1.9.16.2.12"
OID_SIGNING_CERTIFICATE_V2 = "1.2.840.113549.1.9.16.2.47"

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
) -> x509.Certificate:
    """Create a different identity with the same public key and CMS sid fields."""
    rogue_issuer_key = _key()
    return (
        x509.CertificateBuilder()
        .subject_name(_name("Substituted Identity"))
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


def write(name: str, data: bytes) -> None:
    (OUT_DIR / name).write_bytes(data)
    print(f"wrote {name} ({len(data)} bytes)")


def main(*, ess_only: bool = False) -> None:
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


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ess-only", action="store_true", help="write only ESS CMS fixtures")
    args = parser.parse_args()
    main(ess_only=args.ess_only)
