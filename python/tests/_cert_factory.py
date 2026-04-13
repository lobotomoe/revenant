# SPDX-License-Identifier: Apache-2.0
"""Test certificate factory for chain validation tests.

Generates self-signed CAs, intermediates, and leaf certs using the
cryptography library.  All certs are ephemeral and test-only.
"""

from __future__ import annotations

import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def _key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def make_root_ca(cn: str = "Test Root CA") -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    """Create a self-signed root CA certificate."""
    key = _key()
    subject = issuer = _name(cn)
    ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc))
        .not_valid_after(datetime.datetime(2035, 1, 1, tzinfo=datetime.timezone.utc))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(ski, critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return cert, key


def make_intermediate(
    issuer_cert: x509.Certificate,
    issuer_key: rsa.RSAPrivateKey,
    cn: str = "Test Intermediate CA",
) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    """Create an intermediate CA signed by the given issuer."""
    key = _key()
    ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())

    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(issuer_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc))
        .not_valid_after(datetime.datetime(2034, 1, 1, tzinfo=datetime.timezone.utc))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
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
    cn: str = "Test Signer",
    aia_url: str | None = None,
) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    """Create an end-entity (leaf) certificate signed by the given issuer."""
    key = _key()

    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(issuer_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc))
        .not_valid_after(datetime.datetime(2032, 1, 1, tzinfo=datetime.timezone.utc))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_cert.public_key()),
            critical=False,
        )
    )

    # ClientVerifier requires SAN and Key Usage
    builder = (
        builder.add_extension(
            x509.SubjectAlternativeName([x509.RFC822Name(f"{cn.replace(' ', '.')}@test.example")]),
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
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
    )

    if aia_url is not None:
        builder = builder.add_extension(
            x509.AuthorityInformationAccess(
                [
                    x509.AccessDescription(
                        x509.oid.AuthorityInformationAccessOID.CA_ISSUERS,
                        x509.UniformResourceIdentifier(aia_url),
                    ),
                ]
            ),
            critical=False,
        )

    cert = builder.sign(issuer_key, hashes.SHA256())
    return cert, key


def to_der(cert: x509.Certificate) -> bytes:
    """Serialize a certificate to DER bytes."""
    return cert.public_bytes(serialization.Encoding.DER)


def build_cms_with_certs(
    leaf_cert: x509.Certificate,
    leaf_key: rsa.RSAPrivateKey,
    chain_certs: list[x509.Certificate] | None = None,
    data: bytes = b"test data",
) -> bytes:
    """Build a minimal CMS SignedData blob containing the given certs.

    Uses cryptography's PKCS7SignatureBuilder for a real CMS structure.
    """
    from cryptography.hazmat.primitives.serialization import pkcs7

    builder = (
        pkcs7.PKCS7SignatureBuilder()
        .set_data(data)
        .add_signer(leaf_cert, leaf_key, hashes.SHA256())
    )

    if chain_certs:
        for cert in chain_certs:
            builder = builder.add_certificate(cert)

    return builder.sign(serialization.Encoding.DER, [pkcs7.PKCS7Options.Binary])
