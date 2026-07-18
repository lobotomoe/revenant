#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Generate the DER certificate + CMS fixtures used by the Rust pki tests.

These are deterministic test vectors produced by the *Python* `cryptography`
library, so the Rust reader/verifier is validated against an independent,
mature implementation (a real interop check, not Rust-writes/Rust-reads).

Validity windows are deliberately wide (2020..2099) so the fixtures do not
expire and cause spurious test failures.

Regenerate with:
    python/.venv/bin/python \\
        crates/revenant-core/src/pki/testdata/generate_fixtures.py
"""

from __future__ import annotations

import datetime
from pathlib import Path

from asn1crypto import cms as acms
from asn1crypto import core, crl as acrl
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

# Adobe RevocationInfoArchival attribute OID (used for the LTV-positive fixture).
OID_REVOCATION_INFO_ARCHIVAL = "1.2.840.113583.1.1.8"

NOT_BEFORE = datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc)
NOT_AFTER = datetime.datetime(2099, 1, 1, tzinfo=datetime.timezone.utc)
OUT_DIR = Path(__file__).resolve().parent


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


def main() -> None:
    root, root_key = make_root_ca("Test Root CA")
    inter, inter_key = make_intermediate(root, root_key, "Test Intermediate")
    leaf, leaf_key = make_leaf(inter, inter_key, "Test Signer")
    leaf_direct, leaf_direct_key = make_leaf(root, root_key, "Test Signer Direct")
    leaf_aia, _ = make_leaf(inter, inter_key, "Test Signer AIA", "http://example.com/inter.crt")
    root2, root2_key = make_root_ca("CA Two")
    leaf_root2, leaf_root2_key = make_leaf(root2, root2_key, "Untrusted Signer")
    no_aki = make_no_aki()

    write("root.der", to_der(root))
    write("intermediate.der", to_der(inter))
    write("leaf.der", to_der(leaf))
    write("leaf_direct.der", to_der(leaf_direct))
    write("leaf_aia.der", to_der(leaf_aia))
    write("root2.der", to_der(root2))
    write("leaf_root2.der", to_der(leaf_root2))
    write("no_aki.der", to_der(no_aki))

    # CMS blobs. The single-signer blob keeps the leaf as certs[0] (a SET OF is
    # DER-sorted, so with extra certs the first is not necessarily the signer --
    # matching the Python client's behavior; only single-cert blobs are relied
    # on for leaf-first extraction).
    write("cms_leaf_direct.der", build_cms(leaf_direct, leaf_direct_key))
    write("cms_leaf_root2.der", build_cms(leaf_root2, leaf_root2_key))
    write("cms_chain3.der", build_cms(leaf, leaf_key, [inter, root]))

    # LTV-positive CMS fixtures for the `cms::ltv` scan (signatures are not
    # verified by the LTV check, only the presence of revocation data).
    write("cms_with_crl.der", build_cms_with_crl(leaf_direct, leaf_direct_key, root, root_key))
    write("cms_with_archival.der", build_cms_with_archival(leaf_direct, leaf_direct_key))


if __name__ == "__main__":
    main()
