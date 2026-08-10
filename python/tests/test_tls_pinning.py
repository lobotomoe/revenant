"""Tests for revenant.network.tls_pinning -- server key pinning."""

import hashlib

import pytest

from revenant.errors import TLSError
from revenant.network.tls_pinning import check_server_pin, spki_fingerprint

from ._cert_factory import make_root_ca, to_der

_CERT, _ = make_root_ca("Pinned Appliance")
CERT_DER = to_der(_CERT)
CERT_PIN = spki_fingerprint(CERT_DER)

_OTHER_CERT, _ = make_root_ca("Someone Else")
OTHER_CERT_DER = to_der(_OTHER_CERT)


def test_fingerprint_is_the_sha256_of_the_subject_public_key_info():
    from asn1crypto import x509

    cert = x509.Certificate.load(CERT_DER)
    spki = cert["tbs_certificate"]["subject_public_key_info"].dump()
    assert hashlib.sha256(spki).hexdigest() == CERT_PIN


def test_fingerprint_is_stable_across_calls():
    assert spki_fingerprint(CERT_DER) == CERT_PIN


def test_two_certificates_have_different_fingerprints():
    assert spki_fingerprint(OTHER_CERT_DER) != CERT_PIN


def test_unparseable_certificate_is_rejected():
    with pytest.raises(TLSError, match="Cannot read the server's public key"):
        spki_fingerprint(b"not a certificate")


def test_matching_pin_is_accepted():
    check_server_pin(CERT_DER, [CERT_PIN], "appliance.example", 8080)


def test_pin_matching_ignores_case_and_colons():
    formatted = ":".join(CERT_PIN[i : i + 2] for i in range(0, len(CERT_PIN), 2)).upper()
    check_server_pin(CERT_DER, [formatted], "appliance.example", 8080)


def test_any_of_several_pins_may_match():
    check_server_pin(CERT_DER, ["00" * 32, CERT_PIN], "appliance.example", 8080)


def test_a_different_key_is_refused():
    with pytest.raises(TLSError, match="not one of its pinned keys") as exc_info:
        check_server_pin(OTHER_CERT_DER, [CERT_PIN], "appliance.example", 8080)
    message = str(exc_info.value)
    # Both sides are named so the operator can tell a rotation from an attack.
    assert spki_fingerprint(OTHER_CERT_DER) in message
    assert CERT_PIN in message


def test_no_pin_is_refused_and_reports_what_the_server_presented():
    with pytest.raises(TLSError, match="No pinned key configured") as exc_info:
        check_server_pin(CERT_DER, [], "appliance.example", 8080)
    assert CERT_PIN in str(exc_info.value)
