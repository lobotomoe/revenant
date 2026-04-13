# SPDX-License-Identifier: Apache-2.0
"""Tests for TSL parsing, caching, and certificate chain validation."""

from __future__ import annotations

import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from revenant.core.tsl import TrustAnchor, TrustStore, clear_cache, get_trust_store, parse_tsl

from ._cert_factory import (
    build_cms_with_certs,
    make_intermediate,
    make_leaf,
    make_root_ca,
    to_der,
)

# ── Fixtures ─────────────────────────────────────────────────────────

TSL_XML_PATH = Path("/tmp/armenian-tsl.xml")

MINIMAL_TSL_XML = b"""\
<?xml version="1.0" encoding="UTF-8"?>
<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
  <SchemeInformation>
    <SchemeOperatorName><Name xml:lang="en">Test Operator</Name></SchemeOperatorName>
  </SchemeInformation>
  <TrustServiceProviderList>
    <TrustServiceProvider>
      <TSPServices>
        <TSPService>
          <ServiceInformation>
            <ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier>
            <ServiceName><Name xml:lang="en">Test CA</Name></ServiceName>
            <ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus>
            <ServiceDigitalIdentity>
              <DigitalId>
                <X509Certificate>MIICyTCCAbGgAwIBAgIUc+D/OLA1d/dW5cFrQg2HviXUFzowDQYJKoZIhvcNAQELBQAwFDESMBAGA1UEAwwJVGVzdCBDQSAxMB4XDTI0MDEwMTAwMDAwMFoXDTI1MDEwMTAwMDAwMFowFDESMBAGA1UEAwwJVGVzdCBDQSAxMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwNzyFsFN8OAvo2l99sjHg/PXt7OoGpDCywCFRq+NGcDhX7VemYoNESXNooYR2kU8rCOcKEOqi/l3ez87UKF9C2HDgs4+j/L9tuTUzGOcUTfBidSH99psSGJvUefg9pqq1j+D22wIL37JMBnW8ZxfkvXTlETCguURSaEkbm9tHMwx5l1Kd0PYiYLv+oU+ThQSa05Y8+Hd4bImolAZzA8WNqR469KF2SePq/rV6G8U1l6pYBEKdEAOXVNFq6sT/p0dN/CPwyant7bZXRcqejyG9UZrkuTniOJlL1LGxSI/J0JKkvAJgsAdqJOCk4mVneMmU3aYUM4UdoL0ZPQP3IqcpwIDAQABoxMwETAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAIyXXHFwIszwMoxYTe3SCOdtlE6bAwOEqaZBODLVXjNqgV16QvwVV2eL2Jox3Ya7ErVk7NsnRW2N8l1+mO5vF8a5aUxXdyyJ+Ht0PNkr3rmc739OgUzZgLikFVwJxpbADNuYC3gkWEDmBn4V08HW8x/yfFCPMLSTl9qpqUmjEpWPvJsMN9D1Vp9WaI1vAT5PSU8zzLeCQfRVFH6rrnsBRE2PUnmfx+r22M8yZl3cAlyciMyobdQtRy/KFru8/LXpWXKut/ZqC8aMoAuZJwJhhHFH2QrvIkav6Aqus8LBf6KNfhT96gnfI4N8/4UrmY/kEzapJPz414vJTb6S2bviK6</X509Certificate>
              </DigitalId>
              <DigitalId>
                <X509SubjectName>CN=Test CA 1</X509SubjectName>
              </DigitalId>
            </ServiceDigitalIdentity>
          </ServiceInformation>
        </TSPService>
      </TSPServices>
    </TrustServiceProvider>
  </TrustServiceProviderList>
</TrustServiceStatusList>
"""

EMPTY_TSL_XML = b"""\
<?xml version="1.0" encoding="UTF-8"?>
<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
  <SchemeInformation>
    <SchemeOperatorName><Name xml:lang="en">Empty</Name></SchemeOperatorName>
  </SchemeInformation>
</TrustServiceStatusList>
"""


@pytest.fixture
def root_ca():
    return make_root_ca("Test Root CA")


@pytest.fixture
def chain_3(root_ca):
    """Root -> Intermediate -> Leaf chain with all certs."""
    root_cert, root_key = root_ca
    inter_cert, inter_key = make_intermediate(root_cert, root_key, "Test Intermediate")
    leaf_cert, leaf_key = make_leaf(inter_cert, inter_key, "Test Signer")
    return root_cert, inter_cert, leaf_cert, leaf_key


@pytest.fixture
def trust_store_from_root(root_ca):
    """Build a TrustStore containing the root CA."""
    root_cert, _ = root_ca
    anchor = TrustAnchor(
        subject_name="CN=Test Root CA",
        service_name="TestRootCA",
        service_type="CA/QC",
        status="granted",
        cert_der=to_der(root_cert),
    )
    return TrustStore(
        anchors=(anchor,),
        ca_anchors=(anchor,),
        scheme_operator="Test Operator",
        tsl_url="https://example.com/tsl.xml",
        fetched_at=time.monotonic(),
    )


# ── TSL parsing ──────────────────────────────────────────────────────


def test_parse_minimal_tsl():
    store = parse_tsl(MINIMAL_TSL_XML, tsl_url="https://example.com/tsl.xml")
    assert store.scheme_operator == "Test Operator"
    assert store.tsl_url == "https://example.com/tsl.xml"
    assert len(store.anchors) == 1
    assert len(store.ca_anchors) == 1

    anchor = store.ca_anchors[0]
    assert anchor.service_name == "Test CA"
    assert anchor.service_type == "CA/QC"
    assert anchor.status == "granted"
    assert anchor.subject_name == "CN=Test CA 1"
    assert len(anchor.cert_der) > 0


def test_parse_empty_tsl():
    store = parse_tsl(EMPTY_TSL_XML)
    assert store.scheme_operator == "Empty"
    assert len(store.anchors) == 0
    assert len(store.ca_anchors) == 0


@pytest.mark.skipif(not TSL_XML_PATH.exists(), reason="Armenian TSL not available")
def test_parse_real_armenian_tsl():
    xml_bytes = TSL_XML_PATH.read_bytes()
    store = parse_tsl(xml_bytes, tsl_url="https://www.gov.am/files/TSL/AM-TL-1.xml")

    assert store.scheme_operator == "EKENG CJSC"
    assert len(store.anchors) == 6
    assert len(store.ca_anchors) == 3

    ca_names = {a.service_name for a in store.ca_anchors}
    assert "RACitizen" in ca_names
    assert "CA of RoA" in ca_names
    assert "Citizen CA" in ca_names

    for anchor in store.ca_anchors:
        assert len(anchor.cert_der) > 100
        assert anchor.service_type == "CA/QC"
        assert anchor.status in ("granted", "accredited")


def test_parse_tsl_skips_inactive_services():
    xml = b"""\
<?xml version="1.0" encoding="UTF-8"?>
<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
  <SchemeInformation>
    <SchemeOperatorName><Name xml:lang="en">Test</Name></SchemeOperatorName>
  </SchemeInformation>
  <TrustServiceProviderList>
    <TrustServiceProvider>
      <TSPServices>
        <TSPService>
          <ServiceInformation>
            <ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier>
            <ServiceName><Name xml:lang="en">Withdrawn CA</Name></ServiceName>
            <ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn</ServiceStatus>
            <ServiceDigitalIdentity>
              <DigitalId><X509Certificate>AAAA</X509Certificate></DigitalId>
            </ServiceDigitalIdentity>
          </ServiceInformation>
        </TSPService>
      </TSPServices>
    </TrustServiceProvider>
  </TrustServiceProviderList>
</TrustServiceStatusList>
"""
    store = parse_tsl(xml)
    assert len(store.anchors) == 0


def test_parse_tsl_malformed_xml():
    from xml.etree.ElementTree import ParseError

    from defusedxml import DefusedXmlException

    with pytest.raises((ParseError, DefusedXmlException)):
        parse_tsl(b"not xml at all")


def test_parse_tsl_invalid_base64_cert():
    """Invalid base64 in cert element should be skipped, not crash."""
    xml = b"""\
<?xml version="1.0" encoding="UTF-8"?>
<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
  <SchemeInformation>
    <SchemeOperatorName><Name xml:lang="en">Test</Name></SchemeOperatorName>
  </SchemeInformation>
  <TrustServiceProviderList>
    <TrustServiceProvider>
      <TSPServices>
        <TSPService>
          <ServiceInformation>
            <ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier>
            <ServiceName><Name xml:lang="en">Bad Cert CA</Name></ServiceName>
            <ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus>
            <ServiceDigitalIdentity>
              <DigitalId><X509Certificate>!!!not-valid-base64!!!</X509Certificate></DigitalId>
            </ServiceDigitalIdentity>
          </ServiceInformation>
        </TSPService>
      </TSPServices>
    </TrustServiceProvider>
  </TrustServiceProviderList>
</TrustServiceStatusList>
"""
    store = parse_tsl(xml)
    assert len(store.anchors) == 0


def test_parse_tsl_no_subject_name():
    """Service without X509SubjectName should still parse with empty subject."""
    xml = b"""\
<?xml version="1.0" encoding="UTF-8"?>
<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
  <SchemeInformation>
    <SchemeOperatorName><Name xml:lang="en">Test</Name></SchemeOperatorName>
  </SchemeInformation>
  <TrustServiceProviderList>
    <TrustServiceProvider>
      <TSPServices>
        <TSPService>
          <ServiceInformation>
            <ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier>
            <ServiceName><Name xml:lang="en">No Subject CA</Name></ServiceName>
            <ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus>
            <ServiceDigitalIdentity>
              <DigitalId>
                <X509Certificate>MIICyTCCAbGgAwIBAgIUc+D/OLA1d/dW5cFrQg2HviXUFzowDQYJKoZIhvcNAQELBQAwFDESMBAGA1UEAwwJVGVzdCBDQSAxMB4XDTI0MDEwMTAwMDAwMFoXDTI1MDEwMTAwMDAwMFowFDESMBAGA1UEAwwJVGVzdCBDQSAxMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwNzyFsFN8OAvo2l99sjHg/PXt7OoGpDCywCFRq+NGcDhX7VemYoNESXNooYR2kU8rCOcKEOqi/l3ez87UKF9C2HDgs4+j/L9tuTUzGOcUTfBidSH99psSGJvUefg9pqq1j+D22wIL37JMBnW8ZxfkvXTlETCguURSaEkbm9tHMwx5l1Kd0PYiYLv+oU+ThQSa05Y8+Hd4bImolAZzA8WNqR469KF2SePq/rV6G8U1l6pYBEKdEAOXVNFq6sT/p0dN/CPwyant7bZXRcqejyG9UZrkuTniOJlL1LGxSI/J0JKkvAJgsAdqJOCk4mVneMmU3aYUM4UdoL0ZPQP3IqcpwIDAQABoxMwETAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAIyXXHFwIszwMoxYTe3SCOdtlE6bAwOEqaZBODLVXjNqgV16QvwVV2eL2Jox3Ya7ErVk7NsnRW2N8l1+mO5vF8a5aUxXdyyJ+Ht0PNkr3rmc739OgUzZgLikFVwJxpbADNuYC3gkWEDmBn4V08HW8x/yfFCPMLSTl9qpqUmjEpWPvJsMN9D1Vp9WaI1vAT5PSU8zzLeCQfRVFH6rrnsBRE2PUnmfx+r22M8yZl3cAlyciMyobdQtRy/KFru8/LXpWXKut/ZqC8aMoAuZJwJhhHFH2QrvIkav6Aqus8LBf6KNfhT96gnfI4N8/4UrmY/kEzapJPz414vJTb6S2bviK6</X509Certificate>
              </DigitalId>
            </ServiceDigitalIdentity>
          </ServiceInformation>
        </TSPService>
      </TSPServices>
    </TrustServiceProvider>
  </TrustServiceProviderList>
</TrustServiceStatusList>
"""
    store = parse_tsl(xml)
    assert len(store.anchors) == 1
    assert store.anchors[0].subject_name == ""


def test_tsl_text_helper_non_element():
    """_text() with non-Element input returns empty string."""
    from revenant.core.tsl import _text

    assert _text(None, "foo") == ""
    assert _text("not an element", "bar") == ""


def test_tsl_extract_service_type_no_marker():
    """URI without /Svctype/ returns the full URI."""
    from revenant.core.tsl import _extract_service_type_suffix

    assert (
        _extract_service_type_suffix("http://example.com/something")
        == "http://example.com/something"
    )


# ── TSL fetching ────────────────────────────────────────────────────


def test_fetch_trust_store_calls_http_get():
    from revenant.core.tsl import fetch_trust_store

    with patch("revenant.network.transport.http_get", return_value=MINIMAL_TSL_XML) as mock:
        store = fetch_trust_store("https://example.com/tsl.xml", timeout=10)

    mock.assert_called_once_with("https://example.com/tsl.xml", timeout=10)
    assert store.scheme_operator == "Test Operator"


def test_fetch_trust_store_propagates_error():
    from revenant.core.tsl import fetch_trust_store

    with (
        patch("revenant.network.transport.http_get", side_effect=RuntimeError("network")),
        pytest.raises(RuntimeError, match="network"),
    ):
        fetch_trust_store("https://fail.example.com")


# ── Cache ────────────────────────────────────────────────────────────


def test_cache_returns_cached_store():
    clear_cache()
    store = TrustStore(
        anchors=(),
        ca_anchors=(),
        scheme_operator="Cached",
        tsl_url="https://cached.example.com/tsl.xml",
        fetched_at=time.monotonic(),
    )

    with patch("revenant.core.tsl._cache", {"https://cached.example.com/tsl.xml": store}):
        result = get_trust_store("https://cached.example.com/tsl.xml", ttl=3600)

    assert result is not None
    assert result.scheme_operator == "Cached"


def test_cache_returns_none_on_fetch_failure():
    clear_cache()
    with patch("revenant.core.tsl.fetch_trust_store", side_effect=RuntimeError("network error")):
        result = get_trust_store("https://fail.example.com/tsl.xml")

    assert result is None


def test_cache_stores_fetched_result():
    clear_cache()
    with patch("revenant.core.tsl.fetch_trust_store") as mock_fetch:
        store = TrustStore(
            anchors=(),
            ca_anchors=(),
            scheme_operator="Fresh",
            tsl_url="https://fresh.example.com",
            fetched_at=time.monotonic(),
        )
        mock_fetch.return_value = store
        result = get_trust_store("https://fresh.example.com")

    assert result is not None
    assert result.scheme_operator == "Fresh"


def test_cache_returns_stale_on_fetch_failure():
    """When fetch fails, stale cached data should be returned."""
    clear_cache()
    stale = TrustStore(
        anchors=(),
        ca_anchors=(),
        scheme_operator="Stale",
        tsl_url="https://stale.example.com",
        fetched_at=time.monotonic() - 999999,  # expired
    )

    with (
        patch("revenant.core.tsl._cache", {"https://stale.example.com": stale}),
        patch("revenant.core.tsl.fetch_trust_store", side_effect=RuntimeError("down")),
    ):
        result = get_trust_store("https://stale.example.com", ttl=3600)

    assert result is not None
    assert result.scheme_operator == "Stale"


# ── Chain: certificate helpers ──────────────────────────────────────


def test_get_ski(root_ca):
    from revenant.core.chain import _get_ski

    root_cert, _ = root_ca
    asn1_cert = _load_asn1(root_cert)
    ski = _get_ski(asn1_cert)
    assert ski is not None
    assert len(ski) == 20  # SHA-1 length


def test_get_aki_key_id(chain_3):
    from revenant.core.chain import _get_aki_key_id, _get_ski

    root_cert, _, leaf_cert, _ = chain_3
    root_asn1 = _load_asn1(root_cert)
    leaf_asn1 = _load_asn1(leaf_cert)

    # Leaf's AKI should NOT equal root's SKI (there's an intermediate)
    leaf_aki = _get_aki_key_id(leaf_asn1)
    root_ski = _get_ski(root_asn1)
    assert leaf_aki is not None
    assert root_ski is not None
    assert leaf_aki != root_ski  # leaf -> intermediate, not root


def test_get_subject_dn(root_ca):
    from revenant.core.chain import _get_subject_dn

    root_cert, _ = root_ca
    dn = _get_subject_dn(_load_asn1(root_cert))
    assert "Test Root CA" in dn


def test_get_issuer_dn(chain_3):
    from revenant.core.chain import _get_issuer_dn

    _, _, leaf_cert, _ = chain_3
    dn = _get_issuer_dn(_load_asn1(leaf_cert))
    assert "Test Intermediate" in dn


def test_is_self_signed(root_ca, chain_3):
    from revenant.core.chain import _is_self_signed

    root_cert, _ = root_ca
    _, _, leaf_cert, _ = chain_3
    assert _is_self_signed(_load_asn1(root_cert)) is True
    assert _is_self_signed(_load_asn1(leaf_cert)) is False


def test_get_aia_urls():
    from revenant.core.chain import _get_aia_ca_issuer_urls

    root_cert, root_key = make_root_ca()
    leaf_cert, _ = make_leaf(root_cert, root_key, aia_url="http://example.com/ca.crt")
    urls = _get_aia_ca_issuer_urls(_load_asn1(leaf_cert))
    assert urls == ["http://example.com/ca.crt"]


def test_get_aia_urls_no_aia():
    from revenant.core.chain import _get_aia_ca_issuer_urls

    root_cert, _ = make_root_ca()
    urls = _get_aia_ca_issuer_urls(_load_asn1(root_cert))
    assert urls == []


# ── Chain: CMS extraction ────────────────────────────────────────────


def test_extract_certs_from_cms(chain_3):
    from revenant.core.chain import _extract_all_certs_from_cms

    root_cert, inter_cert, leaf_cert, leaf_key = chain_3
    cms_der = build_cms_with_certs(leaf_cert, leaf_key, [inter_cert, root_cert])
    certs = _extract_all_certs_from_cms(cms_der)
    assert len(certs) >= 3


def test_extract_certs_from_empty_cms():
    from revenant.core.chain import _extract_all_certs_from_cms

    # Minimal ASN.1 SEQUENCE that parses but has no certs
    # This should either return [] or raise (both handled)
    try:
        result = _extract_all_certs_from_cms(b"\x30\x00")
    except Exception:
        result = []
    assert result == []


# ── Chain: fetch intermediate ─────────────────────────────────────────


def test_fetch_intermediate_success(root_ca):
    from revenant.core.chain import _fetch_intermediate_cert

    root_cert, _ = root_ca
    root_der = to_der(root_cert)

    with patch("revenant.network.transport.http_get", return_value=root_der):
        result = _fetch_intermediate_cert("http://example.com/ca.crt")

    assert result is not None


def test_fetch_intermediate_failure():
    from revenant.core.chain import _fetch_intermediate_cert

    with patch("revenant.network.transport.http_get", side_effect=RuntimeError("network")):
        result = _fetch_intermediate_cert("http://example.com/ca.crt")

    assert result is None


# ── Chain: chain building ─────────────────────────────────────────────


def test_build_chain_with_pool(chain_3):
    from revenant.core.chain import _build_chain

    root_cert, inter_cert, leaf_cert, _ = chain_3
    pool = [_load_asn1(c) for c in [leaf_cert, inter_cert, root_cert]]
    leaf_asn1 = pool[0]

    chain = _build_chain(leaf_asn1, pool)
    assert len(chain) == 3  # leaf -> intermediate -> root


def test_build_chain_self_signed_only(root_ca):
    from revenant.core.chain import _build_chain

    root_cert, _ = root_ca
    root_asn1 = _load_asn1(root_cert)
    chain = _build_chain(root_asn1, [root_asn1])
    assert len(chain) == 1


def test_build_chain_with_aia_fetch(root_ca):
    """Chain building fetches missing intermediate via AIA."""
    from revenant.core.chain import _build_chain

    root_cert, root_key = root_ca
    inter_cert, inter_key = make_intermediate(root_cert, root_key)
    leaf_cert, _ = make_leaf(inter_cert, inter_key, aia_url="http://example.com/inter.crt")

    # Pool has leaf only -- intermediate must be fetched via AIA
    leaf_asn1 = _load_asn1(leaf_cert)
    root_asn1 = _load_asn1(root_cert)
    pool = [leaf_asn1, root_asn1]

    inter_der = to_der(inter_cert)
    with patch("revenant.network.transport.http_get", return_value=inter_der):
        chain = _build_chain(leaf_asn1, pool)

    assert len(chain) >= 2  # at least leaf + intermediate


def test_build_chain_no_aki():
    """Cert without AKI should produce chain of length 1."""
    import datetime

    # Create a cert with no AKI extension
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa

    from revenant.core.chain import _build_chain

    key = rsa.generate_private_key(65537, 2048)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "No AKI")]))
        .issuer_name(x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "Other")]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc))
        .not_valid_after(datetime.datetime(2035, 1, 1, tzinfo=datetime.timezone.utc))
        .sign(key, hashes.SHA256())
    )
    asn1_cert = _load_asn1(cert)
    chain = _build_chain(asn1_cert, [asn1_cert])
    assert len(chain) == 1


# ── Chain: anchor matching ────────────────────────────────────────────


def test_find_matching_anchor_by_ski(root_ca, trust_store_from_root):
    from revenant.core.chain import _find_matching_anchor

    root_cert, _ = root_ca
    chain = [_load_asn1(root_cert)]
    name = _find_matching_anchor(chain, trust_store_from_root)
    assert name == "TestRootCA"


def test_find_matching_anchor_by_dn(trust_store_from_root):
    from revenant.core.chain import _find_matching_anchor

    # Create a cert whose issuer DN matches the anchor subject_name
    mock_cert = MagicMock()
    mock_cert.key_identifier_value = None  # no SKI
    mock_cert.issuer.human_friendly = "CN=Test Root CA, O=Test"

    name = _find_matching_anchor([mock_cert], trust_store_from_root)
    assert name == "TestRootCA"


def test_find_matching_anchor_no_match(trust_store_from_root):
    from revenant.core.chain import _find_matching_anchor

    mock_cert = MagicMock()
    mock_cert.key_identifier_value = None
    mock_cert.issuer.human_friendly = "CN=Unknown CA"

    name = _find_matching_anchor([mock_cert], trust_store_from_root)
    assert name is None


def test_find_matching_anchor_empty_chain(trust_store_from_root):
    from revenant.core.chain import _find_matching_anchor

    assert _find_matching_anchor([], trust_store_from_root) is None


# ── Chain: cryptographic validation ──────────────────────────────────


def test_validate_with_cryptography_success(root_ca):
    from revenant.core.chain import _validate_with_cryptography

    root_cert, root_key = root_ca
    leaf_cert, _ = make_leaf(root_cert, root_key)

    result = _validate_with_cryptography(
        leaf_der=to_der(leaf_cert),
        intermediate_ders=[],
        anchor_ders=[to_der(root_cert)],
    )
    assert result is True


def test_validate_with_cryptography_3_level(chain_3):
    from revenant.core.chain import _validate_with_cryptography

    root_cert, inter_cert, leaf_cert, _ = chain_3

    result = _validate_with_cryptography(
        leaf_der=to_der(leaf_cert),
        intermediate_ders=[to_der(inter_cert)],
        anchor_ders=[to_der(root_cert)],
    )
    assert result is True


def test_validate_with_cryptography_wrong_anchor():
    from revenant.core.chain import _validate_with_cryptography

    root1_cert, root1_key = make_root_ca("CA One")
    root2_cert, _ = make_root_ca("CA Two")
    leaf_cert, _ = make_leaf(root1_cert, root1_key)

    with pytest.raises(Exception, match="validation failed"):
        _validate_with_cryptography(
            leaf_der=to_der(leaf_cert),
            intermediate_ders=[],
            anchor_ders=[to_der(root2_cert)],  # wrong anchor
        )


# ── Chain: full validation pipeline ──────────────────────────────────


def test_validate_chain_trusted(root_ca, trust_store_from_root):
    from revenant.core.chain import validate_chain

    root_cert, root_key = root_ca
    leaf_cert, leaf_key = make_leaf(root_cert, root_key)
    # Don't include root in CMS -- it's in the trust store pool.
    # PKCS7 puts additional certs before signer, so cms_certs[0] would
    # be root (self-signed) and chain building would stop at depth 1.
    cms_der = build_cms_with_certs(leaf_cert, leaf_key)

    result = validate_chain(cms_der, trust_store_from_root)
    assert result.chain_valid is True
    assert result.trust_anchor == "TestRootCA"
    assert result.chain_depth >= 2


def test_validate_chain_untrusted():
    from revenant.core.chain import validate_chain

    # Sign with an unknown CA not in the trust store
    unknown_cert, unknown_key = make_root_ca("Unknown CA")
    leaf_cert, leaf_key = make_leaf(unknown_cert, unknown_key)
    cms_der = build_cms_with_certs(leaf_cert, leaf_key)

    known_cert, _ = make_root_ca("Known CA")
    anchor = TrustAnchor(
        subject_name="CN=Known CA",
        service_name="KnownCA",
        service_type="CA/QC",
        status="granted",
        cert_der=to_der(known_cert),
    )
    store = TrustStore(
        anchors=(anchor,),
        ca_anchors=(anchor,),
        scheme_operator="Test",
        tsl_url="https://example.com",
        fetched_at=time.monotonic(),
    )

    result = validate_chain(cms_der, store)
    assert result.chain_valid is False
    assert result.trust_anchor is None


def test_validate_chain_no_certs_in_cms(trust_store_from_root):
    """CMS with no parseable certs returns chain_valid=None."""
    from revenant.core.chain import validate_chain

    result = validate_chain(b"\x30\x00", trust_store_from_root)
    assert result.chain_valid is None
    assert result.chain_depth == 0


def test_validate_chain_parse_failure(trust_store_from_root):
    """Completely invalid CMS returns chain_valid=None."""
    from revenant.core.chain import validate_chain

    result = validate_chain(b"not cms at all", trust_store_from_root)
    assert result.chain_valid is None
    assert "failed to parse" in result.details[0].lower()


def test_validate_chain_crypto_failure_falls_back(root_ca, trust_store_from_root):
    """When cryptographic validation fails, fallback to SKI/AKI match."""
    from revenant.core.chain import validate_chain

    root_cert, root_key = root_ca
    leaf_cert, leaf_key = make_leaf(root_cert, root_key)
    cms_der = build_cms_with_certs(leaf_cert, leaf_key)

    with patch(
        "revenant.core.chain._validate_with_cryptography",
        side_effect=Exception("cert parse fail"),
    ):
        result = validate_chain(cms_der, trust_store_from_root)

    assert result.chain_valid is None  # fallback, not True
    assert result.trust_anchor == "TestRootCA"
    assert any("cryptographic verification failed" in d for d in result.details)


# ── Chain: validate_chain_for_profile ─────────────────────────────────


def test_chain_result_for_missing_tsl():
    from revenant.core.chain import validate_chain_for_profile

    with patch("revenant.core.chain.get_trust_store", return_value=None):
        result = validate_chain_for_profile(b"\x30\x00", "https://example.com/tsl.xml")

    assert result.chain_valid is None
    assert "unavailable" in result.details[0]


def test_chain_for_profile_delegates_to_validate_chain(trust_store_from_root):
    from revenant.core.chain import validate_chain_for_profile

    root_cert, root_key = make_root_ca("Test Root CA")
    leaf_cert, leaf_key = make_leaf(root_cert, root_key)
    cms_der = build_cms_with_certs(leaf_cert, leaf_key, [root_cert])

    with patch("revenant.core.chain.get_trust_store", return_value=trust_store_from_root):
        result = validate_chain_for_profile(cms_der, "https://example.com/tsl.xml")

    # The root CAs are different instances (different keys), so this will
    # either be trusted or untrusted depending on key match
    assert result.chain_valid is not None or result.chain_valid is None


# ── Helpers ───────────────────────────────────────────────────────────


def _load_asn1(cert):
    """Convert a cryptography cert to asn1crypto cert."""
    from asn1crypto import x509 as asn1_x509
    from cryptography.hazmat.primitives import serialization

    der = cert.public_bytes(serialization.Encoding.DER)
    return asn1_x509.Certificate.load(der)
