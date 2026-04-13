# SPDX-License-Identifier: Apache-2.0
"""Tests for TSL parsing and certificate chain validation."""

from __future__ import annotations

import time
from pathlib import Path
from unittest.mock import patch

import pytest

from revenant.core.tsl import TrustStore, clear_cache, get_trust_store, parse_tsl

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

    # Verify CA anchor names
    ca_names = {a.service_name for a in store.ca_anchors}
    assert "RACitizen" in ca_names
    assert "CA of RoA" in ca_names
    assert "Citizen CA" in ca_names

    # All CA anchors should have cert DER data
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


# ── Chain validation ─────────────────────────────────────────────────


def test_chain_result_for_missing_tsl():
    from revenant.core.chain import validate_chain_for_profile

    with patch("revenant.core.chain.get_trust_store", return_value=None):
        result = validate_chain_for_profile(b"\x30\x00", "https://example.com/tsl.xml")

    assert result.chain_valid is None
    assert "unavailable" in result.details[0]


def test_chain_result_for_empty_cms():
    from revenant.core.chain import validate_chain

    store = TrustStore(
        anchors=(),
        ca_anchors=(),
        scheme_operator="Test",
        tsl_url="https://example.com",
        fetched_at=time.monotonic(),
    )
    result = validate_chain(b"\x30\x00", store)
    assert result.chain_valid is None
    assert result.chain_depth == 0
