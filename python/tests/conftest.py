"""Shared test fixtures for Revenant test suite."""

from __future__ import annotations

from unittest.mock import Mock

import pytest

# Fake CMS blob that satisfies length checks (~1792 bytes).
# Used across signing and workflow tests.
FAKE_CMS = b"\x30\x82\x07\x00" + b"\xab" * 1788


@pytest.fixture
def mock_transport():
    """Create a mock transport with a default URL."""
    from revenant.network.soap_transport import SoapSigningTransport

    transport = Mock(spec=SoapSigningTransport)
    transport.url = "https://example.com"
    return transport


@pytest.fixture
def valid_pdf_bytes():
    """Create a minimal valid PDF using pikepdf."""
    import io

    import pikepdf

    pdf = pikepdf.Pdf.new()
    pdf.add_blank_page(page_size=(612, 792))
    buf = io.BytesIO()
    pdf.save(buf)
    return buf.getvalue()
