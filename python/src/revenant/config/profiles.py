"""
Server profiles for CoSign appliances.

A profile bundles connection details, identity discovery strategies,
and UI strings for a specific CoSign deployment.  Built-in profiles
are defined here; custom servers are represented as ad-hoc instances.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from ..constants import DEFAULT_TIMEOUT_SOAP


@dataclass(frozen=True)
class CertField:
    """How to extract and display a value from certificate/signer info.

    Used for UI display (Account panel, setup wizard) and as building
    blocks for signature appearance fields.

    Attributes:
        id: Unique identifier for the field.
        label: Display label for UI, e.g. "Name", "SSN".
        source: Which signer info field to extract from.
        regex: Optional regex; capture group 1 is extracted.
            If None, the full source value is used.
    """

    id: str
    label: str
    source: Literal["name", "dn", "organization", "email"] = "name"
    regex: str | None = None


@dataclass(frozen=True)
class SigField:
    """A field in the PDF signature appearance.

    References a CertField by id for certificate-derived values,
    or uses auto="date" for auto-generated fields.

    Attributes:
        cert_field: References a CertField.id for the value.
        auto: Auto-generated value type (currently only "date").
        label: Optional prefix label in the signature appearance.
            For auto="date", defaults to "Date" if not set.
    """

    cert_field: str | None = None
    auto: Literal["date"] | None = None
    label: str | None = None


@dataclass(frozen=True)
class ServerProfile:
    """Describes a CoSign server deployment."""

    name: str
    display_name: str
    url: str
    timeout: int = DEFAULT_TIMEOUT_SOAP
    identity_methods: tuple[str, ...] = ("server", "manual")
    legacy_tls: bool = False
    ca_cert_markers: tuple[str, ...] = ()
    max_auth_attempts: int = 0
    cert_fields: tuple[CertField, ...] = ()
    sig_fields: tuple[SigField, ...] = ()
    font: str = "noto-sans"
    cli_description: str = ""

    def has_identity_method(self, method: str) -> bool:
        return method in self.identity_methods


# ── Built-in profiles ────────────────────────────────────────────────

BUILTIN_PROFILES: dict[str, ServerProfile] = {
    "ekeng": ServerProfile(
        name="ekeng",
        display_name="EKENG (Armenian Government)",
        url="https://ca.gov.am:8080/SAPIWS/DSS.asmx",
        timeout=120,
        legacy_tls=True,
        identity_methods=("server", "manual"),
        ca_cert_markers=("ekeng", "\u0567\u056f\u0565\u0576\u0563"),
        max_auth_attempts=5,
        cert_fields=(
            CertField(id="name", label="Name", source="name", regex=r"^(.+?)\s+\d{5,}$"),
            # SSN is intentional. Social Services Number
            CertField(id="gov_id", label="SSN", source="name", regex=r"(\d{5,})$"),
            CertField(id="email", label="Email", source="email"),
        ),
        sig_fields=(
            SigField(cert_field="name"),
            SigField(cert_field="gov_id", label="SSN"),
            SigField(auto="date"),
        ),
        font="ghea-grapalat",
        cli_description="Cross-platform CLI for ARX CoSign electronic signatures (EKENG profile).",
    ),
}


def get_profile(name: str) -> ServerProfile:
    """
    Look up a built-in profile by name.

    Args:
        name: Profile name (case-insensitive).

    Returns:
        The matching ServerProfile.

    Raises:
        KeyError: If no built-in profile matches.
    """
    key = name.lower().strip()
    if key not in BUILTIN_PROFILES:
        available = ", ".join(sorted(BUILTIN_PROFILES))
        msg = f"Unknown profile {name!r}. Available: {available}"
        raise KeyError(msg)
    return BUILTIN_PROFILES[key]


def make_custom_profile(url: str, timeout: int = DEFAULT_TIMEOUT_SOAP) -> ServerProfile:
    """
    Create an ad-hoc profile for a custom server.

    Identity methods default to server + manual.

    Raises:
        ValueError: If the URL scheme or hostname is invalid.
    """
    from urllib.parse import urlparse

    parsed = urlparse(url)
    if parsed.scheme == "http":
        raise ValueError(
            "HTTP URLs are not supported. Use https:// to protect credentials in transit."
        )
    if parsed.scheme != "https":
        raise ValueError(f"Invalid URL scheme {parsed.scheme!r}. Use https://.")
    if not parsed.hostname:
        raise ValueError(f"Invalid URL: no hostname found in {url!r}")

    return ServerProfile(
        name="custom",
        display_name=f"Custom ({url})",
        url=url,
        timeout=timeout,
        identity_methods=("server", "manual"),
    )
