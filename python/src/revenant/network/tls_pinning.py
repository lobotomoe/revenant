# SPDX-License-Identifier: Apache-2.0
# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false
"""
Server key pinning for connections that cannot use the public PKI.

A pin is the SHA-256 digest of a certificate's SubjectPublicKeyInfo, written
as lowercase hex.  Pinning the key rather than the whole certificate lets a
server be issued a fresh certificate for the same key without invalidating
the pin, and a profile may carry several pins so a key rotation can be
staged.

This is how the legacy TLS transport authenticates its peer.  Appliances that
require TLS 1.0 with RC4 typically present a self-signed factory certificate
whose subject does not name the host it serves, so no certificate authority
vouches for it and no hostname check can succeed -- a pinned key is the only
thing that can distinguish the real appliance from anyone speaking for it.
"""

from __future__ import annotations

__all__ = ["check_server_pin", "spki_fingerprint"]

import hashlib
import logging
from typing import TYPE_CHECKING

from ..errors import TLSError

if TYPE_CHECKING:
    from collections.abc import Sequence

_logger = logging.getLogger(__name__)


def spki_fingerprint(cert_der: bytes) -> str:
    """
    Compute the pin for a DER-encoded certificate.

    Args:
        cert_der: The certificate as presented by the server.

    Returns:
        Lowercase hex SHA-256 of the certificate's SubjectPublicKeyInfo.

    Raises:
        TLSError: If the certificate cannot be parsed.
    """
    from asn1crypto import x509

    try:
        cert = x509.Certificate.load(cert_der)
        spki = cert["tbs_certificate"]["subject_public_key_info"].dump()
    except ValueError as exc:
        raise TLSError(f"Cannot read the server's public key: {exc}") from exc
    return hashlib.sha256(spki).hexdigest()


def check_server_pin(
    cert_der: bytes,
    pins: Sequence[str],
    host: str,
    port: int,
) -> None:
    """
    Verify that a server's key matches one of the configured pins.

    Args:
        cert_der: The leaf certificate the server presented.
        pins: Accepted pins for this server. Empty means the server has no
            declared identity, which is refused rather than assumed benign.
        host: Server hostname, for the error message.
        port: Server port, for the error message.

    Raises:
        TLSError: If no pin is configured, or none of them matches.
    """
    actual = spki_fingerprint(cert_der)

    if not pins:
        raise TLSError(
            f"No pinned key configured for {host}:{port}. Legacy TLS does not "
            "authenticate the server on its own, so a pinned key is required "
            f"before anything is sent.\n"
            f"The server currently presents: {actual}\n"
            "If that is your appliance, record it as the profile's tls_pins."
        )

    normalised = [pin.strip().lower().replace(":", "") for pin in pins]
    if actual in normalised:
        _logger.debug("Server key for %s:%d matches a pinned key", host, port)
        return

    expected = ", ".join(normalised)
    raise TLSError(
        f"The key presented by {host}:{port} is not one of its pinned keys. "
        "Refusing to continue.\n"
        f"  presented: {actual}\n"
        f"  pinned:    {expected}\n"
        "Either the server's key changed, or this is not the server it claims "
        "to be."
    )
