"""
Transport protocol abstraction for remote signing services.

Defines the interface that signing transports must implement. The core
signing logic depends on this protocol, not on concrete implementations.
"""

from __future__ import annotations

from typing import Protocol


class SigningTransport(Protocol):
    """Protocol for remote digital signature services.

    Implementations provide methods to sign data via a remote signing
    service (SOAP, REST, gRPC, etc.). The core signing module depends
    on this protocol, making it transport-agnostic.
    """

    def sign_data(self, data: bytes, username: str, password: str, timeout: int) -> bytes:
        """
        Sign arbitrary data via the remote service.

        The server computes the hash internally and returns a CMS/PKCS#7
        signature with proper DigestAlgorithm and messageDigest attributes.

        Args:
            data: Raw data to sign (any size).
            username: Authentication username.
            password: Authentication password.
            timeout: Request timeout in seconds.

        Returns:
            DER-encoded CMS/PKCS#7 signature.

        Raises:
            AuthError: If credentials are invalid.
            RevenantError: If the signing operation fails.
            TLSError: On connection issues.
        """
        ...

    def sign_hash(self, hash_bytes: bytes, username: str, password: str, timeout: int) -> bytes:
        """
        Sign a pre-computed hash via the remote service.

        The server signs exactly the hash provided (does not re-hash).

        Args:
            hash_bytes: Pre-computed hash (typically 20-byte SHA-1).
            username: Authentication username.
            password: Authentication password.
            timeout: Request timeout in seconds.

        Returns:
            DER-encoded CMS/PKCS#7 signature.

        Raises:
            AuthError: If credentials are invalid.
            RevenantError: If the signing operation fails.
            TLSError: On connection issues.
        """
        ...

    def sign_pdf_detached(
        self, pdf_bytes: bytes, username: str, password: str, timeout: int
    ) -> bytes:
        """
        Sign a complete PDF document (detached signature).

        The server hashes the full PDF internally and returns a detached
        CMS/PKCS#7 signature.

        Args:
            pdf_bytes: Complete PDF file content.
            username: Authentication username.
            password: Authentication password.
            timeout: Request timeout in seconds.

        Returns:
            DER-encoded CMS/PKCS#7 signature (detached).

        Raises:
            AuthError: If credentials are invalid.
            RevenantError: If the signing operation fails.
            TLSError: On connection issues.
        """
        ...
