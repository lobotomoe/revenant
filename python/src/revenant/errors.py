"""Revenant error types."""

from __future__ import annotations

from typing import Any

__all__ = [
    "AuthError",
    "CertificateError",
    "ConfigError",
    "PDFError",
    "RevenantError",
    "ServerError",
    "TLSError",
]


class RevenantError(Exception):
    """Base error for Revenant operations."""


class AuthError(RevenantError):
    """Authentication failed."""


class ServerError(RevenantError):
    """Server returned an error."""


class TLSError(RevenantError):
    """TLS/connection error.

    Args:
        message: Human-readable error description.
        retryable: Whether this error is transient and worth retrying.
            True for timeouts and connection failures;
            False for TLS configuration issues (cipher mismatch, etc.).
    """

    def __init__(self, message: str, *, retryable: bool = False) -> None:
        super().__init__(message)
        self.retryable = retryable

    def __reduce__(self) -> tuple[type[TLSError], tuple[str], dict[str, bool]]:
        """Preserve retryable flag across pickle/unpickle."""
        return (type(self), (str(self),), {"retryable": self.retryable})

    def __setstate__(self, state: dict[str, Any] | None) -> None:
        if state is None:
            return
        self.retryable = state.get("retryable", False)


class PDFError(RevenantError):
    """PDF structure, parsing, or building error."""


class ConfigError(RevenantError):
    """Configuration validation error."""


class CertificateError(RevenantError):
    """Certificate parsing or extraction error."""
