# SPDX-License-Identifier: Apache-2.0
"""Certificate expiration utilities.

Pure functions for computing days remaining, expiration status,
and formatting certificate validity periods.  No I/O, no side effects.
"""

from __future__ import annotations

import datetime
from typing import Literal

ExpiryStatus = Literal["valid", "expiring_soon", "expired", "not_yet_valid"]

EXPIRY_WARNING_DAYS = 30


def days_remaining(not_after_iso: str) -> int:
    """Compute the number of days until a certificate expires.

    Args:
        not_after_iso: Certificate notAfter in ISO 8601 format.

    Returns:
        Days remaining (negative if already expired).
    """
    not_after = datetime.datetime.fromisoformat(not_after_iso)
    if not_after.tzinfo is None:
        not_after = not_after.replace(tzinfo=datetime.timezone.utc)
    now = datetime.datetime.now(datetime.timezone.utc)
    delta = not_after - now
    return delta.days


def expiry_status(not_after_iso: str, warn_days: int = EXPIRY_WARNING_DAYS) -> ExpiryStatus:
    """Determine the expiration status of a certificate.

    Args:
        not_after_iso: Certificate notAfter in ISO 8601 format.
        warn_days: Number of days before expiry to start warning.

    Returns:
        One of: "valid", "expiring_soon", "expired", "not_yet_valid".
    """
    remaining = days_remaining(not_after_iso)
    if remaining < 0:
        return "expired"
    if remaining <= warn_days:
        return "expiring_soon"
    return "valid"


def not_yet_valid(not_before_iso: str) -> bool:
    """Check if a certificate is not yet valid.

    Args:
        not_before_iso: Certificate notBefore in ISO 8601 format.

    Returns:
        True if the certificate's validity period has not started.
    """
    not_before = datetime.datetime.fromisoformat(not_before_iso)
    if not_before.tzinfo is None:
        not_before = not_before.replace(tzinfo=datetime.timezone.utc)
    now = datetime.datetime.now(datetime.timezone.utc)
    return now < not_before


def format_validity_period(
    not_before: str | None,
    not_after: str | None,
) -> str:
    """Format a human-readable certificate validity period.

    Args:
        not_before: Certificate notBefore in ISO 8601 format, or None.
        not_after: Certificate notAfter in ISO 8601 format, or None.

    Returns:
        Human-readable string like "2024-01-15 - 2027-01-15 (347 days remaining)".
    """
    if not not_before and not not_after:
        return "Unknown"

    parts: list[str] = []

    if not_before:
        dt = datetime.datetime.fromisoformat(not_before)
        parts.append(dt.strftime("%Y-%m-%d"))
    else:
        parts.append("?")

    parts.append(" - ")

    if not_after:
        dt = datetime.datetime.fromisoformat(not_after)
        parts.append(dt.strftime("%Y-%m-%d"))

        remaining = days_remaining(not_after)
        if remaining < 0:
            parts.append(f" (expired {abs(remaining)} days ago)")
        elif remaining == 0:
            parts.append(" (expires today)")
        elif remaining == 1:
            parts.append(" (1 day remaining)")
        else:
            parts.append(f" ({remaining} days remaining)")
    else:
        parts.append("?")

    return "".join(parts)


def format_expiry_summary(not_after: str | None) -> str:
    """Format a short expiry summary for display.

    Args:
        not_after: Certificate notAfter in ISO 8601 format, or None.

    Returns:
        Short string like "Valid (347 days)", "Expiring soon (12 days)",
        "EXPIRED (5 days ago)", or "Unknown".
    """
    if not not_after:
        return "Unknown"

    remaining = days_remaining(not_after)
    status = expiry_status(not_after)

    if status == "expired":
        return f"EXPIRED ({abs(remaining)} days ago)"
    if status == "expiring_soon":
        return f"Expiring soon ({remaining} days)"
    return f"Valid ({remaining} days)"
