"""Display field extraction for PDF signature appearances.

Resolves signer identity fields (name, email, org, date) from
profile field definitions and formats them for rendering.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ...config.profiles import CertField, SigField


_logger = logging.getLogger(__name__)

# Source name mapping for signer_info dict keys
_SOURCE_MAP = {
    "name": "name",
    "dn": "dn",
    "organization": "organization",
    "org": "organization",
    "email": "email",
}


def format_utc_offset(dt: datetime) -> str:
    """Format UTC offset cleanly: +0400 -> 'UTC+4', +0530 -> 'UTC+5:30', +0000 -> 'UTC'."""
    raw = dt.strftime("%z")  # e.g. "+0400", "-0530", "+0000"
    if not raw:
        return "UTC"
    sign = raw[0]
    hours = int(raw[1:3])
    minutes = int(raw[3:5])
    if hours == 0 and minutes == 0:
        return "UTC"
    offset = f"UTC{sign}{hours}"
    if minutes:
        offset += f":{minutes:02d}"
    return offset


# Locale-independent English month abbreviations.
# strftime("%b") depends on LC_TIME and produces non-ASCII results on
# Armenian or other non-Latin locales, which Helvetica/WinAnsiEncoding
# can't render.
_MONTH_ABBR = (
    "",
    "Jan",
    "Feb",
    "Mar",
    "Apr",
    "May",
    "Jun",
    "Jul",
    "Aug",
    "Sep",
    "Oct",
    "Nov",
    "Dec",
)


def make_date_str() -> str:
    """Generate a human-friendly date string with UTC offset.

    Uses locale-independent English month abbreviations to ensure
    consistent rendering in PDF signatures across all system locales.

    Example: '7 Feb 2026, 09:51:42 UTC+4'
    """
    now = datetime.now().astimezone()
    offset = format_utc_offset(now)
    month = _MONTH_ABBR[now.month]
    time_str = now.strftime("%H:%M:%S")
    return f"{now.day} {month} {now.year}, {time_str} {offset}"


def extract_cert_fields(
    cert_fields: tuple[CertField, ...],
    signer_info: dict[str, str | None],
) -> dict[str, str]:
    """Extract values from signer info using cert field definitions.

    For each CertField:
    - Looks up the source value from signer_info
    - Applies regex (group 1) if provided
    - Skips fields where the source value is empty or regex doesn't match

    Args:
        cert_fields: Ordered field definitions from the server profile.
        signer_info: Dict with keys "name", "dn", "organization", "email"
            (any may be None).

    Returns:
        Dict mapping CertField.id to extracted value (no label prefix).
    """
    result: dict[str, str] = {}
    for field in cert_fields:
        info_key = _SOURCE_MAP.get(field.source)
        if info_key is None:
            continue
        raw = signer_info.get(info_key) or ""
        if not raw:
            continue

        if field.regex:
            try:
                match = re.search(field.regex, raw)
            except re.error as e:
                _logger.warning("Invalid regex %r in field %r: %s", field.regex, field.id, e)
                continue
            if not match or not match.group(1):
                continue
            result[field.id] = match.group(1)
        else:
            result[field.id] = raw

    return result


def extract_display_fields(
    sig_fields: tuple[SigField, ...],
    cert_values: dict[str, str],
) -> list[str]:
    """Build display strings for PDF signature appearance.

    For each SigField:
    - auto="date": generate date string, prepend label (default "Date")
    - cert_field="name": look up in cert_values, prepend label if set

    Args:
        sig_fields: Ordered field definitions from the server profile.
        cert_values: Output of extract_cert_fields (id -> value mapping).

    Returns:
        Ordered list of display strings ready for rendering.
    """
    result: list[str] = []
    for field in sig_fields:
        # Auto-filled date
        if field.auto == "date":
            date_str = make_date_str()
            value = f"{field.label}: {date_str}" if field.label else f"Date: {date_str}"
            result.append(value)
            continue

        # Cert field reference
        if field.cert_field is not None:
            raw = cert_values.get(field.cert_field)
            if not raw:
                continue
            value = f"{field.label}: {raw}" if field.label else raw
            result.append(value)

    return result
