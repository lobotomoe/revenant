# SPDX-License-Identifier: Apache-2.0
"""Tests for certificate expiration utilities."""

from __future__ import annotations

import datetime

from revenant.core.cert_expiry import (
    days_remaining,
    expiry_status,
    format_expiry_summary,
    format_validity_period,
    not_yet_valid,
)


def _iso(delta_days: int) -> str:
    """Helper: ISO 8601 timestamp offset from now by delta_days."""
    dt = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=delta_days)
    return dt.isoformat()


# ── days_remaining ──────────────────────────────────────────────────


def test_days_remaining_future():
    result = days_remaining(_iso(100))
    assert 99 <= result <= 100


def test_days_remaining_past():
    result = days_remaining(_iso(-10))
    assert -11 <= result <= -10


def test_days_remaining_today():
    # Certificate expiring right now should give 0 or -1
    result = days_remaining(_iso(0))
    assert -1 <= result <= 0


def test_days_remaining_naive_timestamp():
    """Naive (no timezone) timestamps are treated as UTC."""
    dt = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=50)
    naive_iso = dt.replace(tzinfo=None).isoformat()
    result = days_remaining(naive_iso)
    assert 49 <= result <= 50


# ── expiry_status ───────────────────────────────────────────────────


def test_expiry_status_valid():
    assert expiry_status(_iso(365)) == "valid"


def test_expiry_status_expiring_soon():
    assert expiry_status(_iso(15)) == "expiring_soon"


def test_expiry_status_expired():
    assert expiry_status(_iso(-5)) == "expired"


def test_expiry_status_custom_warn_days():
    # 45 days remaining, default warn=30 -> valid
    assert expiry_status(_iso(45)) == "valid"
    # 45 days remaining, warn=60 -> expiring_soon
    assert expiry_status(_iso(45), warn_days=60) == "expiring_soon"


def test_expiry_status_boundary_at_warn_days():
    # Exactly at the warn threshold -> expiring_soon
    assert expiry_status(_iso(30)) == "expiring_soon"


# ── not_yet_valid ───────────────────────────────────────────────────


def test_not_yet_valid_future():
    assert not_yet_valid(_iso(10)) is True


def test_not_yet_valid_past():
    assert not_yet_valid(_iso(-10)) is False


# ── format_validity_period ──────────────────────────────────────────


def test_format_validity_period_both_dates():
    not_before = "2024-01-15T00:00:00+00:00"
    not_after = _iso(100)
    result = format_validity_period(not_before, not_after)
    assert "2024-01-15" in result
    assert "days remaining" in result


def test_format_validity_period_expired():
    not_before = "2020-01-01T00:00:00+00:00"
    not_after = "2023-01-01T00:00:00+00:00"
    result = format_validity_period(not_before, not_after)
    assert "2020-01-01" in result
    assert "expired" in result
    assert "days ago" in result


def test_format_validity_period_none_both():
    assert format_validity_period(None, None) == "Unknown"


def test_format_validity_period_none_before():
    result = format_validity_period(None, _iso(100))
    assert result.startswith("?")
    assert "days remaining" in result


def test_format_validity_period_none_after():
    result = format_validity_period("2024-01-15T00:00:00+00:00", None)
    assert "2024-01-15" in result
    assert result.endswith("?")


def test_format_validity_period_one_day():
    # Create a timestamp approximately 1 day from now
    dt = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1, hours=12)
    result = format_validity_period("2024-01-01T00:00:00+00:00", dt.isoformat())
    assert "1 day remaining" in result


def test_format_validity_period_expires_today():
    dt = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=6)
    result = format_validity_period("2024-01-01T00:00:00+00:00", dt.isoformat())
    assert "expires today" in result


# ── format_expiry_summary ───────────────────────────────────────────


def test_format_expiry_summary_valid():
    result = format_expiry_summary(_iso(200))
    assert result.startswith("Valid (")
    assert "days)" in result


def test_format_expiry_summary_expiring_soon():
    result = format_expiry_summary(_iso(10))
    assert result.startswith("Expiring soon (")


def test_format_expiry_summary_expired():
    result = format_expiry_summary(_iso(-5))
    assert result.startswith("EXPIRED (")
    assert "days ago)" in result


def test_format_expiry_summary_none():
    assert format_expiry_summary(None) == "Unknown"
