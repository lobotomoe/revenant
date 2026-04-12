/**
 * Tests for certificate expiration utilities.
 */

import { describe, expect, it } from "vitest";
import {
  daysRemaining,
  expiryStatus,
  formatExpirySummary,
  formatValidityPeriod,
  notYetValid,
} from "../src/core/cert-expiry.js";

function iso(deltaDays: number): string {
  const dt = new Date(Date.now() + deltaDays * 86_400_000);
  return dt.toISOString();
}

// -- daysRemaining -------------------------------------------------------

describe("daysRemaining", () => {
  it("returns positive for future date", () => {
    const result = daysRemaining(iso(100));
    expect(result).toBeGreaterThanOrEqual(99);
    expect(result).toBeLessThanOrEqual(100);
  });

  it("returns negative for past date", () => {
    const result = daysRemaining(iso(-10));
    expect(result).toBeGreaterThanOrEqual(-11);
    expect(result).toBeLessThanOrEqual(-10);
  });

  it("returns 0 or -1 for today", () => {
    const result = daysRemaining(iso(0));
    expect(result).toBeGreaterThanOrEqual(-1);
    expect(result).toBeLessThanOrEqual(0);
  });
});

// -- expiryStatus -------------------------------------------------------

describe("expiryStatus", () => {
  it("returns 'valid' for distant future", () => {
    expect(expiryStatus(iso(365))).toBe("valid");
  });

  it("returns 'expiring_soon' for near future", () => {
    expect(expiryStatus(iso(15))).toBe("expiring_soon");
  });

  it("returns 'expired' for past date", () => {
    expect(expiryStatus(iso(-5))).toBe("expired");
  });

  it("respects custom warn days", () => {
    expect(expiryStatus(iso(45))).toBe("valid");
    expect(expiryStatus(iso(45), 60)).toBe("expiring_soon");
  });

  it("treats boundary as expiring_soon", () => {
    expect(expiryStatus(iso(30))).toBe("expiring_soon");
  });
});

// -- notYetValid -------------------------------------------------------

describe("notYetValid", () => {
  it("returns true for future date", () => {
    expect(notYetValid(iso(10))).toBe(true);
  });

  it("returns false for past date", () => {
    expect(notYetValid(iso(-10))).toBe(false);
  });
});

// -- formatValidityPeriod -------------------------------------------------------

describe("formatValidityPeriod", () => {
  it("formats both dates with days remaining", () => {
    const result = formatValidityPeriod("2024-01-15T00:00:00Z", iso(100));
    expect(result).toContain("2024-01-15");
    expect(result).toContain("days remaining");
  });

  it("formats expired period", () => {
    const result = formatValidityPeriod("2020-01-01T00:00:00Z", "2023-01-01T00:00:00Z");
    expect(result).toContain("2020-01-01");
    expect(result).toContain("expired");
    expect(result).toContain("days ago");
  });

  it("returns Unknown for both null", () => {
    expect(formatValidityPeriod(null, null)).toBe("Unknown");
  });

  it("handles null not_before", () => {
    const result = formatValidityPeriod(null, iso(100));
    expect(result).toMatch(/^\?/);
    expect(result).toContain("days remaining");
  });

  it("handles null not_after", () => {
    const result = formatValidityPeriod("2024-01-15T00:00:00Z", null);
    expect(result).toContain("2024-01-15");
    expect(result).toMatch(/\?$/);
  });
});

// -- formatExpirySummary -------------------------------------------------------

describe("formatExpirySummary", () => {
  it("formats valid cert", () => {
    const result = formatExpirySummary(iso(200));
    expect(result).toMatch(/^Valid \(\d+ days\)$/);
  });

  it("formats expiring soon cert", () => {
    const result = formatExpirySummary(iso(10));
    expect(result).toMatch(/^Expiring soon \(\d+ days\)$/);
  });

  it("formats expired cert", () => {
    const result = formatExpirySummary(iso(-5));
    expect(result).toMatch(/^EXPIRED \(\d+ days ago\)$/);
  });

  it("returns Unknown for null", () => {
    expect(formatExpirySummary(null)).toBe("Unknown");
  });
});
