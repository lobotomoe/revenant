// SPDX-License-Identifier: Apache-2.0
/**
 * Certificate expiration utilities.
 *
 * Pure functions for computing days remaining, expiration status,
 * and formatting certificate validity periods.  No I/O, no side effects.
 */

export type ExpiryStatus = "valid" | "expiring_soon" | "expired" | "not_yet_valid";

const EXPIRY_WARNING_DAYS = 30;
const MS_PER_DAY = 86_400_000;

/**
 * Compute the number of days until a certificate expires.
 *
 * @returns Days remaining (negative if already expired).
 */
export function daysRemaining(notAfterIso: string): number {
  const notAfter = new Date(notAfterIso);
  const now = new Date();
  const deltaMs = notAfter.getTime() - now.getTime();
  return Math.floor(deltaMs / MS_PER_DAY);
}

/**
 * Determine the expiration status of a certificate.
 */
export function expiryStatus(
  notAfterIso: string,
  warnDays: number = EXPIRY_WARNING_DAYS,
): ExpiryStatus {
  const remaining = daysRemaining(notAfterIso);
  if (remaining < 0) return "expired";
  if (remaining <= warnDays) return "expiring_soon";
  return "valid";
}

/**
 * Check if a certificate is not yet valid.
 */
export function notYetValid(notBeforeIso: string): boolean {
  const notBefore = new Date(notBeforeIso);
  return new Date() < notBefore;
}

/**
 * Format a human-readable certificate validity period.
 *
 * @returns String like "2024-01-15 - 2027-01-15 (347 days remaining)".
 */
export function formatValidityPeriod(notBefore: string | null, notAfter: string | null): string {
  if (!notBefore && !notAfter) return "Unknown";

  const parts: string[] = [];

  if (notBefore) {
    parts.push(new Date(notBefore).toISOString().slice(0, 10));
  } else {
    parts.push("?");
  }

  parts.push(" - ");

  if (notAfter) {
    parts.push(new Date(notAfter).toISOString().slice(0, 10));

    const remaining = daysRemaining(notAfter);
    if (remaining < 0) {
      parts.push(` (expired ${Math.abs(remaining)} days ago)`);
    } else if (remaining === 0) {
      parts.push(" (expires today)");
    } else if (remaining === 1) {
      parts.push(" (1 day remaining)");
    } else {
      parts.push(` (${remaining} days remaining)`);
    }
  } else {
    parts.push("?");
  }

  return parts.join("");
}

/**
 * Format a short expiry summary for display.
 *
 * @returns String like "Valid (347 days)", "Expiring soon (12 days)",
 *          "EXPIRED (5 days ago)", or "Unknown".
 */
export function formatExpirySummary(notAfter: string | null): string {
  if (!notAfter) return "Unknown";

  const remaining = daysRemaining(notAfter);
  const status = expiryStatus(notAfter);

  if (status === "expired") return `EXPIRED (${Math.abs(remaining)} days ago)`;
  if (status === "expiring_soon") return `Expiring soon (${remaining} days)`;
  return `Valid (${remaining} days)`;
}
