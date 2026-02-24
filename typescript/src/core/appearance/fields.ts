// SPDX-License-Identifier: Apache-2.0
/**
 * Display field extraction for PDF signature appearances.
 *
 * Resolves signer identity fields (name, email, org, date) from
 * profile field definitions and formats them for rendering.
 */

import type { CertField, SigField } from "../../config/profiles.js";

// Source name mapping for signer_info dict keys
const SOURCE_MAP: Record<string, string> = {
  name: "name",
  dn: "dn",
  organization: "organization",
  org: "organization",
  email: "email",
};

/**
 * Format UTC offset cleanly: +0400 -> 'UTC+4', +0530 -> 'UTC+5:30', +0000 -> 'UTC'.
 */
export function formatUtcOffset(date: Date): string {
  const offsetMinutes = -date.getTimezoneOffset();
  if (offsetMinutes === 0) return "UTC";

  const sign = offsetMinutes >= 0 ? "+" : "-";
  const absMinutes = Math.abs(offsetMinutes);
  const hours = Math.floor(absMinutes / 60);
  const minutes = absMinutes % 60;

  let offset = `UTC${sign}${hours}`;
  if (minutes > 0) {
    offset += `:${minutes.toString().padStart(2, "0")}`;
  }
  return offset;
}

// Locale-independent English month abbreviations.
const MONTH_ABBR = [
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
];

/**
 * Generate a human-friendly date string with UTC offset.
 *
 * Uses locale-independent English month abbreviations.
 * Example: '7 Feb 2026, 09:51:42 UTC+4'
 */
export function makeDateStr(): string {
  const now = new Date();
  const offset = formatUtcOffset(now);
  const monthIndex = now.getMonth() + 1;
  const month = MONTH_ABBR[monthIndex] ?? "Jan";
  const hours = now.getHours().toString().padStart(2, "0");
  const mins = now.getMinutes().toString().padStart(2, "0");
  const secs = now.getSeconds().toString().padStart(2, "0");
  return `${now.getDate()} ${month} ${now.getFullYear()}, ${hours}:${mins}:${secs} ${offset}`;
}

/**
 * Extract values from signer info using cert field definitions.
 */
export function extractCertFields(
  certFields: readonly CertField[],
  signerInfo: Record<string, string | null>,
): Record<string, string> {
  const result: Record<string, string> = {};

  for (const field of certFields) {
    const infoKey = SOURCE_MAP[field.source];
    if (!infoKey) continue;
    const raw = signerInfo[infoKey] ?? "";
    if (!raw) continue;

    if (field.regex) {
      try {
        const match = raw.match(new RegExp(field.regex));
        if (!match || !match[1]) continue;
        result[field.id] = match[1];
      } catch {}
    } else {
      result[field.id] = raw;
    }
  }

  return result;
}

/**
 * Build display strings for PDF signature appearance.
 */
export function extractDisplayFields(
  sigFields: readonly SigField[],
  certValues: Record<string, string>,
): string[] {
  const result: string[] = [];

  for (const field of sigFields) {
    // Auto-filled date
    if (field.auto === "date") {
      const dateStr = makeDateStr();
      const value = field.label ? `${field.label}: ${dateStr}` : `Date: ${dateStr}`;
      result.push(value);
      continue;
    }

    // Cert field reference
    if (field.certField != null) {
      const raw = certValues[field.certField];
      if (!raw) continue;
      const value = field.label ? `${field.label}: ${raw}` : raw;
      result.push(value);
    }
  }

  return result;
}
