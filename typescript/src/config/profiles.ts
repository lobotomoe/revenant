// SPDX-License-Identifier: Apache-2.0
/**
 * Server profiles for CoSign appliances.
 *
 * A profile bundles connection details, identity discovery strategies,
 * and UI strings for a specific CoSign deployment.
 */

import { DEFAULT_TIMEOUT_SOAP } from "../constants.js";

export interface CertField {
  readonly id: string;
  readonly label: string;
  readonly source: "name" | "dn" | "organization" | "email";
  readonly regex?: string;
}

export interface SigField {
  readonly certField?: string;
  readonly auto?: "date";
  readonly label?: string;
}

export interface ServerProfile {
  readonly name: string;
  readonly displayName: string;
  readonly url: string;
  readonly timeout: number;
  readonly identityMethods: readonly string[];
  readonly legacyTls: boolean;
  readonly caCertMarkers: readonly string[];
  readonly maxAuthAttempts: number;
  readonly certFields: readonly CertField[];
  readonly sigFields: readonly SigField[];
  readonly font: string;
  readonly cliDescription: string;
  readonly tslUrl?: string;
}

export function hasIdentityMethod(profile: ServerProfile, method: string): boolean {
  return profile.identityMethods.includes(method);
}

// -- Built-in profiles -------------------------------------------------------

export const BUILTIN_PROFILES: ReadonlyMap<string, ServerProfile> = new Map([
  [
    "ekeng",
    {
      name: "ekeng",
      displayName: "EKENG (Armenian Government)",
      url: "https://ca.gov.am:8080/SAPIWS/DSS.asmx",
      timeout: 120,
      legacyTls: true,
      identityMethods: ["server", "manual"],
      caCertMarkers: ["ekeng", "\u0567\u056f\u0565\u0576\u0563"],
      maxAuthAttempts: 5,
      certFields: [
        {
          id: "name",
          label: "Name",
          source: "name",
          regex: "^(.+?)\\s+\\d{5,}$",
        },
        {
          id: "gov_id",
          label: "SSN",
          source: "name",
          regex: "(\\d{5,})$",
        },
        { id: "email", label: "Email", source: "email" },
      ],
      sigFields: [{ certField: "name" }, { certField: "gov_id", label: "SSN" }, { auto: "date" }],
      font: "ghea-grapalat",
      cliDescription: "Cross-platform CLI for ARX CoSign electronic signatures (EKENG profile).",
      tslUrl: "https://www.gov.am/files/TSL/AM-TL-1.xml",
    },
  ],
]);

export function getProfile(name: string): ServerProfile {
  const key = name.toLowerCase().trim();
  const profile = BUILTIN_PROFILES.get(key);
  if (!profile) {
    const available = [...BUILTIN_PROFILES.keys()].sort().join(", ");
    throw new Error(`Unknown profile ${JSON.stringify(name)}. Available: ${available}`);
  }
  return profile;
}

export function makeCustomProfile(
  url: string,
  timeout: number = DEFAULT_TIMEOUT_SOAP,
): ServerProfile {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error(`Invalid URL: ${JSON.stringify(url)}`);
  }

  if (parsed.protocol === "http:") {
    throw new Error("HTTP URLs are not supported. Use https:// to protect credentials in transit.");
  }
  if (parsed.protocol !== "https:") {
    throw new Error(`Invalid URL scheme ${JSON.stringify(parsed.protocol)}. Use https://.`);
  }
  if (!parsed.hostname) {
    throw new Error(`Invalid URL: no hostname found in ${JSON.stringify(url)}`);
  }

  return {
    name: "custom",
    displayName: `Custom (${url})`,
    url,
    timeout,
    identityMethods: ["server", "manual"],
    legacyTls: false,
    caCertMarkers: [],
    maxAuthAttempts: 0,
    certFields: [],
    sigFields: [],
    font: "noto-sans",
    cliDescription: "",
  };
}
