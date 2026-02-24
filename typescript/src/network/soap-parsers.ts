// SPDX-License-Identifier: Apache-2.0
/** SOAP response parsers for CoSign API. */

import { XMLParser } from "fast-xml-parser";
import { MIN_SIGNATURE_B64_LEN, XML_PREVIEW_LENGTH } from "../constants.js";
import { AuthError, getErrorMessage, RevenantError, ServerError } from "../errors.js";
import { logger } from "../logger.js";

const AUTH_MINOR_SUFFIX = ":AuthenticationError";

const REDACT_PASSWORD_PATTERN = /<[\w:]*LogonPassword>[^<]*<\/[\w:]*LogonPassword>/g;
const REDACT_NAME_PATTERN = /<(\w+:)?Name>[^<]*<\/(\w+:)?Name>/g;

function isAuthError(resultMinor: string | null, msg: string): boolean {
  return (
    resultMinor?.endsWith(AUTH_MINOR_SUFFIX) ||
    msg.toLowerCase().includes("password") ||
    msg.toLowerCase().includes("user name")
  );
}

function redactAndTruncateXml(xmlStr: string): string {
  let redacted = xmlStr.replace(
    REDACT_PASSWORD_PATTERN,
    "<LogonPassword>[REDACTED]</LogonPassword>",
  );
  redacted = redacted.replace(REDACT_NAME_PATTERN, "<Name>[REDACTED]</Name>");
  return redacted.slice(0, XML_PREVIEW_LENGTH);
}

const parser = new XMLParser({
  ignoreAttributes: false,
  removeNSPrefix: true,
  trimValues: true,
});

type ParsedXml = Record<string, unknown>;

function parseXml(xmlStr: string): ParsedXml {
  const result: unknown = parser.parse(xmlStr);
  if (!isRecord(result)) {
    throw new RevenantError("XML parser returned non-object result");
  }
  return result;
}

/** Type guard: narrow unknown to a string-keyed record. */
function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Extract the text content from a value that may be a string or an object
 *  with a #text key (fast-xml-parser returns objects when attributes exist). */
function extractText(value: unknown): string | null {
  if (typeof value === "string") {
    const trimmed = value.trim();
    return trimmed || null;
  }
  if (isRecord(value) && typeof value["#text"] === "string") {
    const trimmed = value["#text"].trim();
    return trimmed || null;
  }
  return null;
}

function findValue(obj: Record<string, unknown>, targetTag: string): string | null {
  for (const [key, value] of Object.entries(obj)) {
    if (key === targetTag) {
      const text = extractText(value);
      if (text) return text;
    }
    if (isRecord(value)) {
      const found = findValue(value, targetTag);
      if (found) return found;
    }
  }
  return null;
}

function findAllValues(obj: Record<string, unknown>, targetTag: string): string[] {
  const results: string[] = [];

  function recurse(node: Record<string, unknown>): void {
    for (const [key, value] of Object.entries(node)) {
      if (key === targetTag) {
        if (Array.isArray(value)) {
          for (const item of value) {
            const text = extractText(item);
            if (text) results.push(text);
          }
        } else {
          const text = extractText(value);
          if (text) results.push(text);
        }
      }
      if (isRecord(value)) {
        recurse(value);
      }
    }
  }

  recurse(obj);
  return results;
}

function findAttribute(
  obj: Record<string, unknown>,
  elementTag: string,
  attrName: string,
): string | null {
  for (const [key, value] of Object.entries(obj)) {
    if (isRecord(value)) {
      if (key === elementTag) {
        const attrKey = `@_${attrName}`;
        const attrVal = value[attrKey];
        if (typeof attrVal === "string") return attrVal;
      }
      const found = findAttribute(value, elementTag, attrName);
      if (found) return found;
    }
  }
  return null;
}

export function parseSignResponse(xmlStr: string): Uint8Array {
  let parsed: ParsedXml;
  try {
    parsed = parseXml(xmlStr);
  } catch (e) {
    const safePreview = redactAndTruncateXml(xmlStr.slice(0, 500));
    throw new RevenantError(`Invalid XML response: ${getErrorMessage(e)}\nRaw: ${safePreview}`);
  }

  const resultMajor = findValue(parsed, "ResultMajor");
  const resultMinor = findValue(parsed, "ResultMinor");
  const resultMessage = findValue(parsed, "ResultMessage");

  // Find CMS Base64 data
  let cmsB64: string | null = null;
  for (const tag of ["Base64Data", "Base64Signature"]) {
    const val = findValue(parsed, tag);
    if (val && val.length > MIN_SIGNATURE_B64_LEN) {
      cmsB64 = val;
      break;
    }
  }

  if (resultMajor?.endsWith(":Success")) {
    if (!cmsB64) {
      throw new ServerError("Server returned Success but no signature data.");
    }
    try {
      return new Uint8Array(Buffer.from(cmsB64, "base64"));
    } catch (e) {
      throw new RevenantError(`Invalid Base64 in server response: ${getErrorMessage(e)}`);
    }
  }

  const msg = resultMessage ?? resultMinor ?? resultMajor ?? "Unknown error";

  if (isAuthError(resultMinor, msg)) {
    throw new AuthError(`Authentication failed: ${msg}`);
  }

  throw new ServerError(`Signing failed: ${msg}`);
}

export function parseEnumCertificatesResponse(xmlStr: string): Uint8Array[] {
  let parsed: ParsedXml;
  try {
    parsed = parseXml(xmlStr);
  } catch (e) {
    const safePreview = redactAndTruncateXml(xmlStr.slice(0, 500));
    throw new RevenantError(`Invalid XML response: ${getErrorMessage(e)}\nRaw: ${safePreview}`);
  }

  const resultMajor = findValue(parsed, "ResultMajor");
  const resultMinor = findValue(parsed, "ResultMinor");
  const resultMessage = findValue(parsed, "ResultMessage");

  if (resultMajor?.endsWith(":Success")) {
    const certsB64 = findAllValues(parsed, "AvailableCertificate");
    const certs: Uint8Array[] = [];
    for (const certB64 of certsB64) {
      try {
        certs.push(new Uint8Array(Buffer.from(certB64, "base64")));
      } catch {
        logger.warn("Skipping malformed certificate Base64");
      }
    }
    return certs;
  }

  const msg = resultMessage ?? resultMinor ?? resultMajor ?? "Unknown error";

  if (isAuthError(resultMinor, msg)) {
    throw new AuthError(`Authentication failed: ${msg}`);
  }

  throw new ServerError(`enum-certificates failed: ${msg}`);
}

export interface ServerVerifyResult {
  valid: boolean;
  signerName: string | null;
  signTime: string | null;
  certificateStatus: string | null;
  error: string | null;
}

export function parseVerifyResponse(xmlStr: string): ServerVerifyResult {
  let parsed: ParsedXml;
  try {
    parsed = parseXml(xmlStr);
  } catch (e) {
    return {
      valid: false,
      signerName: null,
      signTime: null,
      certificateStatus: null,
      error: `Invalid XML response: ${getErrorMessage(e)}`,
    };
  }

  const resultMajor = findValue(parsed, "ResultMajor");
  const resultMessage = findValue(parsed, "ResultMessage");
  const signerName = findAttribute(parsed, "SignedFieldInfo", "SignerName");
  const signTime = findAttribute(parsed, "SignedFieldInfo", "SignatureTime");
  const certStatus = findAttribute(parsed, "FieldStatus", "CertificateStatus");

  if (resultMajor?.endsWith(":Success")) {
    return {
      valid: true,
      signerName,
      signTime,
      certificateStatus: certStatus,
      error: null,
    };
  }

  const errorMsg = resultMessage ?? "Server returned non-success result";
  return {
    valid: false,
    signerName: null,
    signTime: null,
    certificateStatus: null,
    error: errorMsg,
  };
}
