// SPDX-License-Identifier: Apache-2.0
/**
 * Certificate information extraction from CMS/PKCS#7 blobs,
 * X.509 certs, and signed PDFs.
 *
 * Includes identity discovery via enum-certificates (preferred)
 * or dummy-hash signing (fallback).
 */

import * as asn1js from "asn1js";
import * as pkijs from "pkijs";

import { SHA1_DIGEST_SIZE } from "../constants.js";
import { AuthError, CertificateError, RevenantError } from "../errors.js";
import { logger } from "../logger.js";
import type { SigningTransport } from "../network/protocol.js";
import { extractCmsFromByterangeMatch, findByteRanges } from "./pdf/cms-extraction.js";

/** Get a proper ArrayBuffer from a Uint8Array. */
function toArrayBuffer(data: Uint8Array): ArrayBuffer {
  const buf = new ArrayBuffer(data.byteLength);
  new Uint8Array(buf).set(data);
  return buf;
}

// OIDs for common subject fields
const OID_CN = "2.5.4.3";
const OID_EMAIL = "1.2.840.113549.1.9.1";
const OID_ORG = "2.5.4.10";

/**
 * Extract a string value from an ASN.1 value object.
 * Handles Utf8String, PrintableString, BmpString, IA5String, and generic valueBlock.
 */
function extractAsn1StringValue(value: asn1js.BaseBlock): string | null {
  if (
    value instanceof asn1js.Utf8String ||
    value instanceof asn1js.PrintableString ||
    value instanceof asn1js.BmpString ||
    value instanceof asn1js.IA5String
  ) {
    return value.valueBlock.value;
  }
  const block: unknown = value.valueBlock;
  if (block !== null && typeof block === "object" && "value" in block) {
    return String(block.value);
  }
  return null;
}

export interface CertInfo {
  name: string | null;
  email: string | null;
  organization: string | null;
  dn: string | null;
}

/**
 * Extract CN, email, org, dn from a pkijs Certificate object.
 */
function extractInfoFromCertObject(cert: pkijs.Certificate): CertInfo {
  const subject = cert.subject;
  const fields: CertInfo = {
    name: null,
    email: null,
    organization: null,
    dn: null,
  };

  // Check certificate validity
  try {
    const now = new Date();
    const notBefore = cert.notBefore.value;
    const notAfter = cert.notAfter.value;
    if (now < notBefore) {
      logger.warn(`Certificate is not yet valid (notBefore: ${notBefore.toISOString()})`);
    } else if (now > notAfter) {
      logger.warn(`Certificate has expired (notAfter: ${notAfter.toISOString()})`);
    }
  } catch {
    // Cannot check certificate validity dates
  }

  const oidMap: Record<string, keyof CertInfo> = {
    [OID_CN]: "name",
    [OID_EMAIL]: "email",
    [OID_ORG]: "organization",
  };

  // Extract individual fields by OID
  for (const rdn of subject.typesAndValues) {
    const oid = rdn.type;
    const fieldKey = oidMap[oid];
    if (fieldKey) {
      const extracted = extractAsn1StringValue(rdn.value);
      if (extracted) {
        fields[fieldKey] = extracted;
      }
    }
  }

  // Build human-readable DN
  const dnParts: string[] = [];
  for (const rdn of subject.typesAndValues) {
    const strValue = extractAsn1StringValue(rdn.value) ?? "";
    const oidName = getOidName(rdn.type);
    dnParts.push(`${oidName}=${strValue}`);
  }
  fields.dn = dnParts.join(", ");

  return fields;
}

function getOidName(oid: string): string {
  const oidNames: Record<string, string> = {
    "2.5.4.3": "CN",
    "2.5.4.4": "SN",
    "2.5.4.5": "SERIALNUMBER",
    "2.5.4.6": "C",
    "2.5.4.7": "L",
    "2.5.4.8": "ST",
    "2.5.4.10": "O",
    "2.5.4.11": "OU",
    "1.2.840.113549.1.9.1": "E",
  };
  return oidNames[oid] ?? oid;
}

/**
 * Parse a DER-encoded X.509 certificate.
 */
function parseCertificate(certDer: Uint8Array): pkijs.Certificate {
  const asn1 = asn1js.fromBER(toArrayBuffer(certDer));
  if (asn1.offset === -1) {
    throw new CertificateError("Failed to parse ASN.1 structure from certificate");
  }
  return new pkijs.Certificate({ schema: asn1.result });
}

/**
 * Extract signer certificate info from a CMS/PKCS#7 DER blob.
 */
export function extractCertInfoFromCms(cmsDer: Uint8Array): CertInfo {
  let signedData: pkijs.SignedData;
  try {
    const asn1 = asn1js.fromBER(toArrayBuffer(cmsDer));
    if (asn1.offset === -1) {
      throw new Error("Invalid ASN.1");
    }
    const contentInfo = new pkijs.ContentInfo({ schema: asn1.result });
    signedData = new pkijs.SignedData({ schema: contentInfo.content });
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    throw new CertificateError(`Failed to parse CMS/PKCS#7 blob: ${msg}`);
  }

  const certs = signedData.certificates;
  if (!certs || certs.length === 0) {
    throw new CertificateError("No certificate subject found in CMS blob.");
  }

  const cert = certs[0];
  if (cert === undefined || !(cert instanceof pkijs.Certificate)) {
    throw new CertificateError("First certificate in CMS blob is not an X.509 certificate.");
  }

  return extractInfoFromCertObject(cert);
}

/**
 * Extract signer info from a raw DER-encoded X.509 certificate.
 */
export function extractCertInfoFromX509(certDer: Uint8Array): CertInfo {
  try {
    const cert = parseCertificate(certDer);
    return extractInfoFromCertObject(cert);
  } catch (e) {
    if (e instanceof CertificateError) throw e;
    const msg = e instanceof Error ? e.message : String(e);
    throw new CertificateError(`Failed to parse X.509 certificate: ${msg}`);
  }
}

/**
 * Extract signer certificate info from ALL signatures in a signed PDF.
 *
 * Duplicates are removed (same DN).
 */
export function extractAllCertInfoFromPdf(pdfBytes: Uint8Array): CertInfo[] {
  const brMatches = findByteRanges(pdfBytes);
  if (brMatches.length === 0) {
    throw new CertificateError("No embedded signature found in this PDF.");
  }

  const results: CertInfo[] = [];
  const seenDns = new Set<string>();

  for (const br of brMatches) {
    try {
      const cmsDer = extractCmsFromByterangeMatch(pdfBytes, br);
      const info = extractCertInfoFromCms(cmsDer);
      const dn = info.dn ?? "";
      if (dn && !seenDns.has(dn)) {
        seenDns.add(dn);
        results.push(info);
      }
    } catch (exc) {
      if (exc instanceof RevenantError) continue;
      throw exc;
    }
  }

  if (results.length === 0) {
    throw new CertificateError("Could not extract any certificate info from PDF signatures.");
  }

  return results;
}

/**
 * Extract signer certificate info from a signed PDF.
 *
 * If there are multiple signatures, returns the last one.
 */
export function extractCertInfoFromPdf(pdfBytes: Uint8Array): CertInfo {
  const allInfo = extractAllCertInfoFromPdf(pdfBytes);
  const lastInfo = allInfo[allInfo.length - 1];
  if (lastInfo === undefined) {
    throw new CertificateError("Could not extract any certificate info from PDF signatures.");
  }
  return lastInfo;
}

/**
 * Discover signer identity from the server.
 *
 * Tries enum-certificates first (cleaner, no dummy signing), falls back
 * to signing a dummy SHA-1 hash if the server doesn't support it.
 */
export async function discoverIdentityFromServer(
  transport: SigningTransport,
  username: string,
  password: string,
  timeout: number,
): Promise<CertInfo> {
  // Try enum-certificates (preferred)
  const url = transport.url;
  if (url) {
    try {
      const { enumCertificates } = await import("../network/soap-transport.js");
      const certs = await enumCertificates(url, username, password, timeout);
      const firstCert = certs[0];
      if (firstCert) {
        return extractCertInfoFromX509(firstCert);
      }
    } catch (exc) {
      if (exc instanceof AuthError) throw exc;
      // enum-certificates not available, fall back to dummy-hash
    }
  }

  // Fallback: sign dummy hash and extract cert from CMS
  const dummyHash = new Uint8Array(SHA1_DIGEST_SIZE);
  const cmsDer = await transport.signHash(dummyHash, username, password, timeout);
  return extractCertInfoFromCms(cmsDer);
}
