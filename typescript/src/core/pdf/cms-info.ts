// SPDX-License-Identifier: Apache-2.0
/**
 * CMS metadata extraction -- digest info, signer identity, and blob inspection.
 */

import * as asn1js from "asn1js";
import * as pkijs from "pkijs";

import { RevenantError } from "../../errors.js";
import { toArrayBuffer } from "../../utils.js";
import { ASN1_SEQUENCE_TAG, MIN_CMS_SIZE } from "./asn1.js";

/** OID for messageDigest attribute in CMS SignerInfo. */
const OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4";

/**
 * Map non-standard CMS digest algorithm OIDs to Web Crypto names.
 * CoSign puts sha1WithRSAEncryption in the digestAlgorithm field
 * instead of sha1.
 */
const DIGEST_ALGO_MAP: ReadonlyMap<string, string> = new Map([
  ["1.3.14.3.2.26", "SHA-1"],
  ["2.16.840.1.101.3.4.2.1", "SHA-256"],
  ["2.16.840.1.101.3.4.2.2", "SHA-384"],
  ["2.16.840.1.101.3.4.2.3", "SHA-512"],
  // sha*WithRSAEncryption OIDs (CoSign quirk)
  ["1.2.840.113549.1.1.5", "SHA-1"],
  ["1.2.840.113549.1.1.11", "SHA-256"],
  ["1.2.840.113549.1.1.12", "SHA-384"],
  ["1.2.840.113549.1.1.13", "SHA-512"],
]);

/**
 * Resolve a CMS digest algorithm OID to a Web Crypto name.
 */
export function resolveHashAlgo(algoOid: string): string | null {
  return DIGEST_ALGO_MAP.get(algoOid) ?? null;
}

/**
 * Parse a CMS/PKCS#7 DER blob into a pkijs ContentInfo.
 */
function parseCms(cmsDer: Uint8Array): pkijs.ContentInfo {
  const asn1 = asn1js.fromBER(toArrayBuffer(cmsDer));
  if (asn1.offset === -1) {
    throw new RevenantError("Failed to parse ASN.1 structure from CMS blob");
  }
  return new pkijs.ContentInfo({ schema: asn1.result });
}

/**
 * Extract digest algorithm and messageDigest from a CMS SignerInfo.
 */
export function extractDigestInfo(
  cmsDer: Uint8Array,
): { algorithm: string; digest: Uint8Array } | null {
  try {
    const contentInfo = parseCms(cmsDer);
    const signedData = new pkijs.SignedData({
      schema: contentInfo.content,
    });

    if (signedData.signerInfos.length === 0) return null;

    const signerInfo = signedData.signerInfos[0];
    if (signerInfo === undefined) return null;

    // Get digest algorithm OID
    const algoOid = signerInfo.digestAlgorithm.algorithmId;
    const algoName = resolveHashAlgo(algoOid);
    if (!algoName) return null;

    // Get messageDigest from signed attributes
    const signedAttrs = signerInfo.signedAttrs;
    if (!signedAttrs) return null;

    for (const attr of signedAttrs.attributes) {
      if (attr.type === OID_MESSAGE_DIGEST) {
        if (attr.values.length > 0) {
          const digestValue = attr.values[0];
          if (digestValue !== undefined && digestValue instanceof asn1js.OctetString) {
            const digestBytes = new Uint8Array(digestValue.valueBlock.valueHexView);
            return { algorithm: algoName, digest: digestBytes };
          }
        }
      }
    }

    return null;
  } catch {
    return null;
  }
}

export interface SignerInfo {
  name: string | null;
  email: string | null;
  organization: string | null;
  dn: string | null;
}

/**
 * Extract signer certificate info from a CMS blob.
 * Uses dynamic import to avoid circular dependency with cert-info.
 */
export async function extractSignerInfo(cmsDer: Uint8Array): Promise<SignerInfo | null> {
  try {
    const { extractCertInfoFromCms } = await import("../cert-info.js");
    return extractCertInfoFromCms(cmsDer);
  } catch {
    return null;
  }
}

export interface CmsInspection {
  signer: SignerInfo | null;
  digestAlgorithm: string | null;
  cmsSize: number;
  details: string[];
}

/**
 * Inspect a CMS/PKCS#7 blob without verifying against original data.
 *
 * Extracts certificate info and digest algorithm. Use this when
 * only the .p7s file is available (no original data to verify against).
 */
export async function inspectCmsBlob(cmsDer: Uint8Array): Promise<CmsInspection> {
  const details: string[] = [];

  if (cmsDer.length < MIN_CMS_SIZE) {
    details.push(`CMS too small (${cmsDer.length} bytes) -- likely corrupt`);
    return {
      signer: null,
      digestAlgorithm: null,
      cmsSize: cmsDer.length,
      details,
    };
  }

  if (cmsDer[0] !== ASN1_SEQUENCE_TAG) {
    details.push("Not a valid CMS blob (expected ASN.1 SEQUENCE)");
    return {
      signer: null,
      digestAlgorithm: null,
      cmsSize: cmsDer.length,
      details,
    };
  }

  details.push(`CMS blob: ${cmsDer.length} bytes, valid ASN.1 structure`);

  const signer = await extractSignerInfo(cmsDer);
  if (signer) {
    if (signer.name) details.push(`Signer: ${signer.name}`);
    if (signer.organization) {
      details.push(`Organization: ${signer.organization}`);
    }
    if (signer.email) details.push(`Email: ${signer.email}`);
  }

  let digestAlgorithm: string | null = null;
  const digestInfo = extractDigestInfo(cmsDer);
  if (digestInfo) {
    digestAlgorithm = digestInfo.algorithm;
    details.push(`Digest algorithm: ${digestAlgorithm}`);
  }

  return {
    signer,
    digestAlgorithm,
    cmsSize: cmsDer.length,
    details,
  };
}
