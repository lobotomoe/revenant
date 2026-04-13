// SPDX-License-Identifier: Apache-2.0
/**
 * Post-sign verification of embedded PDF signatures.
 *
 * Extracts ByteRange data and CMS blobs, verifies hash consistency,
 * and checks structural validity. Supports multi-signature PDFs.
 */

import { createHash } from "node:crypto";

import { PDFDocument } from "pdf-lib";

import { PDFError, RevenantError } from "../../errors.js";
import { bytesToHex } from "../../utils.js";
import { ASN1_SEQUENCE_TAG, MIN_CMS_SIZE } from "./asn1.js";
import {
  type ByteRangeMatch,
  extractSignatureDataFromMatch,
  findByteRanges,
} from "./cms-extraction.js";
import { extractDigestInfo, extractSignerInfo, type SignerInfo } from "./cms-info.js";

// -- Types --------------------------------------------------------------------

export interface VerificationResult {
  /** Overall verification result. */
  valid: boolean;
  /** ByteRange and CMS structure valid. */
  structureOk: boolean;
  /** Hash matches expected value. */
  hashOk: boolean;
  /** Contains embedded revocation data. */
  ltvEnabled: boolean;
  /** Human-readable messages. */
  details: string[];
  /** Certificate info (name, email, org, dn). */
  signer: SignerInfo | null;
  /** Chain validation result (null = not attempted). */
  chainValid: boolean | null;
  /** CA name from TSL. */
  trustAnchor: string | null;
  /** "trusted" | "untrusted" | "unknown". */
  trustStatus: string | null;
}

// -- Helpers ------------------------------------------------------------------

/** Convert Web Crypto algorithm name to Node.js crypto name. */
function toNodeCryptoName(algo: string): string {
  // "SHA-1" -> "sha1", "SHA-256" -> "sha256"
  return algo.toLowerCase().replace("-", "");
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

// -- Core verification --------------------------------------------------------

/**
 * Core verification logic for a single ByteRange match.
 */
async function verifySignatureMatch(
  pdfBytes: Uint8Array,
  brMatch: ByteRangeMatch,
  expectedHash: Uint8Array | null = null,
  tslUrl: string | null = null,
): Promise<VerificationResult> {
  const details: string[] = [];
  let structureOk = true;

  // 1. Extract signature data
  let signedData: Uint8Array;
  let cmsDer: Uint8Array;
  try {
    const extracted = extractSignatureDataFromMatch(pdfBytes, brMatch);
    signedData = extracted.signedData;
    cmsDer = extracted.cmsDer;
    details.push(`ByteRange OK -- signed data: ${signedData.length} bytes`);
    details.push(`CMS blob: ${cmsDer.length} bytes`);
  } catch (e) {
    const msg = e instanceof RevenantError ? e.message : String(e);
    return {
      valid: false,
      structureOk: false,
      hashOk: false,
      ltvEnabled: false,
      details: [`Structure error: ${msg}`],
      signer: null,
      chainValid: null,
      trustAnchor: null,
      trustStatus: null,
    };
  }

  // 2. CMS structure check
  if (cmsDer.length < MIN_CMS_SIZE) {
    structureOk = false;
    details.push(`CMS too small (${cmsDer.length} bytes) -- likely corrupt`);
  } else if (cmsDer[0] !== ASN1_SEQUENCE_TAG) {
    structureOk = false;
    details.push("CMS does not start with ASN.1 SEQUENCE tag (0x30)");
  } else {
    details.push("CMS: valid ASN.1 structure");
  }

  // 3. Signer info
  const signer = await extractSignerInfo(cmsDer);
  if (signer?.name) {
    details.push(`Signer: ${signer.name}`);
  }

  // 4. Hash verification
  let hashOk = false;

  if (expectedHash !== null) {
    // Post-sign path: we know the exact SHA-1 hash sent to CoSign
    const actualHash = new Uint8Array(createHash("sha1").update(signedData).digest());
    if (bytesEqual(actualHash, expectedHash)) {
      hashOk = true;
      details.push(`Hash OK -- SHA-1 matches expected: ${bytesToHex(actualHash)}`);
    } else {
      details.push(
        `Hash MISMATCH!\n` +
          `  ByteRange SHA-1: ${bytesToHex(actualHash)}\n` +
          `  Expected:        ${bytesToHex(expectedHash)}`,
      );
    }
  } else {
    // Standalone verification: determine algorithm from CMS
    const digestInfo = extractDigestInfo(cmsDer);
    if (digestInfo !== null) {
      const algoNode = toNodeCryptoName(digestInfo.algorithm);
      const algoUpper = digestInfo.algorithm;
      const actualHash = new Uint8Array(createHash(algoNode).update(signedData).digest());
      if (bytesEqual(actualHash, digestInfo.digest)) {
        hashOk = true;
        details.push(
          `Hash OK -- ${algoUpper} matches CMS messageDigest: ${bytesToHex(actualHash)}`,
        );
      } else {
        details.push(
          `Hash MISMATCH!\n` +
            `  ByteRange ${algoUpper}:   ${bytesToHex(actualHash)}\n` +
            `  CMS messageDigest:  ${bytesToHex(digestInfo.digest)}`,
        );
      }
    } else if (cmsDer.length >= MIN_CMS_SIZE && cmsDer[0] === ASN1_SEQUENCE_TAG) {
      // Non-standard CMS -- hash cannot be verified without a reference value.
      const actualHash = new Uint8Array(createHash("sha1").update(signedData).digest());
      details.push(
        `Hash computed -- SHA-1: ${bytesToHex(actualHash)} ` +
          "(CMS digest info not available -- cannot verify)",
      );
    } else {
      details.push("Hash: cannot verify without expected hash and CMS is suspect");
    }
  }

  // 5. LTV status
  const { checkLtvStatus } = await import("./ltv.js");
  const ltv = checkLtvStatus(cmsDer);
  const ltvLabel = ltv.ltvEnabled ? "LTV enabled" : "Not LTV enabled";
  details.push(`LTV: ${ltvLabel}`);

  // 6. Chain validation (optional, best-effort)
  let chainValid: boolean | null = null;
  let trustAnchor: string | null = null;
  let trustStatus: string | null = "unknown";

  if (tslUrl) {
    try {
      const { validateChainForProfile } = await import("../chain.js");
      const chainResult = await validateChainForProfile(cmsDer, tslUrl);
      chainValid = chainResult.chainValid;
      trustAnchor = chainResult.trustAnchor;
      if (chainValid === true) trustStatus = "trusted";
      else if (chainValid === false) trustStatus = "untrusted";
      details.push(...chainResult.details);
    } catch {
      details.push("Chain: validation unavailable");
    }
  }

  const valid = structureOk && hashOk;
  return {
    valid,
    structureOk,
    hashOk,
    ltvEnabled: ltv.ltvEnabled,
    details,
    signer,
    chainValid,
    trustAnchor,
    trustStatus,
  };
}

// -- Public verification API --------------------------------------------------

/**
 * Verify the last embedded PDF signature.
 *
 * Checks structure (ByteRange, CMS), hash (auto-detected algorithm or
 * expected SHA-1), and performs a pdf-lib structural check.
 *
 * Never raises on verification failure -- returns valid=false with details.
 */
export async function verifyEmbeddedSignature(
  pdfBytes: Uint8Array,
  expectedHash: Uint8Array | null = null,
  tslUrl: string | null = null,
): Promise<VerificationResult> {
  const brMatches = findByteRanges(pdfBytes);
  if (brMatches.length === 0) {
    return {
      valid: false,
      structureOk: false,
      hashOk: false,
      ltvEnabled: false,
      details: ["Structure error: No /ByteRange found in PDF -- not a signed PDF?"],
      signer: null,
      chainValid: null,
      trustAnchor: null,
      trustStatus: null,
    };
  }

  const lastMatch = brMatches[brMatches.length - 1];
  if (lastMatch === undefined) {
    return {
      valid: false,
      structureOk: false,
      hashOk: false,
      ltvEnabled: false,
      details: ["Structure error: No /ByteRange found in PDF -- not a signed PDF?"],
      signer: null,
      chainValid: null,
      trustAnchor: null,
      trustStatus: null,
    };
  }
  const result = await verifySignatureMatch(pdfBytes, lastMatch, expectedHash, tslUrl);

  // pdf-lib structural check (informational, does not override signature validity)
  try {
    const pdfDoc = await PDFDocument.load(pdfBytes, {
      updateMetadata: false,
    });
    const pageCount = pdfDoc.getPageCount();
    result.details.push(`pdf-lib: valid PDF, ${pageCount} page(s)`);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    result.details.push(`pdf-lib: structural warning -- ${msg}`);
  }

  return result;
}

/**
 * Verify ALL embedded signatures in a PDF.
 *
 * Iterates every /ByteRange and verifies each signature independently.
 * The pdf-lib structural check is performed once.
 */
export async function verifyAllEmbeddedSignatures(
  pdfBytes: Uint8Array,
  tslUrl: string | null = null,
): Promise<VerificationResult[]> {
  const brMatches = findByteRanges(pdfBytes);
  if (brMatches.length === 0) {
    throw new PDFError("No /ByteRange found in PDF -- not a signed PDF?");
  }

  // pdf-lib structural check (informational)
  let pdfLibDetail = "";
  try {
    const pdfDoc = await PDFDocument.load(pdfBytes, {
      updateMetadata: false,
    });
    const pageCount = pdfDoc.getPageCount();
    pdfLibDetail = `pdf-lib: valid PDF, ${pageCount} page(s)`;
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    pdfLibDetail = `pdf-lib: structural warning -- ${msg}`;
  }

  const results: VerificationResult[] = [];
  for (const brMatch of brMatches) {
    const result = await verifySignatureMatch(pdfBytes, brMatch, null, tslUrl);
    result.details.push(pdfLibDetail);
    results.push(result);
  }

  return results;
}

// -- Detached signature verification ------------------------------------------

/**
 * Verify a detached CMS/PKCS#7 signature against original data.
 *
 * Extracts the digest algorithm and messageDigest from the CMS blob,
 * computes the hash of the original data, and compares.
 */
export async function verifyDetachedSignature(
  dataBytes: Uint8Array,
  cmsDer: Uint8Array,
  tslUrl: string | null = null,
): Promise<VerificationResult> {
  const details: string[] = [];
  let structureOk = true;

  // CMS structure check
  if (cmsDer.length < MIN_CMS_SIZE) {
    structureOk = false;
    details.push(`CMS too small (${cmsDer.length} bytes) -- likely corrupt`);
  } else if (cmsDer[0] !== ASN1_SEQUENCE_TAG) {
    structureOk = false;
    details.push("CMS does not start with ASN.1 SEQUENCE tag (0x30)");
  } else {
    details.push(`CMS blob: ${cmsDer.length} bytes, valid ASN.1 structure`);
  }

  // Signer info
  const signer = await extractSignerInfo(cmsDer);
  if (signer?.name) {
    details.push(`Signer: ${signer.name}`);
  }

  // Hash verification
  let hashOk = false;
  const digestInfo = extractDigestInfo(cmsDer);
  if (digestInfo !== null) {
    const algoNode = toNodeCryptoName(digestInfo.algorithm);
    const algoUpper = digestInfo.algorithm;
    const actualHash = new Uint8Array(createHash(algoNode).update(dataBytes).digest());
    if (bytesEqual(actualHash, digestInfo.digest)) {
      hashOk = true;
      details.push(`Hash OK -- ${algoUpper} matches CMS messageDigest: ${bytesToHex(actualHash)}`);
    } else {
      details.push(
        `Hash MISMATCH!\n` +
          `  Data ${algoUpper}:        ${bytesToHex(actualHash)}\n` +
          `  CMS messageDigest:  ${bytesToHex(digestInfo.digest)}`,
      );
    }
  } else {
    details.push("Could not extract digest info -- hash verification unavailable");
  }

  // LTV status
  const { checkLtvStatus } = await import("./ltv.js");
  const ltv = checkLtvStatus(cmsDer);
  const ltvLabel = ltv.ltvEnabled ? "LTV enabled" : "Not LTV enabled";
  details.push(`LTV: ${ltvLabel}`);

  // Chain validation (optional, best-effort)
  let chainValid: boolean | null = null;
  let trustAnchor: string | null = null;
  let trustStatus: string | null = "unknown";

  if (tslUrl) {
    try {
      const { validateChainForProfile } = await import("../chain.js");
      const chainResult = await validateChainForProfile(cmsDer, tslUrl);
      chainValid = chainResult.chainValid;
      trustAnchor = chainResult.trustAnchor;
      if (chainValid === true) trustStatus = "trusted";
      else if (chainValid === false) trustStatus = "untrusted";
      details.push(...chainResult.details);
    } catch {
      details.push("Chain: validation unavailable");
    }
  }

  const valid = structureOk && hashOk;
  return {
    valid,
    structureOk,
    hashOk,
    ltvEnabled: ltv.ltvEnabled,
    details,
    signer,
    chainValid,
    trustAnchor,
    trustStatus,
  };
}
