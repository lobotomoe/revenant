// SPDX-License-Identifier: Apache-2.0
/**
 * Post-sign verification of embedded PDF signatures.
 *
 * Extracts ByteRange data and CMS blobs, verifies hash consistency and the CMS
 * signer signature, and checks structural validity. Supports multi-signature PDFs.
 */

import { createHash } from "node:crypto";

import { PDFDocument } from "pdf-lib";

import { PDFError, RevenantError } from "../../errors.js";
import { bytesToHex } from "../../utils.js";
import { ASN1_SEQUENCE_TAG, MIN_CMS_SIZE } from "./asn1.js";
import {
  type ByteRangeMatch,
  byteRangeCoverage,
  extractSignatureDataFromMatch,
  findByteRanges,
} from "./cms-extraction.js";
import { extractDigestInfo, extractSignerInfo, type SignerInfo } from "./cms-info.js";
import { type SignatureVerification, verifySignerSignature } from "./cms-signature.js";

// -- Types --------------------------------------------------------------------

/** How much of the file one signature covers. */
export interface SignatureCoverage {
  /** ByteRange reaches EOF; false = bytes follow it. */
  coversWholeFile: boolean;
  /** Bytes the ByteRange actually covers. */
  coveredBytes: number;
  /** Size of the whole file. */
  totalBytes: number;
}

export interface VerificationResult {
  /** Overall verification result. */
  valid: boolean;
  /** ByteRange and CMS structure valid. */
  structureOk: boolean;
  /** CMS digest matches data (and the optional expected hash matches). */
  hashOk: boolean;
  /** Cryptographic signer signature result (null = verification unavailable). */
  signatureValid: boolean | null;
  /** How much of the file this signature covers. */
  coverage: SignatureCoverage;
  /** Contains embedded revocation data. */
  ltvEnabled: boolean;
  /** Human-readable messages. */
  details: string[];
  /** Authenticated certificate info (name, email, org, dn), or null. */
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

/** Expose certificate identity only when it is bound by ESS or a trusted chain. */
function authenticatedSigner(
  candidate: SignerInfo | null,
  signature: SignatureVerification,
  chainValid: boolean | null,
  details: string[],
): SignerInfo | null {
  if (candidate === null) return null;

  if (signature.valid === true && (signature.signerCertificateBound || chainValid === true)) {
    if (candidate.name) details.push(`Signer: ${candidate.name}`);
    return candidate;
  }

  if (signature.valid === true) {
    details.push(
      "Signer identity not authenticated -- no matching ESS certificate binding or trusted certificate chain",
    );
  }
  return null;
}

function verifyHash(
  data: Uint8Array,
  cmsDer: Uint8Array,
  details: string[],
  signature: SignatureVerification,
  dataLabel: string,
  expectedHash: Uint8Array | null = null,
): boolean {
  let expectedOk = true;
  if (expectedHash !== null) {
    const actualSha1 = new Uint8Array(createHash("sha1").update(data).digest());
    expectedOk = bytesEqual(actualSha1, expectedHash);
    if (expectedOk) {
      details.push(`Hash OK -- SHA-1 matches expected: ${bytesToHex(actualSha1)}`);
    } else {
      details.push(
        `Hash MISMATCH!\n` +
          `  ${dataLabel} SHA-1: ${bytesToHex(actualSha1)}\n` +
          `  Expected:        ${bytesToHex(expectedHash)}`,
      );
    }
  }

  const digestInfo = extractDigestInfo(cmsDer);
  if (digestInfo === null) {
    if (signature.coversContent) {
      // RFC 5652 section 5.4: with no signed attributes there is no separate
      // messageDigest to compare -- the signature itself binds these bytes,
      // so integrity follows from the signature verdict alone.
      details.push("Integrity: signature covers the signed bytes directly (no signed attributes)");
      return expectedOk && signature.valid === true;
    }
    details.push("CMS messageDigest unavailable -- cannot verify hash");
    return false;
  }

  const algoNode = toNodeCryptoName(digestInfo.algorithm);
  const actualDigest = new Uint8Array(createHash(algoNode).update(data).digest());
  const cmsDigestOk = bytesEqual(actualDigest, digestInfo.digest);
  if (cmsDigestOk) {
    details.push(
      `Hash OK -- ${digestInfo.algorithm} matches CMS messageDigest: ${bytesToHex(actualDigest)}`,
    );
  } else {
    details.push(
      `Hash MISMATCH!\n` +
        `  ${dataLabel} ${digestInfo.algorithm}:   ${bytesToHex(actualDigest)}\n` +
        `  CMS messageDigest:  ${bytesToHex(digestInfo.digest)}`,
    );
  }
  return expectedOk && cmsDigestOk;
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
      signatureValid: null,
      coverage: { coversWholeFile: false, coveredBytes: 0, totalBytes: 0 },
      ltvEnabled: false,
      details: [`Structure error: ${msg}`],
      signer: null,
      chainValid: null,
      trustAnchor: null,
      trustStatus: null,
    };
  }

  // 2a. Signature coverage. Bytes past the ByteRange are not signed by this
  // signature. In an incrementally updated PDF they are usually a later
  // revision -- possibly another signature, possibly an unsigned change.
  // Reported, never inferred.
  const coverage = byteRangeCoverage(pdfBytes, brMatch);
  details.push(
    coverage.coversToEof
      ? `Coverage: whole file (${coverage.coveredBytes} of ${coverage.totalBytes} bytes)`
      : `Coverage: partial -- ${coverage.trailingBytes} of ${coverage.totalBytes} bytes ` +
          "follow this signature and are outside it",
  );

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
  const candidateSigner = await extractSignerInfo(cmsDer);

  // 4. Cryptographic signature verification
  const signature = await verifySignerSignature(cmsDer, signedData);

  // 5. Hash verification
  const hashOk = verifyHash(signedData, cmsDer, details, signature, "ByteRange", expectedHash);
  details.push(signature.detail);

  // 6. LTV status
  const { checkLtvStatus } = await import("./ltv.js");
  const ltv = checkLtvStatus(cmsDer);
  const ltvLabel = ltv.ltvEnabled ? "LTV enabled" : "Not LTV enabled";
  details.push(`LTV: ${ltvLabel}`);

  // 7. Chain validation (optional, best-effort)
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

  const signer = authenticatedSigner(candidateSigner, signature, chainValid, details);
  const valid = structureOk && hashOk && signature.valid === true;
  return {
    valid,
    structureOk,
    hashOk,
    signatureValid: signature.valid,
    coverage: {
      coversWholeFile: coverage.coversToEof,
      coveredBytes: coverage.coveredBytes,
      totalBytes: coverage.totalBytes,
    },
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
 * Checks structure (ByteRange, CMS), the signed CMS digest, an optional
 * expected SHA-1, the signer signature, and performs a pdf-lib structural check.
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
      signatureValid: null,
      coverage: { coversWholeFile: false, coveredBytes: 0, totalBytes: 0 },
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
      signatureValid: null,
      coverage: { coversWholeFile: false, coveredBytes: 0, totalBytes: 0 },
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

  // One signature covering an earlier revision is expected -- a later signature
  // covers the rest. Bytes past *every* signature are signed by nobody, which is
  // decided by arithmetic alone, without inspecting what they contain.
  const lastResult = results[results.length - 1];
  if (lastResult !== undefined && !results.some((r) => r.coverage.coversWholeFile)) {
    const furthest = Math.max(
      ...brMatches.map((br) => byteRangeCoverage(pdfBytes, br).coverageEnd),
    );
    const unsigned = pdfBytes.length - furthest;
    lastResult.details.push(
      `WARNING: ${unsigned} trailing bytes are covered by no signature in this document`,
    );
  }

  return results;
}

// -- Detached signature verification ------------------------------------------

/**
 * Verify a detached CMS/PKCS#7 signature against original data.
 *
 * Extracts the digest algorithm and messageDigest from the CMS blob, compares
 * it with the original data, and verifies the signer signature.
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
  const candidateSigner = await extractSignerInfo(cmsDer);

  // Cryptographic signature verification
  const signature = await verifySignerSignature(cmsDer, dataBytes);

  // Hash verification
  const hashOk = verifyHash(dataBytes, cmsDer, details, signature, "Data");
  details.push(signature.detail);

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

  const signer = authenticatedSigner(candidateSigner, signature, chainValid, details);
  const valid = structureOk && hashOk && signature.valid === true;
  return {
    valid,
    structureOk,
    hashOk,
    signatureValid: signature.valid,
    // A detached signature covers exactly the data it was handed; there is no
    // surrounding file that could carry unsigned bytes.
    coverage: {
      coversWholeFile: true,
      coveredBytes: dataBytes.length,
      totalBytes: dataBytes.length,
    },
    ltvEnabled: ltv.ltvEnabled,
    details,
    signer,
    chainValid,
    trustAnchor,
    trustStatus,
  };
}
