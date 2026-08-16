// SPDX-License-Identifier: Apache-2.0
/**
 * ByteRange and CMS extraction from signed PDFs.
 */

import { PDFError } from "../../errors.js";
import { extractDerFromPaddedHex, MAX_CMS_HEX_CHARS } from "./asn1.js";

/** Regex pattern to find ByteRange arrays in PDF. */
export const BYTERANGE_PATTERN = /\/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]/g;

export interface ByteRangeMatch {
  off1: number;
  len1: number;
  off2: number;
  len2: number;
}

/** How much of a file one signature's ByteRange actually covers. */
export interface ByteRangeCoverage {
  coveredBytes: number;
  totalBytes: number;
  /** First byte position past the signature's coverage. */
  coverageEnd: number;
  coversToEof: boolean;
  /** Bytes after this signature's coverage, if any. */
  trailingBytes: number;
}

/**
 * Measure what portion of the file a ByteRange covers.
 *
 * A ByteRange `[a b c d]` covers `[a, a+b)` and `[c, c+d)`. The hole between
 * them is the `/Contents` slot holding the signature itself, so it is not a gap
 * in coverage. Anything at or after `c + d` lies outside this signature: in an
 * incrementally updated PDF that is usually a later revision, which a
 * subsequent signature may or may not cover.
 */
export function byteRangeCoverage(pdfBytes: Uint8Array, br: ByteRangeMatch): ByteRangeCoverage {
  const totalBytes = pdfBytes.length;
  const coverageEnd = br.off2 + br.len2;
  return {
    coveredBytes: br.len1 + br.len2,
    totalBytes,
    coverageEnd,
    coversToEof: coverageEnd >= totalBytes,
    trailingBytes: Math.max(totalBytes - coverageEnd, 0),
  };
}

/**
 * Find all ByteRange matches in PDF bytes.
 */
export function findByteRanges(pdfBytes: Uint8Array): ByteRangeMatch[] {
  const text = new TextDecoder("latin1").decode(pdfBytes);
  const pattern = new RegExp(BYTERANGE_PATTERN.source, "g");
  const matches: ByteRangeMatch[] = [];

  for (const m of text.matchAll(pattern)) {
    const g1 = m[1];
    const g2 = m[2];
    const g3 = m[3];
    const g4 = m[4];
    if (g1 === undefined || g2 === undefined || g3 === undefined || g4 === undefined) {
      continue;
    }
    matches.push({
      off1: parseInt(g1, 10),
      len1: parseInt(g2, 10),
      off2: parseInt(g3, 10),
      len2: parseInt(g4, 10),
    });
  }

  return matches;
}

/**
 * Extract CMS DER blob from a PDF given ByteRange parameters.
 *
 * This is the canonical low-level extraction function used by both
 * signature verification and certificate discovery.
 */
export function extractCmsFromByterange(
  pdfBytes: Uint8Array,
  len1: number,
  off2: number,
): Uint8Array {
  if (len1 <= 0) {
    throw new PDFError(`Invalid ByteRange: len1 must be positive, got ${len1}`);
  }
  if (off2 <= len1) {
    throw new PDFError(`Invalid ByteRange: off2 (${off2}) must be greater than len1 (${len1})`);
  }
  if (off2 > pdfBytes.length) {
    throw new PDFError(`Invalid ByteRange: off2 (${off2}) exceeds PDF size (${pdfBytes.length})`);
  }

  // ByteRange structure: [0 len1 off2 len2]
  // The hex signature sits between angle brackets in the gap between chunks.
  // Two conventions exist for where the "<" bracket falls:
  //   Revenant: "<" is at len1-1 (included in chunk1), hex starts at len1
  //   Original cosign: "<" is at len1 (first byte of gap), hex starts at len1+1
  // The ">" bracket is consistently at off2-1 in both conventions.
  let hexStart: number;
  if (pdfBytes[len1 - 1] === 0x3c) {
    // Revenant convention: chunk1 includes "<"
    hexStart = len1;
  } else if (pdfBytes[len1] === 0x3c) {
    // Original cosign convention: "<" is outside chunk1
    hexStart = len1 + 1;
  } else {
    const prev = (pdfBytes[len1 - 1] ?? 0).toString(16);
    const curr = (pdfBytes[len1] ?? 0).toString(16);
    throw new PDFError(`Expected '<' near offset ${len1}, got 0x${prev} 0x${curr}`);
  }

  const hexEnd = off2 - 1; // position of ">"
  if (pdfBytes[hexEnd] !== 0x3e) {
    throw new PDFError(
      `Expected '>' at offset ${hexEnd}, got 0x${(pdfBytes[hexEnd] ?? 0).toString(16)}`,
    );
  }

  // Bound the gap before decoding it, not after: the /Contents span is whatever
  // the document says it is, and turning it into a string is itself the
  // allocation worth refusing.
  const gapLength = hexEnd - hexStart;
  if (gapLength > MAX_CMS_HEX_CHARS) {
    throw new PDFError(
      `Signature /Contents is ${gapLength / 2} bytes, exceeds maximum ` +
        `(${MAX_CMS_HEX_CHARS / 2} bytes)`,
    );
  }

  const hexBytes = pdfBytes.slice(hexStart, hexEnd);
  const hexStr = new TextDecoder("ascii").decode(hexBytes).trim();

  try {
    return extractDerFromPaddedHex(hexStr);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    throw new PDFError(`Invalid hex in CMS blob: ${msg}`);
  }
}

/**
 * Extract CMS DER blob from a ByteRange match.
 */
export function extractCmsFromByterangeMatch(
  pdfBytes: Uint8Array,
  brMatch: ByteRangeMatch,
): Uint8Array {
  return extractCmsFromByterange(pdfBytes, brMatch.len1, brMatch.off2);
}

/**
 * Extract ByteRange data and CMS blob from a specific ByteRange match.
 */
export function extractSignatureDataFromMatch(
  pdfBytes: Uint8Array,
  brMatch: ByteRangeMatch,
): { signedData: Uint8Array; cmsDer: Uint8Array } {
  if (brMatch.off1 !== 0) {
    throw new PDFError(`ByteRange offset1 should be 0, got ${brMatch.off1}`);
  }
  if (brMatch.off2 <= brMatch.len1) {
    throw new PDFError(`ByteRange offset2 (${brMatch.off2}) <= len1 (${brMatch.len1})`);
  }
  if (brMatch.off2 + brMatch.len2 > pdfBytes.length) {
    throw new PDFError(
      `ByteRange extends beyond EOF: ${brMatch.off2}+${brMatch.len2} > ${pdfBytes.length}`,
    );
  }

  const chunk1 = pdfBytes.slice(brMatch.off1, brMatch.off1 + brMatch.len1);
  const chunk2 = pdfBytes.slice(brMatch.off2, brMatch.off2 + brMatch.len2);

  const signedData = new Uint8Array(chunk1.length + chunk2.length);
  signedData.set(chunk1, 0);
  signedData.set(chunk2, chunk1.length);

  const cmsDer = extractCmsFromByterange(pdfBytes, brMatch.len1, brMatch.off2);
  return { signedData, cmsDer };
}

/**
 * Extract ByteRange data and CMS blob from the last signature in a signed PDF.
 *
 * For multi-signature PDFs, returns the last (most recent) signature.
 */
export function extractSignatureData(pdfBytes: Uint8Array): {
  signedData: Uint8Array;
  cmsDer: Uint8Array;
} {
  const brMatches = findByteRanges(pdfBytes);
  if (brMatches.length === 0) {
    throw new PDFError("No /ByteRange found in PDF -- not a signed PDF?");
  }
  const lastMatch = brMatches[brMatches.length - 1];
  if (lastMatch === undefined) {
    throw new PDFError("No /ByteRange found in PDF -- not a signed PDF?");
  }
  return extractSignatureDataFromMatch(pdfBytes, lastMatch);
}
