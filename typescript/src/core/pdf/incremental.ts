// SPDX-License-Identifier: Apache-2.0
/**
 * PDF structure analysis and incremental update assembly.
 *
 * Functions for reading existing PDF structure (finding objects, xref offsets)
 * and building incremental updates (xref tables, trailers, ByteRange patching).
 *
 * Object-level construction (types, allocation, overrides) is in objects.ts.
 * High-level signing API is in builder.ts.
 */

import { deflateSync } from "node:zlib";

import { PDFArray, PDFDocument, PDFName, PDFRef } from "pdf-lib";

import { PDFError } from "../../errors.js";
import { BYTERANGE_PLACEHOLDER_BYTES, CMS_HEX_SIZE } from "./objects.js";
import { getPageDimensions, resolvePageIndex } from "./position.js";

// -- PDF structure analysis ---------------------------------------------------

/**
 * Find the catalog /Root object number from the trailer.
 *
 * Uses the LAST match -- PDFs with incremental updates may redefine
 * /Root in later trailers, and the last one is always authoritative.
 */
export function findRootObjNum(pdfBytes: Uint8Array): { objNum: number; genNum: number } {
  const text = new TextDecoder("latin1").decode(pdfBytes);
  const pattern = /\/Root\s+(\d+)\s+(\d+)\s+R/g;
  const matches = [...text.matchAll(pattern)];
  if (matches.length === 0) {
    throw new PDFError("Cannot find /Root reference in PDF trailer.");
  }
  const last = matches[matches.length - 1];
  if (last === undefined) {
    throw new PDFError("Cannot find /Root reference in PDF trailer.");
  }
  const objNumStr = last[1];
  const genNumStr = last[2];
  if (objNumStr === undefined || genNumStr === undefined) {
    throw new PDFError("Malformed /Root reference in PDF trailer.");
  }
  return {
    objNum: parseInt(objNumStr, 10),
    genNum: parseInt(genNumStr, 10),
  };
}

export interface PageInfo {
  pageObjNum: number;
  pageWidth: number;
  pageHeight: number;
  hasAnnots: boolean;
  existingAnnots: string[];
}

/**
 * Find the object number of the target page.
 *
 * Uses pdf-lib for reading -- never saves the PDF.
 */
export async function findPageObjNum(
  pdfBytes: Uint8Array,
  pageSpec: number | string,
): Promise<PageInfo> {
  const pdfDoc = await PDFDocument.load(pdfBytes, {
    updateMetadata: false,
  });
  const pageIdx = resolvePageIndex(pdfDoc, pageSpec);
  const page = pdfDoc.getPage(pageIdx);

  // Get the page's indirect reference to determine object number
  const pagesArray = pdfDoc.catalog.get(PDFName.of("Pages"));
  if (!(pagesArray instanceof PDFRef)) {
    throw new PDFError("Cannot resolve /Pages reference in catalog");
  }
  const pagesDict = pdfDoc.context.lookup(pagesArray);
  if (!pagesDict) {
    throw new PDFError("Cannot find /Pages dictionary");
  }

  // Use the page node's own reference if available
  const pageNode = page.node;
  let pageObjNum = 0;

  // Search all objects to find the one matching our page node
  for (const [ref, obj] of pdfDoc.context.enumerateIndirectObjects()) {
    if (obj === pageNode) {
      pageObjNum = ref.objectNumber;
      break;
    }
  }
  if (pageObjNum === 0) {
    throw new PDFError(`Cannot determine object number for page ${pageIdx}`);
  }

  const dims = getPageDimensions(pdfDoc, pageIdx);

  // Check if page already has /Annots
  const existingAnnots: string[] = [];
  const annotsValue = pageNode.get(PDFName.of("Annots"));
  let hasAnnots = false;

  if (annotsValue) {
    hasAnnots = true;
    // Resolve if indirect
    const resolved =
      annotsValue instanceof PDFRef ? pdfDoc.context.lookup(annotsValue) : annotsValue;
    if (resolved instanceof PDFArray) {
      for (let i = 0; i < resolved.size(); i++) {
        const ref = resolved.get(i);
        if (ref instanceof PDFRef) {
          existingAnnots.push(`${ref.objectNumber} ${ref.generationNumber} R`);
        }
      }
    }
  }

  return {
    pageObjNum,
    pageWidth: dims.width,
    pageHeight: dims.height,
    hasAnnots,
    existingAnnots,
  };
}

/**
 * Find the last startxref offset, max object number, and trailer entries.
 */
export async function findPrevStartxref(pdfBytes: Uint8Array): Promise<{
  prevXref: number;
  maxSize: number;
  trailerExtra: string[];
  useXrefStream: boolean;
}> {
  const text = new TextDecoder("latin1").decode(pdfBytes);

  // Find the LAST startxref in the file
  const pattern = /startxref\s+(\d+)\s+%%EOF/g;
  const matches = [...text.matchAll(pattern)];
  if (matches.length === 0) {
    throw new PDFError("Cannot find startxref in PDF.");
  }
  const lastMatch = matches[matches.length - 1];
  if (lastMatch === undefined) {
    throw new PDFError("Cannot find startxref in PDF.");
  }
  const prevXrefStr = lastMatch[1];
  if (prevXrefStr === undefined) {
    throw new PDFError("Malformed startxref entry in PDF.");
  }
  const prevXref = parseInt(prevXrefStr, 10);

  // Determine /Size: use the maximum of pdf-lib's object count and the
  // /Size value from the trailer or XRef stream.  pdf-lib unpacks ObjStm
  // contents but doesn't count ObjStm/XRef stream objects themselves,
  // so largestObjectNumber can be too low for compact PDFs.
  const pdfDoc = await PDFDocument.load(pdfBytes, {
    updateMetadata: false,
  });
  const pdfLibSize = pdfDoc.context.largestObjectNumber + 1;
  const trailerSize = parseTrailerSize(text);
  const maxSize = Math.max(pdfLibSize, trailerSize);

  // Extract extra trailer entries to carry forward (/Info, /ID, etc.)
  const trailerExtra = extractTrailerEntries(pdfBytes, text);

  // Detect if source PDF uses XRef streams -- incremental updates must
  // use the same format (ISO 32000-1 S7.5.8.4)
  const useXrefStream = detectXrefStreams(pdfBytes, prevXref);

  return { prevXref, maxSize, trailerExtra, useXrefStream };
}

/**
 * Extract /Info and /ID entries from the trailer.
 */
function extractTrailerEntries(_pdfBytes: Uint8Array, text: string): string[] {
  const trailerExtra: string[] = [];

  // Try traditional trailers first
  const trailerPattern = /trailer\s*<<([\s\S]*?)>>/g;
  const allTrailers = [...text.matchAll(trailerPattern)];

  if (allTrailers.length > 0) {
    const lastTrailer = allTrailers[allTrailers.length - 1];
    if (lastTrailer === undefined) {
      return trailerExtra;
    }
    const trailerContent = lastTrailer[1];
    if (trailerContent === undefined) {
      return trailerExtra;
    }

    const infoMatch = trailerContent.match(/\/Info\s+\d+\s+\d+\s+R/);
    if (infoMatch) {
      trailerExtra.push(infoMatch[0]);
    }

    const idMatch = trailerContent.match(/\/ID\s*\[[\s\S]*?\]/);
    if (idMatch) {
      trailerExtra.push(idMatch[0]);
    }

    if (trailerExtra.length > 0) {
      return trailerExtra;
    }
  }

  // For cross-reference stream PDFs, try to extract from xref stream dicts.
  // Look for any object that contains both /Type /XRef and /Info or /ID.
  const xrefStreamPattern = /\d+\s+\d+\s+obj\s*<<([\s\S]*?)>>\s*stream/g;
  const xrefStreams = [...text.matchAll(xrefStreamPattern)];
  for (const xrefMatch of xrefStreams) {
    const content = xrefMatch[1];
    if (content === undefined) {
      continue;
    }
    if (!content.includes("/Type /XRef") && !content.includes("/Type/XRef")) {
      continue;
    }

    const infoMatch = content.match(/\/Info\s+\d+\s+\d+\s+R/);
    if (infoMatch) {
      trailerExtra.push(infoMatch[0]);
    }

    const idMatch = content.match(/\/ID\s*\[[\s\S]*?\]/);
    if (idMatch) {
      trailerExtra.push(idMatch[0]);
    }

    if (trailerExtra.length > 0) {
      return trailerExtra;
    }
  }

  return trailerExtra;
}

// -- Incremental update assembly ----------------------------------------------

/**
 * Assemble the full PDF with incremental update appended.
 */
export function assembleIncrementalUpdate(
  pdfBytes: Uint8Array,
  rawObjects: Array<{ raw: Uint8Array; objNum: number }>,
  newSize: number,
  prevXref: number,
  rootObjNum: number,
  rootGen: number,
  trailerExtra: string[],
  useXrefStream: boolean = false,
): Uint8Array {
  // Ensure original PDF ends with \n after %%EOF
  let base = pdfBytes;
  if (base[base.length - 1] !== 0x0a) {
    const extended = new Uint8Array(base.length + 1);
    extended.set(base, 0);
    extended[base.length] = 0x0a;
    base = extended;
  }

  const updateStart = base.length;

  // Collect all new objects and their offsets
  const xrefEntries = new Map<number, number>();
  const objectChunks: Uint8Array[] = [];
  let runningOffset = updateStart;

  for (const { raw, objNum } of rawObjects) {
    xrefEntries.set(objNum, runningOffset);
    objectChunks.push(raw);
    runningOffset += raw.length;
  }

  const allObjects = Buffer.concat(objectChunks);

  // Build xref section (table or stream depending on source PDF format)
  const xrefOffset = updateStart + allObjects.length;

  if (useXrefStream) {
    const xrefObjNum = newSize;
    const xrefData = buildXrefStream({
      xrefEntries,
      newSize,
      prevXref,
      rootObjNum,
      rootGen,
      trailerExtra,
      xrefOffset,
      xrefObjNum,
    });
    return Buffer.concat([base, allObjects, xrefData]);
  }

  const xrefData = buildXrefAndTrailer({
    xrefEntries,
    newSize,
    prevXref,
    rootObjNum,
    rootGen,
    trailerExtra,
    xrefOffset,
  });

  return Buffer.concat([base, allObjects, xrefData]);
}

/**
 * Patch the ByteRange placeholder and return the patched PDF with hex positions.
 */
export function patchByterange(
  fullPdf: Uint8Array,
  originalLen: number,
): { pdf: Uint8Array; hexStart: number; hexLen: number } {
  const contentsZeros = "0".repeat(CMS_HEX_SIZE);
  const contentsMarker = new TextEncoder().encode(`/Contents <${contentsZeros}>`);

  // Search from where the incremental update starts
  const contentsPos = findBytes(fullPdf, contentsMarker, originalLen);
  if (contentsPos === -1) {
    throw new PDFError("Cannot find Contents placeholder in prepared PDF.");
  }

  const contentsPrefixLen = "/Contents <".length;
  const hexStart = contentsPos + contentsPrefixLen;
  const hexEnd = hexStart + CMS_HEX_SIZE;

  // Compute ByteRange values
  const brBeforeLen = hexStart;
  const brAfterStart = hexEnd + 1; // +1 for closing ">"
  const brAfterLen = fullPdf.length - brAfterStart;

  const byterangeValue = new TextEncoder().encode(
    `/ByteRange [${pad(0, 10)} ${pad(brBeforeLen, 10)} ${pad(brAfterStart, 10)} ${pad(brAfterLen, 10)}]`,
  );

  // Patch the ByteRange placeholder in the incremental update only
  const brPos = findBytes(fullPdf, BYTERANGE_PLACEHOLDER_BYTES, originalLen);
  if (brPos === -1) {
    throw new PDFError("Cannot find ByteRange placeholder in incremental update.");
  }

  // Width must match exactly -- mismatched length silently corrupts the PDF
  if (byterangeValue.length !== BYTERANGE_PLACEHOLDER_BYTES.length) {
    throw new PDFError(
      `ByteRange replacement width mismatch: ` +
        `got ${byterangeValue.length}, expected ${BYTERANGE_PLACEHOLDER_BYTES.length}`,
    );
  }

  const patched = new Uint8Array(fullPdf);
  patched.set(byterangeValue, brPos);

  return { pdf: patched, hexStart, hexLen: CMS_HEX_SIZE };
}

// -- Xref table builder -------------------------------------------------------

interface XrefTrailerOptions {
  xrefEntries: Map<number, number>;
  newSize: number;
  prevXref: number;
  rootObjNum: number;
  rootGen: number;
  trailerExtra: string[];
  xrefOffset: number;
}

interface XrefStreamOptions extends XrefTrailerOptions {
  xrefObjNum: number;
}

/**
 * Build an xref table and trailer for an incremental update.
 */
export function buildXrefAndTrailer(options: XrefTrailerOptions): Uint8Array {
  const { xrefEntries, newSize, prevXref, rootObjNum, rootGen, trailerExtra, xrefOffset } = options;

  const lines: string[] = ["xref"];

  if (xrefEntries.size === 0) {
    throw new PDFError("Cannot build xref table: no objects to reference.");
  }

  // Group consecutive object numbers for compact xref sections
  const sortedNums = [...xrefEntries.keys()].sort((a, b) => a - b);
  const groups = groupConsecutive(sortedNums);

  for (const group of groups) {
    lines.push(`${group[0]} ${group.length}`);
    // PDF spec S7.5.4: each xref entry is exactly 20 bytes including EOL.
    // Format: "oooooooooo ggggg n\r\n"
    for (const objNum of group) {
      const offset = xrefEntries.get(objNum);
      if (offset === undefined) {
        throw new PDFError(`Missing xref offset for object ${objNum}.`);
      }
      lines.push(`${offset.toString().padStart(10, "0")} 00000 n\r`);
    }
  }

  lines.push("trailer");
  lines.push("<<");
  lines.push(`  /Size ${newSize}`);
  lines.push(`  /Prev ${prevXref}`);
  lines.push(`  /Root ${rootObjNum} ${rootGen} R`);
  for (const extra of trailerExtra) {
    lines.push(`  ${extra}`);
  }
  lines.push(">>");
  lines.push("startxref");
  lines.push(String(xrefOffset));
  lines.push("%%EOF");
  lines.push(""); // trailing newline

  return new TextEncoder().encode(lines.join("\n"));
}

/**
 * Build a cross-reference stream for an incremental update (PDF 1.5+).
 *
 * PDFs that use XRef streams require incremental updates to also use
 * XRef streams (ISO 32000-1 S7.5.8.4). This replaces both the xref
 * table and trailer with a single stream object.
 */
export function buildXrefStream(options: XrefStreamOptions): Uint8Array {
  const { xrefEntries, prevXref, rootObjNum, rootGen, trailerExtra, xrefOffset, xrefObjNum } =
    options;

  // Include the XRef stream object in its own cross-reference data
  const allEntries = new Map(xrefEntries);
  allEntries.set(xrefObjNum, xrefOffset);

  // /Size = highest object number + 1
  const actualSize = xrefObjNum + 1;

  // Determine W (column widths for binary entries per ISO 32000-1 Table 17)
  // Column 1: type (1 byte, value 1 = in-use uncompressed)
  // Column 2: byte offset (variable width, big-endian)
  // Column 3: generation number (1 byte, always 0 for new objects)
  const maxOffset = Math.max(...allEntries.values());
  const w2 = bytesNeeded(maxOffset);

  // Build /Index subsections and binary stream data
  const sortedNums = [...allEntries.keys()].sort((a, b) => a - b);
  const groups = groupConsecutive(sortedNums);
  const indexParts: string[] = [];
  const binaryParts: number[] = [];

  for (const group of groups) {
    const first = group[0];
    if (first === undefined) continue;
    indexParts.push(`${first} ${group.length}`);
    for (const objNum of group) {
      const offset = allEntries.get(objNum);
      if (offset === undefined) {
        throw new PDFError(`Missing xref offset for object ${objNum}.`);
      }
      binaryParts.push(1);
      for (let i = w2 - 1; i >= 0; i--) {
        binaryParts.push((offset >>> (i * 8)) & 0xff);
      }
      binaryParts.push(0);
    }
  }

  const rawStreamData = Buffer.from(binaryParts);
  const compressed = deflateSync(rawStreamData);

  // Build the XRef stream object (replaces both xref table and trailer)
  const lines: string[] = [];
  lines.push(`${xrefObjNum} 0 obj`);
  lines.push("<<");
  lines.push("  /Type /XRef");
  lines.push(`  /Size ${actualSize}`);
  lines.push(`  /Prev ${prevXref}`);
  lines.push(`  /Root ${rootObjNum} ${rootGen} R`);
  lines.push(`  /W [1 ${w2} 1]`);
  lines.push(`  /Index [${indexParts.join(" ")}]`);
  lines.push("  /Filter /FlateDecode");
  lines.push(`  /Length ${compressed.length}`);
  for (const extra of trailerExtra) {
    lines.push(`  ${extra}`);
  }
  lines.push(">>");
  lines.push("stream");

  const header = new TextEncoder().encode(`${lines.join("\n")}\n`);
  const footer = new TextEncoder().encode(`\nendstream\nendobj\nstartxref\n${xrefOffset}\n%%EOF\n`);

  return Buffer.concat([header, compressed, footer]);
}

// -- Helpers ------------------------------------------------------------------

function findBytes(haystack: Uint8Array, needle: Uint8Array, startOffset: number = 0): number {
  outer: for (let i = startOffset; i <= haystack.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (haystack[i + j] !== needle[j]) continue outer;
    }
    return i;
  }
  return -1;
}

function pad(n: number, width: number): string {
  return n.toString().padStart(width, " ");
}

/**
 * Parse the largest /Size value from all trailers and XRef streams.
 *
 * pdf-lib's largestObjectNumber doesn't count ObjStm/XRef stream objects,
 * so this provides a floor value to prevent object number collisions.
 */
function parseTrailerSize(text: string): number {
  let maxSize = 0;

  // Traditional trailers: trailer << ... /Size N ... >>
  const trailerPattern = /\/Size\s+(\d+)/g;
  for (const m of text.matchAll(trailerPattern)) {
    const sizeStr = m[1];
    if (sizeStr !== undefined) {
      const size = parseInt(sizeStr, 10);
      if (size > maxSize) maxSize = size;
    }
  }

  return maxSize;
}

/**
 * Detect whether the PDF uses cross-reference streams (PDF 1.5+).
 *
 * Checks the bytes at the last startxref offset: if they match an object
 * definition (N N obj) rather than "xref", the PDF uses XRef streams.
 */
function detectXrefStreams(pdfBytes: Uint8Array, startxrefOffset: number): boolean {
  const end = Math.min(startxrefOffset + 40, pdfBytes.length);
  const slice = pdfBytes.subarray(startxrefOffset, end);
  const text = new TextDecoder("latin1").decode(slice);
  return /^\s*\d+\s+\d+\s+obj\b/.test(text);
}

/**
 * Group sorted numbers into consecutive runs for xref subsections.
 */
function groupConsecutive(sortedNums: number[]): number[][] {
  if (sortedNums.length === 0) return [];
  const first = sortedNums[0];
  if (first === undefined) return [];

  const groups: number[][] = [];
  let currentGroup = [first];
  for (let i = 1; i < sortedNums.length; i++) {
    const n = sortedNums[i];
    if (n === undefined) continue;
    const lastInGroup = currentGroup[currentGroup.length - 1];
    if (lastInGroup !== undefined && n === lastInGroup + 1) {
      currentGroup.push(n);
    } else {
      groups.push(currentGroup);
      currentGroup = [n];
    }
  }
  groups.push(currentGroup);
  return groups;
}

/**
 * Minimum bytes needed to represent a non-negative integer in big-endian.
 */
function bytesNeeded(value: number): number {
  if (value <= 0xff) return 1;
  if (value <= 0xffff) return 2;
  if (value <= 0xffffff) return 3;
  return 4;
}
