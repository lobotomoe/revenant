// SPDX-License-Identifier: Apache-2.0
/**
 * PDF signature field preparation.
 *
 * High-level API for preparing PDFs with empty signature fields,
 * computing ByteRange hashes, and inserting CMS containers.
 *
 * Low-level PDF object building is in objects.ts.
 * Low-level rendering object construction is in render.ts.
 * Position/geometry helpers are in position.ts.
 * Post-sign verification is in verify.ts.
 */

import { createHash } from "node:crypto";

import { PDFError } from "../../errors.js";
import { bytesToHex } from "../../utils.js";
import type { FontMetrics } from "../appearance/fonts.js";
import {
  type AppearanceData,
  buildAppearanceStream,
  getFont,
  loadSignatureImage,
  makeDateStr,
  type SignatureImageData,
} from "../appearance/index.js";
import {
  assembleIncrementalUpdate,
  findPageObjNum,
  findPrevStartxref,
  findRootObjNum,
  patchByterange,
} from "./incremental.js";
import {
  allocateSigObjects,
  buildCatalogOverride,
  buildPageOverride,
  type SigObjectNums,
} from "./objects.js";
import { computeSigRect, SIG_HEIGHT, SIG_WIDTH } from "./position.js";
import {
  buildAnnotWidget,
  buildEmbeddedFontObjects,
  buildFormXobjects,
  buildInvisibleAnnotWidget,
  buildSigDict,
  type FormXobjects,
} from "./render.js";

// -- Helpers ------------------------------------------------------------------

function toBytes(raw: string | Uint8Array): Uint8Array {
  if (raw instanceof Uint8Array) return raw;
  return new TextEncoder().encode(raw);
}

// -- Public API ---------------------------------------------------------------

export interface PrepareOptions {
  /** Page for the signature -- 0-based int, "first", or "last". */
  page?: number | string;
  /** Manual X coordinate (PDF points, origin = bottom-left). */
  x?: number | null;
  /** Manual Y coordinate (PDF points, origin = bottom-left). */
  y?: number | null;
  /** Signature field width in PDF points. */
  width?: number;
  /** Signature field height in PDF points. */
  height?: number;
  /** Preset name ("bottom-right", "br", etc.). Ignored when x/y provided. */
  position?: string;
  /** Signature reason string. */
  reason?: string;
  /** Signer display name (used for PDF /Name entry). */
  name?: string | null;
  /** Path to a PNG/JPEG signature image. */
  imagePath?: string | null;
  /** Ordered display strings for the signature appearance. */
  fields?: string[] | null;
  /** If false, create an invisible signature (no visual appearance). */
  visible?: boolean;
  /** Font registry key (e.g. "noto-sans", "ghea-grapalat"). */
  font?: string | null;
}

export interface PrepareResult {
  pdf: Uint8Array;
  hexStart: number;
  hexLen: number;
}

/**
 * Prepare a PDF with an empty signature field for hash-then-sign.
 *
 * Uses a TRUE incremental update: the original PDF bytes are preserved
 * exactly, and new objects are appended after the original %%EOF.
 */
export async function preparePdfWithSigField(
  pdfBytes: Uint8Array,
  options: PrepareOptions = {},
): Promise<PrepareResult> {
  const {
    page = 0,
    x = null,
    y = null,
    width = SIG_WIDTH,
    height = SIG_HEIGHT,
    position = "bottom-right",
    reason = "",
    name = null,
    imagePath = null,
    fields = null,
    visible = true,
    font = null,
  } = options;

  // Read-only analysis of the original PDF
  const rootInfo = findRootObjNum(pdfBytes);
  const pageInfo = await findPageObjNum(pdfBytes, page);
  const prevInfo = await findPrevStartxref(pdfBytes);

  let rawObjects: Array<{ raw: Uint8Array; objNum: number }>;
  let newSize: number;

  if (visible) {
    const result = await prepareVisible({
      pdfBytes,
      prevSize: prevInfo.maxSize,
      rootObjNum: rootInfo.objNum,
      pageObjNum: pageInfo.pageObjNum,
      existingAnnots: pageInfo.existingAnnots,
      pageW: pageInfo.pageWidth,
      pageH: pageInfo.pageHeight,
      xPos: x,
      yPos: y,
      width,
      height,
      position,
      reason,
      name,
      imagePath,
      displayFields: fields,
      fontKey: font,
    });
    rawObjects = result.rawObjects;
    newSize = result.newSize;
  } else {
    const result = await prepareInvisible(
      pdfBytes,
      prevInfo.maxSize,
      rootInfo.objNum,
      pageInfo.pageObjNum,
      pageInfo.existingAnnots,
      reason,
      name,
    );
    rawObjects = result.rawObjects;
    newSize = result.newSize;
  }

  // Assemble incremental update
  const fullPdf = assembleIncrementalUpdate(
    pdfBytes,
    rawObjects,
    newSize,
    prevInfo.prevXref,
    rootInfo.objNum,
    rootInfo.genNum,
    prevInfo.trailerExtra,
    prevInfo.useXrefStream,
  );

  // Patch the ByteRange and return offsets
  return patchByterange(fullPdf, pdfBytes.length);
}

/**
 * Compute SHA-1 hash of the ByteRange (everything except the Contents hex).
 */
export function computeByterangeHash(
  pdfBytes: Uint8Array,
  hexStart: number,
  hexLen: number,
): Uint8Array {
  const end = hexStart + hexLen;
  if (hexStart <= 0 || end + 1 > pdfBytes.length) {
    throw new PDFError(
      `Invalid hex range: start=${hexStart}, len=${hexLen}, pdf_size=${pdfBytes.length}`,
    );
  }
  if (pdfBytes[hexStart - 1] !== 0x3c) {
    throw new PDFError("Malformed Contents field: expected '<' before hex data");
  }
  if (pdfBytes[end] !== 0x3e) {
    throw new PDFError("Malformed Contents field: expected '>' after hex data");
  }

  const before = pdfBytes.slice(0, hexStart);
  const after = pdfBytes.slice(end + 1);
  const hash = createHash("sha1");
  hash.update(before);
  hash.update(after);
  return new Uint8Array(hash.digest());
}

/**
 * Insert the CMS DER bytes as a hex string into the reserved Contents.
 */
export function insertCms(
  pdfBytes: Uint8Array,
  hexStart: number,
  hexLen: number,
  cmsDer: Uint8Array,
): Uint8Array {
  const cmsHex = bytesToHex(cmsDer);
  if (cmsHex.length > hexLen) {
    throw new PDFError(`CMS too large: ${cmsHex.length} hex chars > ${hexLen} reserved`);
  }
  const cmsHexPadded = cmsHex + "0".repeat(hexLen - cmsHex.length);

  const result = new Uint8Array(pdfBytes);
  const hexBytes = new TextEncoder().encode(cmsHexPadded);
  result.set(hexBytes, hexStart);
  return result;
}

// -- Visible signature --------------------------------------------------------

interface VisibleSigParams {
  pdfBytes: Uint8Array;
  prevSize: number;
  rootObjNum: number;
  pageObjNum: number;
  existingAnnots: string[];
  pageW: number;
  pageH: number;
  xPos: number | null;
  yPos: number | null;
  width: number;
  height: number;
  position: string;
  reason: string;
  name: string | null;
  imagePath: string | null;
  displayFields: string[] | null;
  fontKey: string | null;
}

async function prepareVisible(
  params: VisibleSigParams,
): Promise<{ rawObjects: Array<{ raw: Uint8Array; objNum: number }>; newSize: number }> {
  const fontObj = await getFont(params.fontKey);

  // Resolve signature position
  let x = params.xPos;
  let y = params.yPos;
  let w = params.width;
  let h = params.height;
  if (x === null || y === null) {
    const rect = computeSigRect(params.pageW, params.pageH, params.position, w, h);
    x = rect.x;
    y = rect.y;
    w = rect.width;
    h = rect.height;
  }

  // Load signature image (need dimensions for aspect-ratio-correct layout)
  let imgData: SignatureImageData | null = null;
  let imageAspect: number | null = null;
  if (params.imagePath !== null) {
    imgData = await loadSignatureImage(params.imagePath);
    if (imgData.height > 0) {
      imageAspect = imgData.width / imgData.height;
    }
  }

  // Build appearance stream
  const fields = params.displayFields ?? [
    params.name ?? "Digital Signature",
    `Date: ${makeDateStr()}`,
  ];
  const apInfo = await buildAppearanceStream(
    w,
    h,
    fields,
    params.imagePath !== null,
    fontObj,
    imageAspect,
  );

  // Allocate new object numbers
  const hasImage = imgData !== null;
  const hasSmask = imgData !== null && imgData.smask !== null;
  const objNums = allocateSigObjects(params.prevSize, hasImage, hasSmask, true);

  const rawObjects = await buildAllObjects(
    params.pdfBytes,
    objNums,
    params.rootObjNum,
    params.pageObjNum,
    params.existingAnnots,
    x,
    y,
    w,
    h,
    params.reason,
    params.name,
    apInfo,
    imgData,
    fontObj.metrics,
  );

  return { rawObjects, newSize: objNums.newSize };
}

// -- Invisible signature ------------------------------------------------------

async function prepareInvisible(
  pdfBytes: Uint8Array,
  prevSize: number,
  rootObjNum: number,
  pageObjNum: number,
  existingAnnots: string[],
  reason: string,
  name: string | null,
): Promise<{ rawObjects: Array<{ raw: Uint8Array; objNum: number }>; newSize: number }> {
  const objNums = allocateSigObjects(prevSize, false, false, false);

  const sigDictRaw = buildSigDict(objNums.sig, reason, name);
  const annotRaw = buildInvisibleAnnotWidget(objNums, pageObjNum);

  let annotsList = existingAnnots.length > 0 ? existingAnnots.join(" ") : "";
  if (annotsList) annotsList += " ";
  annotsList += `${objNums.annot} 0 R`;

  const pageOverride = await buildPageOverride(pdfBytes, pageObjNum, annotsList);
  const catalogOverride = await buildCatalogOverride(pdfBytes, rootObjNum, objNums.annot);

  const rawObjects: Array<{ raw: Uint8Array; objNum: number }> = [
    { raw: toBytes(sigDictRaw), objNum: objNums.sig },
    { raw: toBytes(annotRaw), objNum: objNums.annot },
    { raw: toBytes(pageOverride), objNum: pageObjNum },
    { raw: toBytes(catalogOverride), objNum: rootObjNum },
  ];

  return { rawObjects, newSize: objNums.newSize };
}

// -- Object assembly ----------------------------------------------------------

async function buildAllObjects(
  pdfBytes: Uint8Array,
  objNums: SigObjectNums,
  rootObjNum: number,
  pageObjNum: number,
  existingAnnots: string[],
  x: number,
  y: number,
  w: number,
  h: number,
  reason: string,
  name: string | null,
  apInfo: AppearanceData,
  imgData: SignatureImageData | null,
  fontMetrics: FontMetrics,
): Promise<Array<{ raw: Uint8Array; objNum: number }>> {
  const sigDictRaw = buildSigDict(objNums.sig, reason, name);
  const fontObjects = buildEmbeddedFontObjects(objNums, fontMetrics);
  const xobjects = buildFormXobjects(objNums, w, h, apInfo, imgData);
  const annotRaw = buildAnnotWidget(objNums, pageObjNum, x, y, w, h);

  let annotsList = existingAnnots.length > 0 ? existingAnnots.join(" ") : "";
  if (annotsList) annotsList += " ";
  annotsList += `${objNums.annot} 0 R`;

  const pageOverride = await buildPageOverride(pdfBytes, pageObjNum, annotsList);
  const catalogOverride = await buildCatalogOverride(pdfBytes, rootObjNum, objNums.annot);

  return collectObjects(
    sigDictRaw,
    annotRaw,
    fontObjects,
    xobjects,
    pageOverride,
    catalogOverride,
    objNums,
    pageObjNum,
    rootObjNum,
  );
}

function collectObjects(
  sigDictRaw: string,
  annotRaw: string,
  fontObjects: Array<{ raw: Uint8Array; objNum: number }>,
  xobjects: FormXobjects,
  pageOverride: string,
  catalogOverride: string,
  objNums: SigObjectNums,
  pageObjNum: number,
  rootObjNum: number,
): Array<{ raw: Uint8Array; objNum: number }> {
  if (objNums.n0 === null || objNums.n2 === null || objNums.frm === null || objNums.ap === null) {
    throw new PDFError("Visible signature requires n0/n2/frm/ap object numbers");
  }

  const result: Array<{ raw: Uint8Array; objNum: number }> = [];
  result.push({ raw: toBytes(sigDictRaw), objNum: objNums.sig });
  result.push({ raw: toBytes(annotRaw), objNum: objNums.annot });
  result.push(...fontObjects);
  result.push({ raw: xobjects.n0, objNum: objNums.n0 });
  result.push({ raw: xobjects.n2, objNum: objNums.n2 });
  result.push({ raw: xobjects.frm, objNum: objNums.frm });
  result.push({ raw: xobjects.ap, objNum: objNums.ap });

  if (xobjects.img.length > 0 && objNums.img !== null) {
    result.push({ raw: xobjects.img, objNum: objNums.img });
  }
  if (xobjects.smask.length > 0 && objNums.smask !== null) {
    result.push({ raw: xobjects.smask, objNum: objNums.smask });
  }

  result.push({ raw: toBytes(pageOverride), objNum: pageObjNum });
  result.push({ raw: toBytes(catalogOverride), objNum: rootObjNum });

  return result;
}
