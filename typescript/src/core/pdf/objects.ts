// SPDX-License-Identifier: Apache-2.0
/**
 * Low-level PDF object construction.
 *
 * Types, constants, and helpers for building PDF objects used in
 * signature incremental updates: signature dictionaries, annotation
 * widgets, font objects, appearance streams.
 *
 * PDF structure analysis and incremental update assembly is in incremental.ts.
 * High-level signing API is in builder.ts.
 * Position/geometry helpers are in position.ts.
 */

import { PDFDict, PDFDocument, PDFRef } from "pdf-lib";

import { PDFError } from "../../errors.js";
import { logger } from "../../logger.js";

export interface SigObjectNums {
  /**
   * When visible=false (invisible signature), only sig and annot
   * are allocated; all appearance-related keys are null.
   */
  sig: number;
  annot: number;
  font: number | null;
  cidfont: number | null;
  fontDesc: number | null;
  fontFile: number | null;
  tounicode: number | null;
  ap: number | null;
  frm: number | null;
  n0: number | null;
  n2: number | null;
  img: number | null;
  smask: number | null;
  newSize: number;
}

// -- Constants ----------------------------------------------------------------

/** Reserve 8192 bytes for CMS (CoSign CMS is ~1867 bytes, plenty of room). */
export const CMS_RESERVED_SIZE = 8192;
export const CMS_HEX_SIZE = CMS_RESERVED_SIZE * 2;

export const BYTERANGE_PLACEHOLDER = "/ByteRange [         0          0          0          0]";
export const BYTERANGE_PLACEHOLDER_BYTES = new TextEncoder().encode(BYTERANGE_PLACEHOLDER);

/**
 * PDF annotation flags for signature widget (/F entry).
 * Print=4, Locked=128; combined=132.
 */
const ANNOT_FLAG_PRINT = 4;
const ANNOT_FLAG_LOCKED = 128;
export const ANNOT_FLAGS_SIG_WIDGET = ANNOT_FLAG_PRINT | ANNOT_FLAG_LOCKED;

// -- PDF string/object helpers ------------------------------------------------

/**
 * Escape text for a PDF literal string.
 *
 * Handles backslash, parentheses, control characters, and non-Latin1
 * characters (replaced with '?' since PDFDocEncoding has limited
 * Unicode support).
 */
export function pdfString(text: string): string {
  const result: string[] = [];
  let replacedCount = 0;

  for (const char of text) {
    const code = char.codePointAt(0) ?? 0;
    if (char === "\\") {
      result.push("\\\\");
    } else if (char === "(") {
      result.push("\\(");
    } else if (char === ")") {
      result.push("\\)");
    } else if (char === "\n") {
      result.push("\\n");
    } else if (char === "\r") {
      result.push("\\r");
    } else if (char === "\t") {
      result.push("\\t");
    } else if (code < 0x20 || code === 0x7f) {
      result.push(`\\${code.toString(8).padStart(3, "0")}`);
    } else if (code > 0xff) {
      result.push("?");
      replacedCount += 1;
    } else {
      result.push(char);
    }
  }

  if (replacedCount > 0) {
    logger.warn(
      `pdfString: ${replacedCount} non-Latin1 character(s) replaced with '?' in: ${text}`,
    );
  }

  return result.join("");
}

/**
 * Serialize a pdf-lib object to a raw PDF string for embedding.
 */
export function serializePdfObject(obj: { toString(): string } | null | undefined): string {
  if (obj === null || obj === undefined) return "null";
  if (obj instanceof PDFRef) {
    return `${obj.objectNumber} ${obj.generationNumber} R`;
  }
  // pdf-lib objects have a toString() that gives the PDF syntax
  return obj.toString();
}

// -- Object override builders -------------------------------------------------

/**
 * Build a raw override of a PDF object with a new/replaced entry.
 *
 * Opens the PDF, extracts all entries from the target object (skipping
 * skipKey), appends newEntry, and returns the raw PDF object string.
 */
export async function buildObjectOverride(
  pdfBytes: Uint8Array,
  objNum: number,
  skipKey: string,
  newEntry: string,
): Promise<string> {
  const pdfDoc = await PDFDocument.load(pdfBytes, {
    updateMetadata: false,
  });
  const context = pdfDoc.context;
  const ref = PDFRef.of(objNum, 0);
  const obj = context.lookup(ref);

  if (!(obj instanceof PDFDict)) {
    throw new PDFError(
      `Object ${objNum} is not a dictionary (got ${obj?.constructor.name ?? "null"})`,
    );
  }

  const entries: string[] = [];
  const dictEntries = obj.entries();
  for (const [key, value] of dictEntries) {
    if (key.toString() === skipKey) continue;
    entries.push(`  ${key.toString()} ${serializePdfObject(value)}`);
  }

  entries.push(newEntry);
  const body = entries.join("\n");
  return `${objNum} 0 obj\n<<\n${body}\n>>\nendobj\n`;
}

/**
 * Build a raw override of the page object that adds /Annots.
 */
export async function buildPageOverride(
  pdfBytes: Uint8Array,
  pageObjNum: number,
  annotsList: string,
): Promise<string> {
  return buildObjectOverride(pdfBytes, pageObjNum, "/Annots", `  /Annots [${annotsList}]`);
}

/**
 * Build a raw override of the catalog that adds /AcroForm.
 */
export async function buildCatalogOverride(
  pdfBytes: Uint8Array,
  rootObjNum: number,
  annotObjNum: number,
): Promise<string> {
  return buildObjectOverride(
    pdfBytes,
    rootObjNum,
    "/AcroForm",
    `  /AcroForm << /Fields [${annotObjNum} 0 R] /SigFlags 3 >>`,
  );
}

// -- Object number allocation -------------------------------------------------

/**
 * Allocate object numbers for all new PDF objects.
 *
 * When visible=true (default), allocates the full CoSign-compatible
 * nested form structure (AP/N, /FRM, /n0, /n2).
 *
 * When visible=false, only sig dict and annotation are allocated.
 */
export function allocateSigObjects(
  prevSize: number,
  hasImage: boolean,
  hasSmask: boolean,
  visible: boolean = true,
): SigObjectNums {
  let nextObj = prevSize;

  const sigObjNum = nextObj++;
  const annotObjNum = nextObj++;

  if (!visible) {
    return {
      sig: sigObjNum,
      annot: annotObjNum,
      font: null,
      cidfont: null,
      fontDesc: null,
      fontFile: null,
      tounicode: null,
      ap: null,
      frm: null,
      n0: null,
      n2: null,
      img: null,
      smask: null,
      newSize: nextObj,
    };
  }

  const fontObjNum = nextObj++;
  const cidfontObjNum = nextObj++;
  const fontDescObjNum = nextObj++;
  const fontFileObjNum = nextObj++;
  const tounicodeObjNum = nextObj++;
  const apObjNum = nextObj++;
  const frmObjNum = nextObj++;
  const n0ObjNum = nextObj++;
  const n2ObjNum = nextObj++;

  let imgObjNum: number | null = null;
  let smaskObjNum: number | null = null;
  if (hasImage) {
    imgObjNum = nextObj++;
    if (hasSmask) {
      smaskObjNum = nextObj++;
    }
  }

  return {
    sig: sigObjNum,
    annot: annotObjNum,
    font: fontObjNum,
    cidfont: cidfontObjNum,
    fontDesc: fontDescObjNum,
    fontFile: fontFileObjNum,
    tounicode: tounicodeObjNum,
    ap: apObjNum,
    frm: frmObjNum,
    n0: n0ObjNum,
    n2: n2ObjNum,
    img: imgObjNum,
    smask: smaskObjNum,
    newSize: nextObj,
  };
}
