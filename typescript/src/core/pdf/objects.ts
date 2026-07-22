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

import type { PDFContext, PDFObject } from "pdf-lib";
import { PDFArray, PDFDict, PDFDocument, PDFNumber, PDFRef } from "pdf-lib";

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

/**
 * AcroForm /SigFlags bits to set when adding a signature field:
 * SignaturesExist (1) | AppendOnly (2).
 */
const SIG_FLAGS_SIGNED_APPEND = 3;

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
 * Build a raw catalog override that installs the signature field into the
 * document's AcroForm, merging with any AcroForm the document already has
 * instead of replacing it.
 *
 * A signing tool must not destroy an existing form. Overwriting /AcroForm
 * wholesale orphans every existing field -- and, when the input is already
 * signed (e.g. a server-pre-signed agreement), the prior signature's field --
 * so a reader reports the earlier form/signature as removed. This preserves
 * the existing /Fields (appending the new one), keeps ancillary keys
 * (/DR, /DA, /NeedAppearances, /CO, ...), and ORs the signatures-exist /
 * append-only bits into /SigFlags.
 *
 * With no existing AcroForm it emits the minimal
 * `<< /Fields [N 0 R] /SigFlags 3 >>`, matching the fresh-form case.
 */
export async function buildCatalogOverride(
  pdfBytes: Uint8Array,
  rootObjNum: number,
  annotObjNum: number,
): Promise<string> {
  const pdfDoc = await PDFDocument.load(pdfBytes, {
    updateMetadata: false,
  });
  const context = pdfDoc.context;
  const ref = PDFRef.of(rootObjNum, 0);
  const catalog = context.lookup(ref);

  if (!(catalog instanceof PDFDict)) {
    throw new PDFError(
      `Object ${rootObjNum} is not a dictionary (got ${catalog?.constructor.name ?? "null"})`,
    );
  }

  const entries: string[] = [];
  let existingAcroform: PDFObject | undefined;
  for (const [key, value] of catalog.entries()) {
    if (key.toString() === "/AcroForm") {
      existingAcroform = value;
      continue;
    }
    entries.push(`  ${key.toString()} ${serializePdfObject(value)}`);
  }

  const acroformBody = buildMergedAcroformBody(context, existingAcroform, annotObjNum);
  entries.push(`  /AcroForm << ${acroformBody} >>`);

  const body = entries.join("\n");
  return `${rootObjNum} 0 obj\n<<\n${body}\n>>\nendobj\n`;
}

/**
 * Build the body (between << and >>) of the merged AcroForm dictionary.
 *
 * `existing` is the catalog's current /AcroForm value, if any -- an inline
 * dict or an indirect reference, both resolved via context.lookup().
 */
function buildMergedAcroformBody(
  context: PDFContext,
  existing: PDFObject | undefined,
  annotObjNum: number,
): string {
  const existingDict = existing === undefined ? undefined : context.lookup(existing);

  const parts: string[] = [];
  let wroteFields = false;
  let wroteSigFlags = false;
  if (existingDict instanceof PDFDict) {
    for (const [key, value] of existingDict.entries()) {
      const keyName = key.toString();
      if (keyName === "/Fields") {
        parts.push(buildMergedFieldsEntry(context, value, annotObjNum));
        wroteFields = true;
      } else if (keyName === "/SigFlags") {
        // A malformed (non-numeric) /SigFlags is treated as 0, matching the
        // Rust core: the bits we require are set either way.
        const resolved = context.lookup(value);
        const existingFlags = resolved instanceof PDFNumber ? resolved.asNumber() : 0;
        parts.push(`/SigFlags ${existingFlags | SIG_FLAGS_SIGNED_APPEND}`);
        wroteSigFlags = true;
      } else {
        parts.push(`${keyName} ${serializePdfObject(value)}`);
      }
    }
  }
  if (!wroteFields) {
    parts.push(`/Fields [${annotObjNum} 0 R]`);
  }
  if (!wroteSigFlags) {
    parts.push(`/SigFlags ${SIG_FLAGS_SIGNED_APPEND}`);
  }
  return parts.join(" ");
}

/**
 * Build `/Fields [ <existing...> <new> 0 R ]`, preserving the existing field
 * references. Those objects live in the original bytes, untouched by the
 * incremental update, so referencing them by number stays valid.
 */
function buildMergedFieldsEntry(
  context: PDFContext,
  fieldsValue: PDFObject,
  annotObjNum: number,
): string {
  const resolved = context.lookup(fieldsValue);
  const refs: string[] = [];
  if (resolved instanceof PDFArray) {
    for (const elem of resolved.asArray()) {
      refs.push(serializePdfObject(elem));
    }
  }
  refs.push(`${annotObjNum} 0 R`);
  return `/Fields [${refs.join(" ")}]`;
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
