// SPDX-License-Identifier: Apache-2.0
/**
 * Low-level PDF object construction for signature fields.
 *
 * Builds the individual PDF objects that form a signature's visual
 * appearance: signature dictionary, embedded font chain, nested form
 * XObjects (CoSign-compatible), annotation widget, and images.
 *
 * These helpers are called by builder.ts's orchestration layer.
 */

import { readFileSync } from "node:fs";
import { deflateSync } from "node:zlib";

import { VERSION } from "../../constants.js";
import { PDFError } from "../../errors.js";
import type { FontMetrics } from "../appearance/fonts.js";
import type { SignatureImageData } from "../appearance/image.js";
import type { AppearanceData } from "../appearance/stream.js";
import {
  ANNOT_FLAGS_SIG_WIDGET,
  BYTERANGE_PLACEHOLDER,
  CMS_HEX_SIZE,
  pdfString,
  type SigObjectNums,
} from "./objects.js";

// -- Signature dictionary -----------------------------------------------------

export function buildSigDict(objNum: number, reason: string, name: string | null): string {
  const now = new Date();
  const pad2 = (n: number): string => n.toString().padStart(2, "0");
  const pdfDate =
    `D:${now.getUTCFullYear()}${pad2(now.getUTCMonth() + 1)}` +
    `${pad2(now.getUTCDate())}${pad2(now.getUTCHours())}` +
    `${pad2(now.getUTCMinutes())}${pad2(now.getUTCSeconds())}+00'00'`;

  const contentsZeros = "0".repeat(CMS_HEX_SIZE);
  const nameEntry = name ? `  /Name (${pdfString(name)})\n` : "";
  const propBuild =
    `  /Prop_Build << /App << /Name /Revenant /REx (${VERSION}) >> ` +
    `/Filter << /Name /Adobe.PPKLite >> >>\n`;

  return (
    `${objNum} 0 obj\n` +
    `<<\n` +
    `  /Type /Sig\n` +
    `  /Filter /Adobe.PPKLite\n` +
    `  /SubFilter /adbe.pkcs7.detached\n` +
    `  ${BYTERANGE_PLACEHOLDER}\n` +
    `  /Contents <${contentsZeros}>\n` +
    `  /M (${pdfDate})\n` +
    `  /Reason (${pdfString(reason)})\n` +
    nameEntry +
    propBuild +
    `>>\n` +
    `endobj\n`
  );
}

// -- Embedded font objects ----------------------------------------------------

/** PDF Reference Table 123: Font flags. Bit 6 (value 32) = Nonsymbolic. */
const FONT_FLAGS_NONSYMBOLIC = 32;

export function buildEmbeddedFontObjects(
  objNums: SigObjectNums,
  metrics: FontMetrics,
): Array<{ raw: Uint8Array; objNum: number }> {
  const fontNum = objNums.font;
  const cidfontNum = objNums.cidfont;
  const fontDescNum = objNums.fontDesc;
  const fontFileNum = objNums.fontFile;
  const tounicodeNum = objNums.tounicode;

  if (fontNum === null || cidfontNum === null) {
    throw new PDFError("Font object allocation failed: missing font/cidfont numbers");
  }
  if (fontDescNum === null || fontFileNum === null || tounicodeNum === null) {
    throw new PDFError("Font object allocation failed: missing descriptor/file/tounicode numbers");
  }

  const base = metrics.name;
  const bbox = metrics.bbox;
  const enc = new TextEncoder();
  const result: Array<{ raw: Uint8Array; objNum: number }> = [];

  // 1. Type0 font dict
  const type0Str =
    `${fontNum} 0 obj\n` +
    `<< /Type /Font /Subtype /Type0\n` +
    `   /BaseFont /${base}\n` +
    `   /Encoding /Identity-H\n` +
    `   /DescendantFonts [${cidfontNum} 0 R]\n` +
    `   /ToUnicode ${tounicodeNum} 0 R\n` +
    `>>\nendobj\n`;
  result.push({ raw: enc.encode(type0Str), objNum: fontNum });

  // 2. CIDFontType2 dict
  const cidfontStr =
    `${cidfontNum} 0 obj\n` +
    `<< /Type /Font /Subtype /CIDFontType2\n` +
    `   /BaseFont /${base}\n` +
    `   /CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >>\n` +
    `   /DW ${metrics.defaultWidth}\n` +
    `   /W ${metrics.cidWidthsStr}\n` +
    `   /FontDescriptor ${fontDescNum} 0 R\n` +
    `>>\nendobj\n`;
  result.push({ raw: enc.encode(cidfontStr), objNum: cidfontNum });

  // 3. FontDescriptor
  const fontDescStr =
    `${fontDescNum} 0 obj\n` +
    `<< /Type /FontDescriptor\n` +
    `   /FontName /${base}\n` +
    `   /Flags ${FONT_FLAGS_NONSYMBOLIC}\n` +
    `   /FontBBox [${bbox[0]} ${bbox[1]} ${bbox[2]} ${bbox[3]}]\n` +
    `   /ItalicAngle ${metrics.italicAngle}\n` +
    `   /Ascent ${metrics.ascent}\n` +
    `   /Descent ${metrics.descent}\n` +
    `   /CapHeight ${metrics.capHeight}\n` +
    `   /StemV ${metrics.stemV}\n` +
    `   /FontFile2 ${fontFileNum} 0 R\n` +
    `>>\nendobj\n`;
  result.push({ raw: enc.encode(fontDescStr), objNum: fontDescNum });

  // 4. FontFile2 stream (zlib-compressed TTF)
  const ttfBytes = readFileSync(metrics.ttfPath);
  const compressedTtf = deflateSync(ttfBytes);
  const ffHeader = enc.encode(
    `${fontFileNum} 0 obj\n` +
      `<< /Length ${compressedTtf.length} /Length1 ${ttfBytes.length}` +
      ` /Filter /FlateDecode >>\n` +
      `stream\n`,
  );
  const ffFooter = enc.encode("\nendstream\nendobj\n");
  result.push({
    raw: concatBytes([ffHeader, compressedTtf, ffFooter]),
    objNum: fontFileNum,
  });

  // 5. ToUnicode CMap stream
  const cmapBytes = enc.encode(metrics.tounicodeCmap);
  const tuHeader = enc.encode(`${tounicodeNum} 0 obj\n<< /Length ${cmapBytes.length} >>\nstream\n`);
  const tuFooter = enc.encode("\nendstream\nendobj\n");
  result.push({
    raw: concatBytes([tuHeader, cmapBytes, tuFooter]),
    objNum: tounicodeNum,
  });

  return result;
}

// -- Form XObjects ------------------------------------------------------------

export interface FormXobjects {
  n0: Uint8Array;
  n2: Uint8Array;
  frm: Uint8Array;
  ap: Uint8Array;
  img: Uint8Array;
  smask: Uint8Array;
}

export function buildFormXobjects(
  objNums: SigObjectNums,
  w: number,
  h: number,
  apInfo: AppearanceData,
  imgData: SignatureImageData | null,
): FormXobjects {
  const fontNum = objNums.font;
  const apNum = objNums.ap;
  const frmNum = objNums.frm;
  const n0Num = objNums.n0;
  const n2Num = objNums.n2;
  const imgNum = objNums.img;
  const smaskNum = objNums.smask;

  if (fontNum === null || apNum === null || frmNum === null) {
    throw new PDFError("Form XObject allocation failed: missing font/ap/frm numbers");
  }
  if (n0Num === null || n2Num === null) {
    throw new PDFError("Form XObject allocation failed: missing n0/n2 numbers");
  }

  const enc = new TextEncoder();
  const endStream = enc.encode("\nendstream\nendobj\n");

  // /n0 -- empty placeholder form (required by PDF signature spec)
  const n0Stream = enc.encode("% DSBlank");
  const n0Header = enc.encode(
    `${n0Num} 0 obj\n` +
      `<< /Type /XObject /Subtype /Form /FormType 1\n` +
      `   /BBox [0 0 100 100]\n` +
      `   /Length ${n0Stream.length}\n` +
      `>>\nstream\n`,
  );
  const n0Raw = concatBytes([n0Header, n0Stream, endStream]);

  // /n2 -- actual visible content (border, divider, text, image)
  const n2StreamBytes = apInfo.stream;
  let n2XobjectEntry = "";
  if (imgData !== null) {
    n2XobjectEntry = ` /XObject << /Img1 ${imgNum} 0 R >>`;
  }
  let n2ExtgstateEntry = "";
  if (apInfo.bgOpacity > 0) {
    n2ExtgstateEntry = ` /ExtGState << /GS1 << /ca ${apInfo.bgOpacity.toFixed(2)} >> >>`;
  }
  const n2Header = enc.encode(
    `${n2Num} 0 obj\n` +
      `<< /Type /XObject /Subtype /Form /FormType 1\n` +
      `   /BBox [0.00 0.00 ${w.toFixed(2)} ${h.toFixed(2)}]\n` +
      `   /Resources << /Font << /F1 ${fontNum} 0 R >>${n2XobjectEntry}${n2ExtgstateEntry} >>\n` +
      `   /Length ${n2StreamBytes.length}\n` +
      `>>\nstream\n`,
  );
  const n2Raw = concatBytes([n2Header, n2StreamBytes, endStream]);

  // /FRM -- intermediate form, delegates to /n0 and /n2
  const frmStream = enc.encode("q 1 0 0 1 0 0 cm /n0 Do Q q 1 0 0 1 0 0 cm /n2 Do Q");
  const frmHeader = enc.encode(
    `${frmNum} 0 obj\n` +
      `<< /Type /XObject /Subtype /Form /FormType 1\n` +
      `   /BBox [0.00 0.00 ${w.toFixed(2)} ${h.toFixed(2)}]\n` +
      `   /Resources << /XObject << /n0 ${n0Num} 0 R /n2 ${n2Num} 0 R >> >>\n` +
      `   /Length ${frmStream.length}\n` +
      `>>\nstream\n`,
  );
  const frmRaw = concatBytes([frmHeader, frmStream, endStream]);

  // AP/N -- top-level appearance form (just delegates to /FRM)
  const apStream = enc.encode("/FRM Do");
  const apHeader = enc.encode(
    `${apNum} 0 obj\n` +
      `<< /Type /XObject /Subtype /Form /FormType 1\n` +
      `   /BBox [0.00 0.00 ${w.toFixed(2)} ${h.toFixed(2)}]\n` +
      `   /Resources << /XObject << /FRM ${frmNum} 0 R >> >>\n` +
      `   /Length ${apStream.length}\n` +
      `>>\nstream\n`,
  );
  const apRaw = concatBytes([apHeader, apStream, endStream]);

  // Image objects (if needed)
  let imgRaw: Uint8Array = new Uint8Array(0);
  let smaskRaw: Uint8Array = new Uint8Array(0);
  if (imgData !== null && imgNum !== null) {
    imgRaw = buildImageObject(imgNum, imgData, smaskNum);
    if (smaskNum !== null && imgData.smask !== null) {
      smaskRaw = buildSmaskObject(
        smaskNum,
        imgData.smask,
        imgData.width,
        imgData.height,
        imgData.bpc,
      );
    }
  }

  return { n0: n0Raw, n2: n2Raw, frm: frmRaw, ap: apRaw, img: imgRaw, smask: smaskRaw };
}

// -- Annotation widgets -------------------------------------------------------

export function buildAnnotWidget(
  objNums: SigObjectNums,
  pageObjNum: number,
  x: number,
  y: number,
  w: number,
  h: number,
): string {
  return (
    `${objNums.annot} 0 obj\n` +
    `<<\n` +
    `  /Type /Annot\n` +
    `  /Subtype /Widget\n` +
    `  /FT /Sig\n` +
    `  /Rect [${x.toFixed(2)} ${y.toFixed(2)} ${(x + w).toFixed(2)} ${(y + h).toFixed(2)}]\n` +
    `  /V ${objNums.sig} 0 R\n` +
    `  /T (Signature_${objNums.annot})\n` +
    `  /F ${ANNOT_FLAGS_SIG_WIDGET}\n` +
    `  /P ${pageObjNum} 0 R\n` +
    `  /AP << /N ${objNums.ap} 0 R >>\n` +
    `  /Border [0 0 0]\n` +
    `>>\n` +
    `endobj\n`
  );
}

export function buildInvisibleAnnotWidget(objNums: SigObjectNums, pageObjNum: number): string {
  return (
    `${objNums.annot} 0 obj\n` +
    `<<\n` +
    `  /Type /Annot\n` +
    `  /Subtype /Widget\n` +
    `  /FT /Sig\n` +
    `  /Rect [0 0 0 0]\n` +
    `  /V ${objNums.sig} 0 R\n` +
    `  /T (Signature_${objNums.annot})\n` +
    `  /F ${ANNOT_FLAGS_SIG_WIDGET}\n` +
    `  /P ${pageObjNum} 0 R\n` +
    `  /Border [0 0 0]\n` +
    `>>\n` +
    `endobj\n`
  );
}

// -- Image helpers (private) --------------------------------------------------

function buildImageObject(
  imgObjNum: number,
  imgData: SignatureImageData,
  smaskObjNum: number | null,
): Uint8Array {
  const smaskRef = smaskObjNum !== null ? ` /SMask ${smaskObjNum} 0 R` : "";
  const enc = new TextEncoder();
  const header = enc.encode(
    `${imgObjNum} 0 obj\n` +
      `<< /Type /XObject /Subtype /Image\n` +
      `   /Width ${imgData.width} /Height ${imgData.height}\n` +
      `   /ColorSpace /DeviceRGB /BitsPerComponent ${imgData.bpc}\n` +
      `   /Filter /FlateDecode${smaskRef}\n` +
      `   /Length ${imgData.samples.length}\n` +
      `>>\n` +
      `stream\n`,
  );
  return concatBytes([header, imgData.samples, enc.encode("\nendstream\nendobj\n")]);
}

function buildSmaskObject(
  smaskObjNum: number,
  smaskData: Uint8Array,
  width: number,
  height: number,
  bpc: number,
): Uint8Array {
  const enc = new TextEncoder();
  const header = enc.encode(
    `${smaskObjNum} 0 obj\n` +
      `<< /Type /XObject /Subtype /Image\n` +
      `   /Width ${width} /Height ${height}\n` +
      `   /ColorSpace /DeviceGray /BitsPerComponent ${bpc}\n` +
      `   /Filter /FlateDecode\n` +
      `   /Length ${smaskData.length}\n` +
      `>>\n` +
      `stream\n`,
  );
  return concatBytes([header, smaskData, enc.encode("\nendstream\nendobj\n")]);
}

// -- Helpers ------------------------------------------------------------------

function concatBytes(chunks: Uint8Array[]): Uint8Array {
  let totalLen = 0;
  for (const chunk of chunks) totalLen += chunk.length;
  const result = new Uint8Array(totalLen);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.length;
  }
  return result;
}
