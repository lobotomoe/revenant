// SPDX-License-Identifier: Apache-2.0
/**
 * Signature field positioning and page geometry helpers.
 *
 * Computes where to place the signature rectangle on a PDF page,
 * given a preset name ("bottom-right", "br", etc.) or explicit coordinates.
 */

import type { PDFDocument } from "pdf-lib";

import { PDFError } from "../../errors.js";

// -- Signature position presets -----------------------------------------------

/** Default signature field size in PDF points (3:1 aspect ratio, ~75x25 mm). */
export const SIG_WIDTH = 210;
export const SIG_HEIGHT = 70;
export const SIG_MARGIN_H = 36; // horizontal margin (~13 mm)
export const SIG_MARGIN_V = 60; // vertical margin (~21 mm)

const POSITION_ALIASES: ReadonlyMap<string, string> = new Map([
  ["br", "bottom-right"],
  ["tr", "top-right"],
  ["bl", "bottom-left"],
  ["tl", "top-left"],
  ["bc", "bottom-center"],
]);

const POSITION_PRESETS = new Set([
  "bottom-right",
  "top-right",
  "bottom-left",
  "top-left",
  "bottom-center",
]);

/**
 * Normalize a position name, resolving aliases.
 */
export function resolvePosition(positionName: string): string {
  let name = positionName.toLowerCase().trim();
  name = POSITION_ALIASES.get(name) ?? name;
  if (!POSITION_PRESETS.has(name)) {
    const validPresets = [...POSITION_PRESETS].sort();
    const validAliases = [...POSITION_ALIASES.keys()].sort();
    const valid = [...validPresets, ...validAliases].join(", ");
    throw new PDFError(`Unknown position '${positionName}'. Valid: ${valid}`);
  }
  return name;
}

/**
 * Convert user-facing page specifier to internal format.
 *
 * Accepts "first", "last" (returned as-is), or 1-based page numbers
 * (returned as 0-based integers).
 */
export function parsePageSpec(pageStr: string): string | number {
  const spec = pageStr.trim().toLowerCase();
  if (spec === "first" || spec === "last") {
    return spec;
  }
  const pageNum = parseInt(spec, 10);
  if (Number.isNaN(pageNum)) {
    throw new PDFError(`Invalid page: '${pageStr}'. Use 'first', 'last', or a page number.`);
  }
  if (pageNum < 1) {
    throw new PDFError(`Page number must be 1 or greater, got ${pageNum}`);
  }
  return pageNum - 1;
}

export interface SigRect {
  x: number;
  y: number;
  width: number;
  height: number;
}

/**
 * Compute signature field rectangle given page dimensions and a preset.
 *
 * Returns coordinates in PDF coordinate space (origin = bottom-left).
 */
export function computeSigRect(
  pageWidth: number,
  pageHeight: number,
  position: string = "bottom-right",
  sigW: number = SIG_WIDTH,
  sigH: number = SIG_HEIGHT,
  marginH: number = SIG_MARGIN_H,
  marginV: number = SIG_MARGIN_V,
): SigRect {
  if (pageWidth <= 0 || pageHeight <= 0) {
    throw new PDFError(
      `Invalid page dimensions: ${pageWidth.toFixed(1)} x ${pageHeight.toFixed(1)} pt`,
    );
  }
  if (sigW <= 0 || sigH <= 0) {
    throw new PDFError(`Invalid signature dimensions: ${sigW.toFixed(1)} x ${sigH.toFixed(1)} pt`);
  }

  const resolved = resolvePosition(position);
  let x: number;
  let y: number;

  if (resolved.includes("right")) {
    x = pageWidth - marginH - sigW;
  } else if (resolved.includes("left")) {
    x = marginH;
  } else {
    // center
    x = (pageWidth - sigW) / 2.0;
  }

  if (resolved.includes("bottom")) {
    y = marginV;
  } else {
    // top
    y = pageHeight - marginV - sigH;
  }

  if (x < 0 || y < 0) {
    throw new PDFError(
      `Signature does not fit on page: computed position (${x.toFixed(1)}, ${y.toFixed(1)}) is negative. ` +
        `Page: ${pageWidth.toFixed(0)}x${pageHeight.toFixed(0)} pt, ` +
        `signature: ${sigW.toFixed(0)}x${sigH.toFixed(0)} pt, ` +
        `margins: ${marginH.toFixed(0)}x${marginV.toFixed(0)} pt`,
    );
  }

  return { x, y, width: sigW, height: sigH };
}

/**
 * Get effective (width, height) for a page, respecting CropBox and Rotate.
 */
export function getPageDimensions(
  pdfDoc: PDFDocument,
  pageIndex: number,
): { width: number; height: number } {
  const page = pdfDoc.getPage(pageIndex);

  // CropBox takes priority over MediaBox for visible area
  const cropBox = page.getCropBox();
  const mediaBox = page.getMediaBox();
  const box = cropBox ?? mediaBox;

  let w = Math.abs(box.width);
  let h = Math.abs(box.height);

  // /Rotate is clockwise degrees; 90 and 270 swap width/height
  const rotation = page.getRotation().angle % 360;
  if (rotation === 90 || rotation === 270) {
    const tmp = w;
    w = h;
    h = tmp;
  }

  return { width: w, height: h };
}

/**
 * Convert a page specifier to a 0-based index.
 */
export function resolvePageIndex(pdfDoc: PDFDocument, pageSpec: number | string): number {
  const total = pdfDoc.getPageCount();

  if (typeof pageSpec === "string") {
    const spec = pageSpec.trim().toLowerCase();
    if (spec === "last") return total - 1;
    if (spec === "first") return 0;
    const parsed = parseInt(spec, 10);
    if (Number.isNaN(parsed)) {
      throw new PDFError(`Invalid page: '${pageSpec}'. Use 'first', 'last', or a 0-based number.`);
    }
    pageSpec = parsed;
  }

  if (pageSpec < 0 || pageSpec >= total) {
    throw new PDFError(`Page ${pageSpec} out of range (PDF has ${total} page(s), 0-based).`);
  }
  return pageSpec;
}
