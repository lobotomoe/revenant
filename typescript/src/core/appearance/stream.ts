// SPDX-License-Identifier: Apache-2.0
/**
 * Visual appearance stream for PDF signature fields.
 *
 * Generates the /AP /N content stream that Adobe Acrobat displays
 * inside the signature widget rectangle.
 */

import { logger } from "../../logger.js";
import type { Font } from "./fonts.js";
import { getDefaultFont, wrapLines } from "./fonts.js";

export interface AppearanceData {
  stream: Uint8Array;
  bbox: [number, number, number, number];
  resources: { fontName: string; baseFont: string };
  needsImage: boolean;
  bgOpacity: number;
}

// -- Layout constants ---------------------------------------------------------

const PAD_H = 8.0;
const PAD_V = 4.0;
const IMAGE_COLUMN_RATIO = 0.4;
const COLUMN_GAP = 4.0;
const NAME_MAX_FONT_SIZE = 14.0;
const NAME_MIN_FONT_SIZE = 5.0;
const NAME_FONT_STEP = 0.5;
const DETAIL_MAX_FONT_SIZE = 8.0;
const DETAIL_MIN_FONT_SIZE = 4.0;
const DETAIL_FONT_STEP = 0.5;
const DETAIL_HEIGHT_DIVISOR = 7.5;
const DETAIL_COLOR = 0.35;
const NAME_DETAIL_GAP_RATIO = 1.0;
const NAME_HEIGHT_DIVISOR = 3.0;
const TEXT_WIDTH_MARGIN = 4.0;
const LINE_LEADING = 1.4;
const BORDER_COLOR = 0.7;
const BORDER_WIDTH = 0.75;
const BG_OPACITY = 0.9;
const BG_COLOR = 0.97;
const MIN_SIG_WIDTH = 150.0;
const MAX_SIG_WIDTH = 300.0;
const MIN_SIG_HEIGHT = 40.0;
const MAX_SIG_HEIGHT = 120.0;

type WrapFn = (text: string, fontSize: number, maxWidth: number) => string[];

function makeWrapFn(font: Font): WrapFn {
  return (text, fontSize, maxWidth) => wrapLines(text, fontSize, maxWidth, font.textWidth);
}

// -- Layout computation -------------------------------------------------------

export function computeOptimalWidth(
  fields: string[],
  height: number,
  hasImage: boolean,
  font: Font,
): number {
  if (fields.length === 0) return MIN_SIG_WIDTH;

  const tw = font.textWidth;
  const contentH = height - 2 * PAD_V;
  const nameFontSize = Math.min(NAME_MAX_FONT_SIZE, contentH / NAME_HEIGHT_DIVISOR);
  const detailFontSize = Math.min(DETAIL_MAX_FONT_SIZE, contentH / DETAIL_HEIGHT_DIVISOR);

  const firstField = fields[0];
  if (firstField === undefined) return MIN_SIG_WIDTH;
  let widest = tw(firstField, nameFontSize);
  for (let i = 1; i < fields.length; i++) {
    const field = fields[i];
    if (field !== undefined) {
      widest = Math.max(widest, tw(field, detailFontSize));
    }
  }

  const textW = widest + TEXT_WIDTH_MARGIN;
  let contentW: number;

  if (hasImage) {
    contentW = (textW + COLUMN_GAP) / (1 - IMAGE_COLUMN_RATIO);
  } else {
    contentW = textW;
  }

  const totalW = contentW + 2 * PAD_H;
  return Math.max(MIN_SIG_WIDTH, Math.min(MAX_SIG_WIDTH, totalW));
}

export function computeOptimalHeight(
  fields: string[],
  width: number,
  hasImage: boolean,
  font: Font,
): number {
  if (fields.length === 0) return MIN_SIG_HEIGHT;

  const wl = makeWrapFn(font);
  let contentW = width - 2 * PAD_H;
  if (hasImage) {
    const imgW = contentW * IMAGE_COLUMN_RATIO;
    contentW = contentW - imgW - COLUMN_GAP;
  }

  const nameFontSize = NAME_MAX_FONT_SIZE;
  const detailFontSize = DETAIL_MAX_FONT_SIZE;

  const firstFieldForHeight = fields[0] ?? "";
  const nameLines = wl(firstFieldForHeight, nameFontSize, contentW);
  const nameLeading = nameFontSize * LINE_LEADING;
  const detailLeading = detailFontSize * LINE_LEADING;

  let totalDetailLines = 0;
  for (let i = 1; i < fields.length; i++) {
    const field = fields[i];
    if (field !== undefined) {
      totalDetailLines += wl(field, detailFontSize, contentW).length;
    }
  }

  const nameSectionH = nameLines.length * nameLeading;
  const nameDetailGap = fields.length > 1 ? nameFontSize * NAME_DETAIL_GAP_RATIO : 0;
  const detailSectionH = totalDetailLines * detailLeading;

  const contentH = nameSectionH + nameDetailGap + detailSectionH;
  const totalH = contentH + 2 * PAD_V;

  return Math.max(MIN_SIG_HEIGHT, Math.min(MAX_SIG_HEIGHT, totalH));
}

// -- Appearance stream builder ------------------------------------------------

export async function buildAppearanceStream(
  width: number,
  height: number,
  fields: string[],
  hasImage: boolean = false,
  font?: Font | null,
  imageAspect?: number | null,
): Promise<AppearanceData> {
  const f = font ?? (await getDefaultFont());
  const pe = f.pdfEscape;
  const wl = makeWrapFn(f);

  const bw = BORDER_WIDTH;
  const halfBw = bw / 2;

  const contentX = PAD_H;
  const contentY = PAD_V;
  const contentW = width - 2 * PAD_H;
  const contentH = height - 2 * PAD_V;

  let imgW = 0;
  let textX: number;
  let textW: number;
  if (hasImage) {
    imgW = contentW * IMAGE_COLUMN_RATIO;
    textX = contentX + imgW + COLUMN_GAP;
    textW = contentW - imgW - COLUMN_GAP;
  } else {
    textX = contentX;
    textW = contentW;
  }

  // Font sizing
  let nameFontSize = Math.min(NAME_MAX_FONT_SIZE, contentH / NAME_HEIGHT_DIVISOR);
  let detailFontSize = Math.min(DETAIL_MAX_FONT_SIZE, contentH / DETAIL_HEIGHT_DIVISOR);

  const nameText = fields[0] ?? "";
  const detailTexts = fields.slice(1);

  let nameLines = nameText ? wl(nameText, nameFontSize, textW) : [];
  let nameLeading = nameFontSize * LINE_LEADING;
  let detailLeading = detailFontSize * LINE_LEADING;

  const totalHeight = (): number => {
    let nDetail = 0;
    for (const d of detailTexts) {
      nDetail += wl(d, detailFontSize, textW).length;
    }
    const nameH = nameLines.length * nameLeading;
    const detailH = nDetail * detailLeading;
    const gap = detailTexts.length > 0 ? nameFontSize * NAME_DETAIL_GAP_RATIO : 0;
    return nameH + gap + detailH;
  };

  // Phase 1: shrink name font
  while (nameFontSize > NAME_MIN_FONT_SIZE && nameLines.length > 0) {
    if (totalHeight() <= contentH) break;
    nameFontSize -= NAME_FONT_STEP;
    nameLines = wl(nameText, nameFontSize, textW);
    nameLeading = nameFontSize * LINE_LEADING;
  }

  // Phase 2: shrink detail font
  while (detailFontSize > DETAIL_MIN_FONT_SIZE && detailTexts.length > 0) {
    if (totalHeight() <= contentH) break;
    detailFontSize -= DETAIL_FONT_STEP;
    detailLeading = detailFontSize * LINE_LEADING;
  }

  if (totalHeight() > contentH) {
    logger.warn(
      `Signature text (${totalHeight().toFixed(1)} pt) exceeds field height ` +
        `(${contentH.toFixed(1)} pt). Content will be clipped.`,
    );
  }

  // Vertical centering
  let totalDetailLines = 0;
  for (const d of detailTexts) {
    totalDetailLines += wl(d, detailFontSize, textW).length;
  }
  const nameDetailGap = detailTexts.length > 0 ? nameFontSize * NAME_DETAIL_GAP_RATIO : 0;
  let textSpan = nameFontSize + (nameLines.length - 1) * nameLeading;
  if (totalDetailLines > 0) {
    textSpan += nameDetailGap + (totalDetailLines - 1) * detailLeading;
  }
  const vOffset = Math.max(0, (contentH - textSpan) / 2);

  // Build PDF content stream
  const ops: string[] = [];

  // 0. Semi-transparent white backdrop
  ops.push("q");
  ops.push("/GS1 gs");
  ops.push(`${BG_COLOR} g`);
  ops.push(`0 0 ${width.toFixed(2)} ${height.toFixed(2)} re`);
  ops.push("f");
  ops.push("Q");

  // 1. Border rectangle
  const borderRgb = `${BORDER_COLOR} ${BORDER_COLOR} ${BORDER_COLOR}`;
  ops.push("q");
  ops.push(`${borderRgb} RG`);
  ops.push(`${bw} w`);
  ops.push(
    `${halfBw.toFixed(2)} ${halfBw.toFixed(2)} ${(width - bw).toFixed(2)} ${(height - bw).toFixed(2)} re`,
  );
  ops.push("S");
  ops.push("Q");

  // 2. Image
  if (hasImage) {
    let drawW = imgW;
    let drawH = contentH;
    if (imageAspect && imageAspect > 0) {
      const spaceAspect = contentH > 0 ? imgW / contentH : 1.0;
      if (imageAspect > spaceAspect) {
        drawH = imgW / imageAspect;
      } else {
        drawW = contentH * imageAspect;
      }
    }
    const drawX = contentX + (imgW - drawW) / 2;
    const drawY = contentY + (contentH - drawH) / 2;
    ops.push("q");
    ops.push(
      `${drawW.toFixed(2)} 0 0 ${drawH.toFixed(2)} ${drawX.toFixed(2)} ${drawY.toFixed(2)} cm`,
    );
    ops.push("/Img1 Do");
    ops.push("Q");
  }

  // 3. Text stack
  ops.push("q");
  ops.push(
    `${textX.toFixed(2)} ${contentY.toFixed(2)} ${textW.toFixed(2)} ${contentH.toFixed(2)} re W n`,
  );
  ops.push("BT");
  ops.push("0 Tc 0 Tw");

  // Name field
  const cursorY = contentY + contentH - nameFontSize - vOffset;
  ops.push("0 g");
  ops.push(`/F1 ${nameFontSize.toFixed(3)} Tf`);
  ops.push(`${textX.toFixed(2)} ${cursorY.toFixed(2)} Td`);
  for (let i = 0; i < nameLines.length; i++) {
    if (i > 0) {
      ops.push(`0 ${(-nameLeading).toFixed(2)} Td`);
    }
    const nameLine = nameLines[i];
    if (nameLine !== undefined) {
      ops.push(`${pe(nameLine)} Tj`);
    }
  }

  // Detail fields
  if (detailTexts.length > 0) {
    const nameGap = nameFontSize * NAME_DETAIL_GAP_RATIO;
    ops.push(`0 ${(-nameGap).toFixed(2)} Td`);
    ops.push(`${DETAIL_COLOR} g`);
    ops.push(`/F1 ${detailFontSize.toFixed(3)} Tf`);

    for (let idx = 0; idx < detailTexts.length; idx++) {
      const detailText = detailTexts[idx];
      if (detailText === undefined) continue;
      const detailLines = wl(detailText, detailFontSize, textW);
      for (let i = 0; i < detailLines.length; i++) {
        if (i > 0 || idx > 0) {
          ops.push(`0 ${(-detailLeading).toFixed(2)} Td`);
        }
        const detailLine = detailLines[i];
        if (detailLine !== undefined) {
          ops.push(`${pe(detailLine)} Tj`);
        }
      }
    }
  }

  ops.push("ET");
  ops.push("Q");

  const streamStr = ops.join("\n");
  const streamBytes = new TextEncoder().encode(streamStr);

  return {
    stream: streamBytes,
    bbox: [0, 0, width, height],
    resources: {
      fontName: "F1",
      baseFont: f.name,
    },
    needsImage: hasImage,
    bgOpacity: BG_OPACITY,
  };
}
