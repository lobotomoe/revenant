// SPDX-License-Identifier: Apache-2.0
/**
 * Font registry and text rendering for PDF signature appearances.
 *
 * Available fonts:
 *   - noto-sans: Noto Sans (Google, OFL 1.1) -- default
 *   - ghea-mariam: GHEA Mariam (Armenian)
 *   - ghea-grapalat: GHEA Grapalat (Armenian)
 */

import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export interface FontMetrics {
  name: string;
  unitsPerEm: number;
  ascent: number;
  descent: number;
  capHeight: number;
  bbox: [number, number, number, number];
  stemV: number;
  italicAngle: number;
  defaultWidth: number;
  cmap: Map<number, number>;
  widths: Map<number, number>;
  cidWidthsStr: string;
  tounicodeCmap: string;
  ttfFileName: string;
  /** Resolved absolute path to the TTF file (set during font loading). */
  ttfPath: string;
}

export interface Font {
  name: string;
  textWidth: (text: string, fontSize: number) => number;
  pdfEscape: (text: string) => string;
  metrics: FontMetrics;
}

// -- Font registry ------------------------------------------------------------

export const AVAILABLE_FONTS = ["noto-sans", "ghea-mariam", "ghea-grapalat"] as const;

export type FontName = (typeof AVAILABLE_FONTS)[number];

export const DEFAULT_FONT: FontName = "noto-sans";

interface FontDef {
  metricsModule: string;
  ttfFileName: string;
  baseFontName: string;
}

const FONT_DEFS: Record<FontName, FontDef> = {
  "noto-sans": {
    metricsModule: "./font-data/noto-sans/metrics.js",
    ttfFileName: "NotoSans-Subset.ttf",
    baseFontName: "NotoSans",
  },
  "ghea-mariam": {
    metricsModule: "./font-data/ghea-mariam/metrics.js",
    ttfFileName: "GHEAMariam-Subset.ttf",
    baseFontName: "GHEAMariam",
  },
  "ghea-grapalat": {
    metricsModule: "./font-data/ghea-grapalat/metrics.js",
    ttfFileName: "GHEAGrapalat-Subset.ttf",
    baseFontName: "GHEAGrapalat",
  },
};

const fontCache = new Map<string, Font>();
const defaultFontKey: FontName = DEFAULT_FONT;

const FONT_NAMES: Set<string> = new Set(AVAILABLE_FONTS);

function isValidFontName(name: string): name is FontName {
  return FONT_NAMES.has(name);
}

/**
 * Get a font by key name. Lazy-loads metrics on first access.
 */
export async function getFont(name?: string | null): Promise<Font> {
  const key = name ?? defaultFontKey;
  const cached = fontCache.get(key);
  if (cached) return cached;

  if (!isValidFontName(key)) {
    const available = AVAILABLE_FONTS.join(", ");
    throw new Error(`Unknown font '${key}'. Available: ${available}`);
  }

  return loadFont(key);
}

async function loadFont(key: FontName): Promise<Font> {
  const fontDef = FONT_DEFS[key];

  // Dynamic import of the metrics module
  const mod = await import(fontDef.metricsModule);

  // Resolve absolute path to the TTF file for embedding
  const selfDir = dirname(fileURLToPath(import.meta.url));
  const fontDir = dirname(fontDef.metricsModule);
  const ttfPath = join(selfDir, fontDir, fontDef.ttfFileName);

  const metrics: FontMetrics = {
    name: fontDef.baseFontName,
    unitsPerEm: mod.UNITS_PER_EM,
    ascent: mod.ASCENT,
    descent: mod.DESCENT,
    capHeight: mod.CAP_HEIGHT,
    bbox: mod.BBOX,
    stemV: mod.STEM_V,
    italicAngle: mod.ITALIC_ANGLE,
    defaultWidth: mod.DEFAULT_WIDTH,
    cmap: mod.CMAP,
    widths: mod.WIDTHS,
    cidWidthsStr: mod.CID_WIDTHS_STR,
    tounicodeCmap: mod.TOUNICODE_CMAP,
    ttfFileName: fontDef.ttfFileName,
    ttfPath,
  };

  const font: Font = {
    name: fontDef.baseFontName,
    textWidth: makeTextWidth(metrics),
    pdfEscape: makePdfEscape(metrics),
    metrics,
  };

  fontCache.set(key, font);
  return font;
}

function makeTextWidth(m: FontMetrics): (text: string, fontSize: number) => number {
  const cmap = m.cmap;
  const widths = m.widths;
  const defaultW = m.defaultWidth;
  const upm = m.unitsPerEm;

  return (text: string, fontSize: number): number => {
    let total = 0;
    for (const ch of text) {
      const gid = cmap.get(ch.codePointAt(0) ?? 0) ?? 0;
      total += widths.get(gid) ?? defaultW;
    }
    return (total * fontSize) / upm;
  };
}

function makePdfEscape(m: FontMetrics): (text: string) => string {
  const cmap = m.cmap;
  const questionGid = cmap.get(0x3f) ?? 0; // '?'

  return (text: string): string => {
    const parts: string[] = [];
    for (const ch of text) {
      const gid = cmap.get(ch.codePointAt(0) ?? 0) ?? questionGid;
      parts.push(gid.toString(16).toUpperCase().padStart(4, "0"));
    }
    return `<${parts.join("")}>`;
  };
}

// -- Default font -------------------------------------------------------------

export async function getDefaultFont(): Promise<Font> {
  return getFont(defaultFontKey);
}

// -- Convenience functions ----------------------------------------------------

export async function textWidth(text: string, fontSize: number): Promise<number> {
  const font = await getDefaultFont();
  return font.textWidth(text, fontSize);
}

export async function pdfEscape(text: string): Promise<string> {
  const font = await getDefaultFont();
  return font.pdfEscape(text);
}

export function wrapLines(
  text: string,
  fontSize: number,
  maxWidth: number,
  measure: (text: string, fontSize: number) => number,
): string[] {
  const words = text.split(/\s+/);
  const lines: string[] = [];
  let current = "";

  for (const word of words) {
    if (!word) continue;
    const candidate = current ? `${current} ${word}` : word;
    if (measure(candidate, fontSize) <= maxWidth) {
      current = candidate;
    } else {
      if (current) lines.push(current);
      current = word;
    }
  }
  if (current) lines.push(current);

  return lines;
}

export function encodeTextHex(text: string, cmap: Map<number, number>): string {
  const questionGid = cmap.get(0x3f) ?? 0;
  const parts: string[] = [];
  for (const ch of text) {
    const gid = cmap.get(ch.codePointAt(0) ?? 0) ?? questionGid;
    parts.push(gid.toString(16).toUpperCase().padStart(4, "0"));
  }
  return parts.join("");
}
