/**
 * Convert Python font metrics to TypeScript.
 * Run: node scripts/convert-font-metrics.mjs
 */

import { readFileSync, writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const projectRoot = join(__dirname, "..");
const pythonRoot = join(projectRoot, "..", "python", "src", "revenant", "core", "appearance", "font_data");

const fonts = [
  { pyDir: "noto_sans", tsDir: "noto-sans" },
  { pyDir: "ghea_mariam", tsDir: "ghea-mariam" },
  { pyDir: "ghea_grapalat", tsDir: "ghea-grapalat" },
];

for (const font of fonts) {
  const pyPath = join(pythonRoot, font.pyDir, "metrics.py");
  const tsPath = join(projectRoot, "src", "core", "appearance", "font-data", font.tsDir, "metrics.ts");

  const pyContent = readFileSync(pyPath, "utf-8");

  // Extract scalar values
  const scalars = {};
  for (const name of ["UNITS_PER_EM", "ASCENT", "DESCENT", "CAP_HEIGHT", "STEM_V", "ITALIC_ANGLE", "DEFAULT_WIDTH"]) {
    const m = pyContent.match(new RegExp(`^${name}\\s*=\\s*(-?\\d+)`, "m"));
    if (m) scalars[name] = parseInt(m[1]);
  }

  // Extract BBOX tuple
  const bboxMatch = pyContent.match(/BBOX\s*=\s*\(([^)]+)\)/);
  const bbox = bboxMatch[1].split(",").map(s => parseInt(s.trim()));

  // Extract CMAP dict
  const cmapMatch = pyContent.match(/CMAP:\s*dict\[int,\s*int\]\s*=\s*\{([^}]+)\}/s);
  const cmapEntries = [];
  for (const line of cmapMatch[1].split("\n")) {
    const m = line.match(/(\d+):\s*(\d+)/);
    if (m) cmapEntries.push([parseInt(m[1]), parseInt(m[2])]);
  }

  // Extract WIDTHS dict
  const widthsMatch = pyContent.match(/WIDTHS:\s*dict\[int,\s*int\]\s*=\s*\{([^}]+)\}/s);
  const widthEntries = [];
  for (const line of widthsMatch[1].split("\n")) {
    const m = line.match(/(\d+):\s*(\d+)/);
    if (m) widthEntries.push([parseInt(m[1]), parseInt(m[2])]);
  }

  // Extract CID_WIDTHS_STR (multiline string)
  const cidMatch = pyContent.match(/CID_WIDTHS_STR\s*=\s*"""([\s\S]*?)"""/);
  // Fallback to single-line if needed
  const cidStr = cidMatch
    ? cidMatch[1].trim()
    : pyContent.match(/CID_WIDTHS_STR\s*=\s*"([^"]+)"/)?.[1] ?? "";

  // Extract TOUNICODE_CMAP (multiline string)
  const tuMatch = pyContent.match(/TOUNICODE_CMAP\s*=\s*"""([\s\S]*?)"""/);
  const tuStr = tuMatch ? tuMatch[1] : "";

  // Build TypeScript
  const lines = [];
  lines.push(`/** Generated font metrics. Do not edit manually. */`);
  lines.push(``);
  lines.push(`export const UNITS_PER_EM = ${scalars.UNITS_PER_EM};`);
  lines.push(`export const ASCENT = ${scalars.ASCENT};`);
  lines.push(`export const DESCENT = ${scalars.DESCENT};`);
  lines.push(`export const CAP_HEIGHT = ${scalars.CAP_HEIGHT};`);
  lines.push(`export const BBOX: [number, number, number, number] = [${bbox.join(", ")}];`);
  lines.push(`export const STEM_V = ${scalars.STEM_V};`);
  lines.push(`export const ITALIC_ANGLE = ${scalars.ITALIC_ANGLE};`);
  lines.push(`export const DEFAULT_WIDTH = ${scalars.DEFAULT_WIDTH};`);
  lines.push(``);
  lines.push(`/** Unicode codepoint -> glyph ID. */`);
  lines.push(`export const CMAP = new Map<number, number>([`);
  for (const [cp, gid] of cmapEntries) {
    lines.push(`  [${cp}, ${gid}],`);
  }
  lines.push(`]);`);
  lines.push(``);
  lines.push(`/** Glyph ID -> advance width. */`);
  lines.push(`export const WIDTHS = new Map<number, number>([`);
  for (const [gid, w] of widthEntries) {
    lines.push(`  [${gid}, ${w}],`);
  }
  lines.push(`]);`);
  lines.push(``);
  lines.push(`/** PDF /W array string. */`);
  lines.push("export const CID_WIDTHS_STR = `");
  lines.push(cidStr);
  lines.push("`;");
  lines.push(``);
  lines.push(`/** ToUnicode CMap string. */`);
  lines.push("export const TOUNICODE_CMAP = `");
  lines.push(tuStr.trimEnd());
  lines.push("`;");
  lines.push(``);

  writeFileSync(tsPath, lines.join("\n"));
  console.log(`Converted ${font.pyDir} -> ${font.tsDir} (${cmapEntries.length} cmap entries, ${widthEntries.length} width entries)`);
}
