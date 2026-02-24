/**
 * Post-build: copy .ttf font files to dist/font-data/.
 * Metrics modules are compiled by tsup as separate entry points.
 */

const { cpSync, readdirSync } = require("node:fs");
const { join } = require("node:path");

const SRC = "src/core/appearance/font-data";
const DEST = "dist/font-data";

for (const font of readdirSync(SRC, { withFileTypes: true })) {
  if (!font.isDirectory()) continue;
  const srcDir = join(SRC, font.name);
  const destDir = join(DEST, font.name);
  for (const file of readdirSync(srcDir)) {
    if (file.endsWith(".ttf")) {
      cpSync(join(srcDir, file), join(destDir, file));
    }
  }
}
