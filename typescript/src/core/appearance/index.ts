// SPDX-License-Identifier: Apache-2.0
/** Signature visual appearance -- layout, fonts, and image handling. */

export {
  extractCertFields,
  extractDisplayFields,
  formatUtcOffset,
  makeDateStr,
} from "./fields.js";
export {
  AVAILABLE_FONTS,
  DEFAULT_FONT,
  encodeTextHex,
  type Font,
  type FontMetrics,
  type FontName,
  getDefaultFont,
  getFont,
  pdfEscape,
  textWidth,
  wrapLines,
} from "./fonts.js";
export {
  loadSignatureImage,
  type SignatureImageData,
} from "./image.js";
export {
  type AppearanceData,
  buildAppearanceStream,
  computeOptimalHeight,
  computeOptimalWidth,
} from "./stream.js";
