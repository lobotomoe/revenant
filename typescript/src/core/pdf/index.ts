// SPDX-License-Identifier: Apache-2.0
/** PDF core re-exports. */

export {
  ASN1_SEQUENCE_TAG,
  extractDerFromPaddedHex,
  MIN_CMS_SIZE,
} from "./asn1.js";
export {
  computeByterangeHash,
  insertCms,
  type PrepareOptions,
  type PrepareResult,
  preparePdfWithSigField,
} from "./builder.js";
export {
  BYTERANGE_PATTERN,
  type ByteRangeMatch,
  extractCmsFromByterange,
  extractCmsFromByterangeMatch,
  extractSignatureData,
  extractSignatureDataFromMatch,
  findByteRanges,
} from "./cms-extraction.js";
export {
  type CmsInspection,
  extractDigestInfo,
  extractSignerInfo,
  inspectCmsBlob,
  resolveHashAlgo,
} from "./cms-info.js";
export {
  assembleIncrementalUpdate,
  buildXrefAndTrailer,
  buildXrefStream,
  findPageObjNum,
  findPrevStartxref,
  findRootObjNum,
  type PageInfo,
  patchByterange,
} from "./incremental.js";
export { checkLtvStatus, type LtvStatus } from "./ltv.js";
export {
  ANNOT_FLAGS_SIG_WIDGET,
  allocateSigObjects,
  BYTERANGE_PLACEHOLDER,
  BYTERANGE_PLACEHOLDER_BYTES,
  buildCatalogOverride,
  buildObjectOverride,
  buildPageOverride,
  CMS_HEX_SIZE,
  CMS_RESERVED_SIZE,
  pdfString,
  type SigObjectNums,
  serializePdfObject,
} from "./objects.js";
export {
  computeSigRect,
  getPageDimensions,
  parsePageSpec,
  resolvePageIndex,
  resolvePosition,
  SIG_HEIGHT,
  SIG_WIDTH,
  type SigRect,
} from "./position.js";
export {
  buildAnnotWidget,
  buildEmbeddedFontObjects,
  buildFormXobjects,
  buildInvisibleAnnotWidget,
  buildSigDict,
  type FormXobjects,
} from "./render.js";
export {
  type VerificationResult,
  verifyAllEmbeddedSignatures,
  verifyDetachedSignature,
  verifyEmbeddedSignature,
} from "./verify.js";
