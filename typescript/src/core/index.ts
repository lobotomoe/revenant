// SPDX-License-Identifier: Apache-2.0
/** Core module re-exports. */

export {
  type CertInfo,
  discoverIdentityFromServer,
  extractAllCertInfoFromPdf,
  extractCertInfoFromCms,
  extractCertInfoFromPdf,
  extractCertInfoFromX509,
} from "./cert-info.js";
export {
  signData,
  signHash,
  signPdfDetached,
  signPdfEmbedded,
} from "./signing.js";
