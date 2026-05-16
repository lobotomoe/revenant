// SPDX-License-Identifier: Apache-2.0
/**
 * revenant -- Cross-platform client for ARX CoSign electronic signatures.
 *
 * Signs PDF documents via the CoSign SOAP API (OASIS DSS standard).
 * No Windows required -- works on macOS and Linux.
 */

// High-level API — production callers use these. Profile resolution,
// transport setup, and TLS registration are handled internally; no
// SigningTransport instance ever crosses the API boundary.
export {
  type DetachedSignOptions,
  getCertInfo,
  type SignOptions,
  sign,
  signData,
  signDetached,
  signHash,
  verifyCredentials,
} from "./api.js";
// Configuration
export { getSignerName } from "./config/config.js";
// Constants
export { VERSION } from "./constants.js";
// Identity payload returned by getCertInfo (CN, email, organization,
// validity dates, full DN).
export type { CertInfo } from "./core/cert-info.js";
// PDF verification
export {
  type PrepareOptions,
  type PrepareResult,
  resolvePosition,
  type VerificationResult,
  verifyAllEmbeddedSignatures,
  verifyDetachedSignature,
  verifyEmbeddedSignature,
} from "./core/pdf/index.js";
// Low-level signing — exported for callers that need to inject a
// custom SigningTransport (mocks, alternative appliances). Production
// code should use the high-level exports above.
export {
  signDataWithTransport,
  signHashWithTransport,
  signPdfDetachedWithTransport,
  signPdfEmbeddedWithTransport,
} from "./core/signing.js";
// Errors
export {
  AuthError,
  CertificateError,
  ConfigError,
  PDFError,
  RevenantError,
  ServerError,
  TLSError,
} from "./errors.js";
// Logger
export {
  type LogHandler,
  type LogLevel,
  setLogHandler,
  setLogLevel,
} from "./logger.js";
