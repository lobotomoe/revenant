// SPDX-License-Identifier: Apache-2.0
/**
 * revenant -- Cross-platform client for ARX CoSign electronic signatures.
 *
 * Signs PDF documents via the CoSign SOAP API (OASIS DSS standard).
 * No Windows required -- works on macOS and Linux.
 */

// High-level API
export {
  type DetachedSignOptions,
  type SignOptions,
  sign,
  signDetached,
} from "./api.js";
// Configuration
export { getSignerName } from "./config/config.js";
// Constants
export { VERSION } from "./constants.js";
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
// Core signing
export {
  signData,
  signHash,
  signPdfDetached,
  signPdfEmbedded,
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
