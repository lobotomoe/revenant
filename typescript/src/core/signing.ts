// SPDX-License-Identifier: Apache-2.0
/**
 * Core signing functions -- detached CMS and embedded PDF signatures.
 *
 * All signing functions accept a SigningTransport, making them
 * transport-agnostic. Use SoapSigningTransport to create an instance.
 */

import { DEFAULT_TIMEOUT_SOAP, PDF_MAGIC, SHA1_DIGEST_SIZE } from "../constants.js";
import { PDFError, RevenantError } from "../errors.js";
import type { SigningTransport } from "../network/protocol.js";
import { computeOptimalHeight, computeOptimalWidth, getFont } from "./appearance/index.js";
import {
  computeByterangeHash,
  insertCms,
  type PrepareOptions,
  preparePdfWithSigField,
  SIG_HEIGHT,
  SIG_WIDTH,
  verifyEmbeddedSignature,
} from "./pdf/index.js";

// -- Helpers ------------------------------------------------------------------

function validatePdf(pdfBytes: Uint8Array): void {
  if (pdfBytes.length < PDF_MAGIC.length) {
    throw new PDFError("Input does not appear to be a PDF file.");
  }
  for (let i = 0; i < PDF_MAGIC.length; i++) {
    if (pdfBytes[i] !== PDF_MAGIC[i]) {
      throw new PDFError("Input does not appear to be a PDF file.");
    }
  }
}

// -- Detached signing ---------------------------------------------------------

/**
 * Sign a PDF document -- returns a detached CMS/PKCS#7 signature.
 */
export async function signPdfDetached(
  pdfBytes: Uint8Array,
  transport: SigningTransport,
  username: string,
  password: string,
  timeout: number = DEFAULT_TIMEOUT_SOAP,
): Promise<Uint8Array> {
  validatePdf(pdfBytes);
  return transport.signPdfDetached(pdfBytes, username, password, timeout);
}

// -- Hash signing -------------------------------------------------------------

/**
 * Sign a pre-computed hash (typically 20-byte SHA-1).
 */
export async function signHash(
  hashBytes: Uint8Array,
  transport: SigningTransport,
  username: string,
  password: string,
  timeout: number = DEFAULT_TIMEOUT_SOAP,
): Promise<Uint8Array> {
  if (hashBytes.length !== SHA1_DIGEST_SIZE) {
    throw new RevenantError(
      `Expected ${SHA1_DIGEST_SIZE}-byte SHA-1 hash, got ${hashBytes.length} bytes.`,
    );
  }
  return transport.signHash(hashBytes, username, password, timeout);
}

// -- Data signing -------------------------------------------------------------

/**
 * Sign arbitrary data. The server computes SHA-1 internally.
 */
export async function signData(
  dataBytes: Uint8Array,
  transport: SigningTransport,
  username: string,
  password: string,
  timeout: number = DEFAULT_TIMEOUT_SOAP,
): Promise<Uint8Array> {
  if (dataBytes.length === 0) {
    throw new RevenantError("Cannot sign empty data.");
  }
  return transport.signData(dataBytes, username, password, timeout);
}

// -- Embedded PDF signing -----------------------------------------------------

/**
 * Sign a PDF with an embedded signature.
 *
 * Uses the data-then-sign workflow:
 * 1. Prepare PDF with empty signature field
 * 2. Extract ByteRange data (everything except hex placeholder)
 * 3. Send ByteRange data to transport for signing
 * 4. Insert CMS into the PDF
 * 5. Verify the signature
 */
export async function signPdfEmbedded(
  pdfBytes: Uint8Array,
  transport: SigningTransport,
  username: string,
  password: string,
  timeout: number = DEFAULT_TIMEOUT_SOAP,
  options: PrepareOptions = {},
): Promise<Uint8Array> {
  validatePdf(pdfBytes);

  let w = options.width ?? SIG_WIDTH;
  let h = options.height ?? SIG_HEIGHT;
  const visible = options.visible ?? true;

  if (w <= 0 || h <= 0) {
    throw new PDFError(`Signature dimensions must be positive, got w=${w}, h=${h}`);
  }
  if (options.x != null && options.x < 0) {
    throw new PDFError(`Signature x-coordinate must be non-negative, got ${options.x}`);
  }
  if (options.y != null && options.y < 0) {
    throw new PDFError(`Signature y-coordinate must be non-negative, got ${options.y}`);
  }

  // Auto-size dimensions if fields are available (visible mode only)
  if (visible && options.fields) {
    const fontObj = await getFont(options.font);
    const hasImg = options.imagePath != null;
    if (w === SIG_WIDTH) {
      w = computeOptimalWidth(options.fields, h, hasImg, fontObj);
    }
    if (h === SIG_HEIGHT) {
      h = computeOptimalHeight(options.fields, w, hasImg, fontObj);
    }
  }

  // Step 1: Prepare PDF with signature field
  const prepareOpts: PrepareOptions = {
    ...options,
    width: w,
    height: h,
  };
  const {
    pdf: preparedPdf,
    hexStart,
    hexLen,
  } = await preparePdfWithSigField(pdfBytes, prepareOpts);

  // Step 2: Extract ByteRange data (everything except hex placeholder)
  const before = preparedPdf.slice(0, hexStart);
  const after = preparedPdf.slice(hexStart + hexLen + 1); // +1 for '>'
  const brData = new Uint8Array(before.length + after.length);
  brData.set(before, 0);
  brData.set(after, before.length);

  // Step 3: Send ByteRange data to transport for signing
  const cmsDer = await signData(brData, transport, username, password, timeout);

  // Step 4: Insert CMS into PDF
  const signedPdf = insertCms(preparedPdf, hexStart, hexLen, cmsDer);
  if (signedPdf.length !== preparedPdf.length) {
    throw new PDFError(`insertCms changed PDF size: ${preparedPdf.length} -> ${signedPdf.length}`);
  }

  // Step 5: Verify the result
  const brHash = computeByterangeHash(preparedPdf, hexStart, hexLen);
  const result = await verifyEmbeddedSignature(signedPdf, brHash);
  if (!result.valid) {
    const detailStr = result.details.join("\n  ");
    throw new PDFError(
      `Post-sign verification FAILED:\n  ${detailStr}\n` +
        "The signed PDF may be corrupt -- not saved.",
    );
  }

  return signedPdf;
}
