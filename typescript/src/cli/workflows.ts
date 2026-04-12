// SPDX-License-Identifier: Apache-2.0
/**
 * Shared signing and verification workflows.
 *
 * UI-agnostic orchestration of signing and verification operations.
 * CLI is a thin wrapper around these functions.
 *
 * Constraints:
 * - No stdout/stderr output (no console.log)
 * - No process.exit()
 * - Returns structured results, never raises on business errors
 */

import { getActiveProfile, getSignerInfo, registerActiveProfileTls } from "../config/index.js";
import { DEFAULT_POSITION } from "../constants.js";
import { extractCertFields, extractDisplayFields } from "../core/appearance/index.js";
import type { VerificationResult } from "../core/pdf/index.js";
import { AuthError, isNodeError, RevenantError, TLSError } from "../errors.js";
import { atomicWrite } from "./helpers.js";

// -- Result types -------------------------------------------------------------

export interface SigningResult {
  ok: boolean;
  authFailed: boolean;
  tlsError: boolean;
  errorMessage: string | null;
  outputPath: string | null;
  outputSize: number;
}

export interface VerifyEntry {
  index: number;
  total: number;
  valid: boolean;
  signerName: string;
  detailLines: string[];
}

export interface VerifyResult {
  allValid: boolean;
  totalCount: number;
  failedCount: number;
  entries: VerifyEntry[];
}

// -- Error classification -----------------------------------------------------

function classifyError(error: unknown): SigningResult {
  if (error instanceof AuthError) {
    return {
      ok: false,
      authFailed: true,
      tlsError: false,
      errorMessage: error.message,
      outputPath: null,
      outputSize: 0,
    };
  }

  if (error instanceof TLSError) {
    return {
      ok: false,
      authFailed: false,
      tlsError: true,
      errorMessage: error.message,
      outputPath: null,
      outputSize: 0,
    };
  }

  if (error instanceof RevenantError || error instanceof Error) {
    return {
      ok: false,
      authFailed: false,
      tlsError: false,
      errorMessage: error.message,
      outputPath: null,
      outputSize: 0,
    };
  }

  return {
    ok: false,
    authFailed: false,
    tlsError: false,
    errorMessage: "An unexpected error occurred.",
    outputPath: null,
    outputSize: 0,
  };
}

// -- Signing workflows --------------------------------------------------------

export interface EmbeddedSignOptions {
  name?: string | null;
  position?: string;
  page?: number | string;
  imagePath?: string | null;
  visible?: boolean;
  font?: string | null;
  reason?: string;
  fields?: string[] | null;
}

/**
 * Orchestrate embedded PDF signing.
 *
 * Creates transport, calls core signing, writes output atomically.
 * Never raises on business errors -- all captured in the result.
 */
export async function signOneEmbedded(
  pdfBytes: Uint8Array,
  outputPath: string,
  url: string,
  username: string,
  password: string,
  timeout: number,
  options: EmbeddedSignOptions = {},
): Promise<SigningResult> {
  let signedPdf: Uint8Array;
  try {
    const { signPdfEmbedded } = await import("../core/signing.js");
    const { SoapSigningTransport } = await import("../network/soap-transport.js");

    await registerActiveProfileTls();
    const transport = new SoapSigningTransport(url);
    signedPdf = await signPdfEmbedded(pdfBytes, transport, username, password, timeout, {
      name: options.name,
      position: options.position ?? DEFAULT_POSITION,
      page: options.page ?? "last",
      reason: options.reason ?? "",
      imagePath: options.imagePath,
      fields: options.fields,
      visible: options.visible ?? true,
      font: options.font,
    });
  } catch (e) {
    return classifyError(e);
  }

  try {
    atomicWrite(outputPath, signedPdf);
  } catch (e) {
    if (isNodeError(e, "EACCES")) {
      return {
        ok: false,
        authFailed: false,
        tlsError: false,
        errorMessage: `Permission denied: ${outputPath}`,
        outputPath: null,
        outputSize: 0,
      };
    }
    throw e;
  }

  return {
    ok: true,
    authFailed: false,
    tlsError: false,
    errorMessage: null,
    outputPath,
    outputSize: signedPdf.length,
  };
}

/**
 * Orchestrate detached PDF signing.
 */
export async function signOneDetached(
  pdfBytes: Uint8Array,
  outputPath: string,
  url: string,
  username: string,
  password: string,
  timeout: number,
): Promise<SigningResult> {
  let cmsSignature: Uint8Array;
  try {
    const { signPdfDetached } = await import("../core/signing.js");
    const { SoapSigningTransport } = await import("../network/soap-transport.js");

    await registerActiveProfileTls();
    const transport = new SoapSigningTransport(url);
    cmsSignature = await signPdfDetached(pdfBytes, transport, username, password, timeout);
  } catch (e) {
    return classifyError(e);
  }

  try {
    atomicWrite(outputPath, cmsSignature);
  } catch (e) {
    if (isNodeError(e, "EACCES")) {
      return {
        ok: false,
        authFailed: false,
        tlsError: false,
        errorMessage: `Permission denied: ${outputPath}`,
        outputPath: null,
        outputSize: 0,
      };
    }
    throw e;
  }

  return {
    ok: true,
    authFailed: false,
    tlsError: false,
    errorMessage: null,
    outputPath,
    outputSize: cmsSignature.length,
  };
}

// -- Verification workflow ----------------------------------------------------

/**
 * Convert raw verification results into structured display data.
 */
export function formatVerifyResults(results: VerificationResult[]): VerifyResult {
  const total = results.length;
  const entries: VerifyEntry[] = [];
  let failed = 0;

  for (let i = 0; i < results.length; i++) {
    const result = results[i];
    if (result === undefined) continue;
    const signer = result.signer;
    const signerName = signer?.name ?? "Unknown";
    const valid = result.valid;
    if (!valid) failed++;

    const detailLines: string[] = [];
    for (const detail of result.details) {
      detailLines.push(...detail.split("\n"));
    }

    entries.push({
      index: i,
      total,
      valid,
      signerName,
      detailLines,
    });
  }

  return {
    allValid: failed === 0,
    totalCount: total,
    failedCount: failed,
    entries,
  };
}

// -- Field extraction helper --------------------------------------------------

/**
 * Extract display fields from the active profile's sig_fields config.
 */
export function resolveSigFields(): string[] | null {
  const profile = getActiveProfile();
  if (!profile || profile.sigFields.length === 0) {
    return null;
  }
  const signerInfo = getSignerInfo();
  const certValues = extractCertFields(profile.certFields, {
    ...signerInfo,
  });
  return extractDisplayFields(profile.sigFields, certValues);
}
