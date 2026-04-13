// SPDX-License-Identifier: Apache-2.0
/**
 * Application-wide constants for Revenant.
 *
 * All timeout values, size limits, and other magic numbers are centralized
 * here for easy maintenance and configuration.
 */

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";

const PackageJson = z.object({ version: z.string().optional() });

function resolveVersion(): string {
  try {
    const dir = dirname(fileURLToPath(import.meta.url));
    const pkgPath = join(dir, "..", "package.json");
    const raw: unknown = JSON.parse(readFileSync(pkgPath, "utf-8"));
    const pkg = PackageJson.parse(raw);
    return pkg.version ?? "0.2.4";
  } catch {
    return "0.2.4";
  }
}

export const VERSION = resolveVersion();

// -- Timeout values (seconds) -----------------------------------------------

/** SOAP signing operations timeout. */
export const DEFAULT_TIMEOUT_SOAP = 120;

/** HTTP GET request timeout (for discovery). */
export const DEFAULT_TIMEOUT_HTTP_GET = 15;

/** HTTP POST request timeout (SOAP). */
export const DEFAULT_TIMEOUT_HTTP_POST = 120;

/** Legacy TLS connection timeout. */
export const DEFAULT_TIMEOUT_LEGACY_TLS = 30;

// -- Size units --------------------------------------------------------------

/** Bytes per megabyte -- used for size limit formatting and calculations. */
export const BYTES_PER_MB = 1024 * 1024;

// -- Size limits (bytes) -----------------------------------------------------

/** Maximum response body size for legacy TLS requests (50 MB). */
export const MAX_RESPONSE_SIZE = 50 * 1024 * 1024;

/** Socket recv buffer size for legacy TLS. */
export const RECV_BUFFER_SIZE = 8192;

/**
 * PDF file size warning threshold (35 MB).
 * Server reliably handles up to 35 MB (5/5 stable). 36+ MB is flaky (~50% failure).
 */
export const PDF_WARN_SIZE = 35 * 1024 * 1024;

// -- Retry configuration ----------------------------------------------------

/** Maximum number of retry attempts on transient failures. */
export const DEFAULT_MAX_RETRIES = 3;

/** Initial delay between retries (seconds). */
export const DEFAULT_RETRY_DELAY = 1.0;

/** Exponential backoff multiplier for retry delay. */
export const DEFAULT_RETRY_BACKOFF = 2.0;

// -- Protocol constants ------------------------------------------------------

/** Minimum Base64 length to distinguish CMS signatures from error messages. */
export const MIN_SIGNATURE_B64_LEN = 50;

/** XML preview truncation length for error messages (characters). */
export const XML_PREVIEW_LENGTH = 300;

/** SHA-1 digest size (bytes). */
export const SHA1_DIGEST_SIZE = 20;

// -- Environment variable names ----------------------------------------------

export const ENV_URL = "REVENANT_URL";
export const ENV_TIMEOUT = "REVENANT_TIMEOUT";
export const ENV_USER = "REVENANT_USER";
export const ENV_PASS = "REVENANT_PASS";
export const ENV_NAME = "REVENANT_NAME";

// -- Timeout validation ------------------------------------------------------

export const MIN_TIMEOUT = 1;
export const MAX_TIMEOUT = 3600;

// -- Signature defaults ------------------------------------------------------

/** Default position preset for embedded signatures. */
export const DEFAULT_POSITION = "bottom-right";

// -- TSL / chain validation --------------------------------------------------

/** Trust Service List cache time-to-live (seconds) -- 24 hours. */
export const TSL_CACHE_TTL = 86400;

/** TSL fetch timeout (seconds). */
export const TSL_FETCH_TIMEOUT = 30;

/** Maximum AIA intermediate cert fetches per chain. */
export const MAX_AIA_FETCHES = 5;

/** PDF file magic bytes. */
export const PDF_MAGIC = new Uint8Array([0x25, 0x50, 0x44, 0x46, 0x2d]); // %PDF-
