// SPDX-License-Identifier: Apache-2.0
/**
 * HTTP transport for CoSign.
 *
 * Auto-detects TLS mode per host: standard HTTPS via Node's https module,
 * or legacy TLS via node-forge for hosts requiring RC4.
 */

import {
  BYTES_PER_MB,
  DEFAULT_MAX_RETRIES,
  DEFAULT_RETRY_BACKOFF,
  DEFAULT_RETRY_DELAY,
  DEFAULT_TIMEOUT_HTTP_GET,
  DEFAULT_TIMEOUT_HTTP_POST,
  MAX_RESPONSE_SIZE,
} from "../constants.js";
import { RevenantError, TLSError } from "../errors.js";
import { logger } from "../logger.js";
import { legacyRequest } from "./legacy-tls.js";

// -- Per-host TLS mode cache -------------------------------------------------

const hostLegacyTls = new Map<string, boolean>();

export function registerHostTls(host: string, legacy: boolean): void {
  hostLegacyTls.set(host, legacy);
}

export function getHostTlsInfo(host: string): string | null {
  const mode = hostLegacyTls.get(host);
  if (mode === undefined) return null;
  return mode ? "Legacy TLS (RC4)" : "Standard HTTPS";
}

function resolveHost(url: string): string {
  const parsed = new URL(url);
  if (!parsed.hostname) {
    throw new RevenantError(`Cannot extract hostname from URL: ${url}`);
  }
  return parsed.hostname;
}

function requireHttpsUrl(url: string): void {
  const parsed = new URL(url);
  if (parsed.protocol !== "https:") {
    throw new RevenantError(
      `Only HTTPS URLs are allowed (got ${parsed.protocol}). ` +
        "Credentials must not be sent over unencrypted connections.",
    );
  }
}

// -- Retry logic -------------------------------------------------------------

function isRetryableError(exc: RevenantError): boolean {
  return exc instanceof TLSError && exc.retryable;
}

async function withRetry<T>(
  fn: () => Promise<T>,
  maxRetries: number = DEFAULT_MAX_RETRIES,
  delay: number = DEFAULT_RETRY_DELAY,
  backoff: number = DEFAULT_RETRY_BACKOFF,
  operation: string = "request",
): Promise<T> {
  let lastExc: RevenantError | null = null;
  let currentDelay = delay;

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      return await fn();
    } catch (exc) {
      if (!(exc instanceof RevenantError)) throw exc;
      lastExc = exc;
      if (attempt >= maxRetries || !isRetryableError(exc)) throw exc;

      logger.warn(
        `${operation} failed (attempt ${attempt + 1}/${maxRetries + 1}): ${exc.message}. ` +
          `Retrying in ${currentDelay.toFixed(1)}s...`,
      );
      await sleep(currentDelay * 1000);
      currentDelay *= backoff;
    }
  }

  if (lastExc) throw lastExc;
  throw new Error("Retry logic error");
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// -- Standard HTTPS (Node built-in) -----------------------------------------

async function fetchWithLimit(
  url: string,
  init: RequestInit,
  timeout: number,
): Promise<Uint8Array> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout * 1000);
  init.signal = controller.signal;

  try {
    const response = await fetch(url, init);
    if (!response.ok && !response.body) {
      throw new RevenantError(`HTTP ${response.status} from ${url}: ${response.statusText}`);
    }

    const reader = response.body?.getReader();
    if (!reader) {
      throw new RevenantError(`No response body from ${url}`);
    }

    const chunks: Uint8Array[] = [];
    let totalSize = 0;

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      totalSize += value.length;
      if (totalSize > MAX_RESPONSE_SIZE) {
        reader.cancel();
        throw new RevenantError(
          `Response from ${url} exceeds ${MAX_RESPONSE_SIZE / BYTES_PER_MB} MB limit`,
        );
      }
      chunks.push(value);
    }

    return Buffer.concat(chunks);
  } catch (err) {
    if (err instanceof RevenantError) throw err;
    const errMsg = err instanceof Error ? err.message : String(err);
    if (errMsg.includes("abort") || errMsg.includes("timeout")) {
      throw new TLSError(`Connection timed out after ${timeout}s: ${url}`, {
        retryable: true,
      });
    }
    if (
      errMsg.toLowerCase().includes("ssl") ||
      errMsg.toLowerCase().includes("certificate") ||
      errMsg.includes("UNABLE_TO_VERIFY") ||
      errMsg.includes("ERR_TLS")
    ) {
      throw new TLSError(`SSL error: ${url}: ${errMsg}`, { retryable: true });
    }
    // Generic connection failure (e.g. Node's "fetch failed") -- likely TLS
    // incompatibility since the TCP+TLS handshake never completed.
    if (
      errMsg.includes("fetch failed") ||
      errMsg.includes("ECONNREFUSED") ||
      errMsg.includes("ECONNRESET")
    ) {
      throw new TLSError(`Connection failed: ${url}: ${errMsg}`, { retryable: true });
    }
    throw new RevenantError(`HTTP request failed: ${url}: ${errMsg}`);
  } finally {
    clearTimeout(timer);
  }
}

async function stdGet(url: string, timeout: number): Promise<Uint8Array> {
  return fetchWithLimit(url, { method: "GET" }, timeout);
}

async function stdPost(
  url: string,
  body: Uint8Array,
  headers?: Record<string, string>,
  timeout: number = DEFAULT_TIMEOUT_HTTP_POST,
): Promise<Uint8Array> {
  const init: RequestInit = {
    method: "POST",
    body,
    headers,
  };
  return fetchWithLimit(url, init, timeout);
}

// -- Auto-detection ----------------------------------------------------------

async function autoDetectGet(url: string, host: string, timeout: number): Promise<Uint8Array> {
  try {
    const result = await stdGet(url, timeout);
    hostLegacyTls.set(host, false);
    return result;
  } catch (err) {
    if (err instanceof TLSError) {
      logger.warn(`Standard HTTPS failed for ${host}, trying legacy TLS...`);
    } else {
      throw err;
    }
  }

  const result = await legacyRequest("GET", url, { timeout });
  hostLegacyTls.set(host, true);
  logger.warn(`Auto-detected legacy TLS (RC4) for ${host}`);
  return result;
}

async function autoDetectPost(
  url: string,
  host: string,
  body: Uint8Array,
  headers: Record<string, string> | undefined,
  timeout: number,
): Promise<Uint8Array> {
  try {
    const result = await stdPost(url, body, headers, timeout);
    hostLegacyTls.set(host, false);
    return result;
  } catch (err) {
    if (err instanceof TLSError) {
      logger.warn(`Standard HTTPS failed for ${host}, trying legacy TLS...`);
    } else {
      throw err;
    }
  }

  const result = await legacyRequest("POST", url, { body, headers, timeout });
  hostLegacyTls.set(host, true);
  logger.warn(`Auto-detected legacy TLS (RC4) for ${host}`);
  return result;
}

// -- Public API --------------------------------------------------------------

export async function httpGet(
  url: string,
  options?: {
    timeout?: number;
    maxRetries?: number;
  },
): Promise<Uint8Array> {
  requireHttpsUrl(url);
  const host = resolveHost(url);
  const timeout = options?.timeout ?? DEFAULT_TIMEOUT_HTTP_GET;
  const maxRetries = options?.maxRetries ?? DEFAULT_MAX_RETRIES;
  const legacy = hostLegacyTls.get(host);

  if (legacy === undefined) {
    return autoDetectGet(url, host, timeout);
  }

  if (!legacy) {
    const doGet = () => stdGet(url, timeout);
    return maxRetries > 0
      ? withRetry(doGet, maxRetries, DEFAULT_RETRY_DELAY, DEFAULT_RETRY_BACKOFF, `GET ${url}`)
      : doGet();
  }

  const doGet = () => legacyRequest("GET", url, { timeout });
  return maxRetries > 0
    ? withRetry(doGet, maxRetries, DEFAULT_RETRY_DELAY, DEFAULT_RETRY_BACKOFF, `GET ${url}`)
    : doGet();
}

export async function httpPost(
  url: string,
  body: Uint8Array,
  options?: {
    headers?: Record<string, string>;
    timeout?: number;
    maxRetries?: number;
  },
): Promise<Uint8Array> {
  requireHttpsUrl(url);
  const host = resolveHost(url);
  const timeout = options?.timeout ?? DEFAULT_TIMEOUT_HTTP_POST;
  const maxRetries = options?.maxRetries ?? DEFAULT_MAX_RETRIES;
  const legacy = hostLegacyTls.get(host);

  // Unknown host -- auto-detect on first request
  if (legacy === undefined) {
    return autoDetectPost(url, host, body, options?.headers, timeout);
  }

  const doPost = () => {
    if (!legacy) {
      return stdPost(url, body, options?.headers, timeout);
    }
    return legacyRequest("POST", url, {
      body,
      headers: options?.headers,
      timeout,
    });
  };

  return maxRetries > 0
    ? withRetry(doPost, maxRetries, DEFAULT_RETRY_DELAY, DEFAULT_RETRY_BACKOFF, `POST ${url}`)
    : doPost();
}
