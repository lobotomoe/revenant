// SPDX-License-Identifier: Apache-2.0
/** Revenant error types and utilities. */

// -- Type guards --------------------------------------------------------------

/** Check if an unknown error is a NodeJS ErrnoException, optionally matching a code. */
export function isNodeError(err: unknown, code?: string): err is NodeJS.ErrnoException {
  if (!(err instanceof Error)) return false;
  // "code" in err narrows to Error & { code: unknown }
  if (!("code" in err)) return false;
  if (code === undefined) return true;
  return err.code === code;
}

/** Extract a human-readable message from an unknown error. */
export function getErrorMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  return String(err);
}

// -- Error classes ------------------------------------------------------------

export class RevenantError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RevenantError";
  }
}

export class AuthError extends RevenantError {
  constructor(message: string) {
    super(message);
    this.name = "AuthError";
  }
}

export class ServerError extends RevenantError {
  constructor(message: string) {
    super(message);
    this.name = "ServerError";
  }
}

export class TLSError extends RevenantError {
  readonly retryable: boolean;

  constructor(message: string, options?: { retryable?: boolean }) {
    super(message);
    this.name = "TLSError";
    this.retryable = options?.retryable ?? false;
  }
}

export class PDFError extends RevenantError {
  constructor(message: string) {
    super(message);
    this.name = "PDFError";
  }
}

export class ConfigError extends RevenantError {
  constructor(message: string) {
    super(message);
    this.name = "ConfigError";
  }
}

export class CertificateError extends RevenantError {
  constructor(message: string) {
    super(message);
    this.name = "CertificateError";
  }
}
