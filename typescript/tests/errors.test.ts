/**
 * Tests for error class hierarchy and utility functions.
 */

import { describe, expect, it } from "vitest";

import {
  AuthError,
  CertificateError,
  ConfigError,
  getErrorMessage,
  isNodeError,
  PDFError,
  RevenantError,
  ServerError,
  TLSError,
} from "../src/errors.js";

// -- Error classes ------------------------------------------------------------

describe("RevenantError", () => {
  it("extends Error", () => {
    const err = new RevenantError("test");
    expect(err).toBeInstanceOf(Error);
    expect(err).toBeInstanceOf(RevenantError);
    expect(err.message).toBe("test");
    expect(err.name).toBe("RevenantError");
  });
});

describe("Error subclasses", () => {
  const cases = [
    { cls: AuthError, name: "AuthError" },
    { cls: ServerError, name: "ServerError" },
    { cls: TLSError, name: "TLSError" },
    { cls: PDFError, name: "PDFError" },
    { cls: ConfigError, name: "ConfigError" },
    { cls: CertificateError, name: "CertificateError" },
  ] as const;

  for (const { cls, name } of cases) {
    it(`${name} extends RevenantError`, () => {
      const err = new cls(`${name} message`);
      expect(err).toBeInstanceOf(Error);
      expect(err).toBeInstanceOf(RevenantError);
      expect(err).toBeInstanceOf(cls);
      expect(err.message).toBe(`${name} message`);
      expect(err.name).toBe(name);
    });
  }
});

describe("TLSError retryable", () => {
  it("defaults to false", () => {
    const err = new TLSError("fail");
    expect(err.retryable).toBe(false);
  });

  it("can be set to true", () => {
    const err = new TLSError("fail", { retryable: true });
    expect(err.retryable).toBe(true);
  });
});

// -- isNodeError --------------------------------------------------------------

describe("isNodeError", () => {
  it("returns true for Error with code property", () => {
    const err = new Error("test");
    Object.assign(err, { code: "ENOENT" });
    expect(isNodeError(err)).toBe(true);
  });

  it("returns false for Error without code property", () => {
    const err = new Error("plain error");
    expect(isNodeError(err)).toBe(false);
  });

  it("returns false for non-Error values", () => {
    expect(isNodeError("not an error")).toBe(false);
    expect(isNodeError(42)).toBe(false);
    expect(isNodeError(null)).toBe(false);
    expect(isNodeError(undefined)).toBe(false);
    expect(isNodeError({ code: "ENOENT" })).toBe(false);
  });

  it("matches specific code when provided", () => {
    const err = new Error("file not found");
    Object.assign(err, { code: "ENOENT" });
    expect(isNodeError(err, "ENOENT")).toBe(true);
    expect(isNodeError(err, "EACCES")).toBe(false);
  });

  it("returns true for any code when code arg is omitted", () => {
    const err = new Error("access denied");
    Object.assign(err, { code: "EACCES" });
    expect(isNodeError(err)).toBe(true);
  });
});

// -- getErrorMessage ----------------------------------------------------------

describe("getErrorMessage", () => {
  it("extracts message from Error", () => {
    const err = new Error("something broke");
    expect(getErrorMessage(err)).toBe("something broke");
  });

  it("extracts message from RevenantError", () => {
    const err = new ConfigError("bad config");
    expect(getErrorMessage(err)).toBe("bad config");
  });

  it("converts string to itself", () => {
    expect(getErrorMessage("raw string")).toBe("raw string");
  });

  it("converts number to string", () => {
    expect(getErrorMessage(42)).toBe("42");
  });

  it("converts null to string", () => {
    expect(getErrorMessage(null)).toBe("null");
  });

  it("converts undefined to string", () => {
    expect(getErrorMessage(undefined)).toBe("undefined");
  });

  it("converts object to string", () => {
    const result = getErrorMessage({ key: "value" });
    expect(result).toBe("[object Object]");
  });
});
