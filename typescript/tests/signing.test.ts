/**
 * Tests for core signing functions.
 */

import { describe, expect, it, vi } from "vitest";
import { SHA1_DIGEST_SIZE } from "../src/constants.js";

import { signData, signHash, signPdfDetached, signPdfEmbedded } from "../src/core/signing.js";
import { PDFError, RevenantError } from "../src/errors.js";
import { createMockTransport, createValidPdf, FAKE_CMS } from "./conftest.js";

vi.mock("../src/core/pdf/verify.js", async (importOriginal) => {
  const actual = await importOriginal();
  return {
    ...actual,
    verifyEmbeddedSignature: vi.fn().mockResolvedValue({
      valid: true,
      structureOk: true,
      hashOk: true,
      details: ["mocked"],
      signer: null,
    }),
  };
});

// -- signPdfDetached ----------------------------------------------------------

describe("signPdfDetached", () => {
  it("rejects non-PDF input", async () => {
    const transport = createMockTransport();
    const badBytes = new Uint8Array([0x00, 0x01, 0x02]);
    await expect(signPdfDetached(badBytes, transport, "user", "pass")).rejects.toThrow(PDFError);
  });

  it("rejects empty input", async () => {
    const transport = createMockTransport();
    await expect(signPdfDetached(new Uint8Array(0), transport, "user", "pass")).rejects.toThrow(
      PDFError,
    );
  });

  it("rejects input with correct length but wrong magic bytes", async () => {
    // Exactly 5 bytes (PDF_MAGIC length) but not '%PDF-' -- hits the per-byte check (lines 29-31)
    const transport = createMockTransport();
    const wrongMagic = new Uint8Array([0x25, 0x50, 0x44, 0x46, 0x00]); // '%PDF\0'
    await expect(signPdfDetached(wrongMagic, transport, "user", "pass")).rejects.toThrow(PDFError);
  });

  it("calls transport.signPdfDetached for valid PDF", async () => {
    const transport = createMockTransport();
    const pdf = await createValidPdf();
    const result = await signPdfDetached(pdf, transport, "user", "pass", 60);
    expect(transport.signPdfDetached).toHaveBeenCalledWith(pdf, "user", "pass", 60);
    expect(result).toBe(FAKE_CMS);
  });

  it("uses default timeout of 120 when not provided", async () => {
    const transport = createMockTransport();
    const pdf = await createValidPdf();
    await signPdfDetached(pdf, transport, "user", "pass");
    expect(transport.signPdfDetached).toHaveBeenCalledWith(pdf, "user", "pass", 120);
  });
});

// -- signHash -----------------------------------------------------------------

describe("signHash", () => {
  it("rejects wrong-size hash", async () => {
    const transport = createMockTransport();
    const badHash = new Uint8Array(10);
    await expect(signHash(badHash, transport, "user", "pass")).rejects.toThrow(RevenantError);
  });

  it("rejects empty hash", async () => {
    const transport = createMockTransport();
    await expect(signHash(new Uint8Array(0), transport, "user", "pass")).rejects.toThrow(
      RevenantError,
    );
  });

  it("rejects hash that is too long", async () => {
    const transport = createMockTransport();
    const longHash = new Uint8Array(32);
    await expect(signHash(longHash, transport, "user", "pass")).rejects.toThrow(RevenantError);
  });

  it("includes expected and actual sizes in error message", async () => {
    const transport = createMockTransport();
    const badHash = new Uint8Array(10);
    await expect(signHash(badHash, transport, "user", "pass")).rejects.toThrow(
      /Expected 20-byte SHA-1 hash, got 10 bytes/,
    );
  });

  it("accepts 20-byte SHA-1 hash", async () => {
    const transport = createMockTransport();
    const hash = new Uint8Array(SHA1_DIGEST_SIZE);
    const result = await signHash(hash, transport, "user", "pass");
    expect(transport.signHash).toHaveBeenCalledWith(hash, "user", "pass", 120);
    expect(result).toBe(FAKE_CMS);
  });

  it("passes explicit timeout to transport", async () => {
    const transport = createMockTransport();
    const hash = new Uint8Array(SHA1_DIGEST_SIZE);
    await signHash(hash, transport, "user", "pass", 45);
    expect(transport.signHash).toHaveBeenCalledWith(hash, "user", "pass", 45);
  });
});

// -- signData -----------------------------------------------------------------

describe("signData", () => {
  it("rejects empty data", async () => {
    const transport = createMockTransport();
    await expect(signData(new Uint8Array(0), transport, "user", "pass")).rejects.toThrow(
      RevenantError,
    );
  });

  it("includes meaningful error message for empty data", async () => {
    const transport = createMockTransport();
    await expect(signData(new Uint8Array(0), transport, "user", "pass")).rejects.toThrow(
      /Cannot sign empty data/,
    );
  });

  it("signs non-empty data", async () => {
    const transport = createMockTransport();
    const data = new TextEncoder().encode("hello world");
    const result = await signData(data, transport, "user", "pass");
    expect(transport.signData).toHaveBeenCalled();
    expect(result).toBe(FAKE_CMS);
  });

  it("passes credentials and timeout to transport", async () => {
    const transport = createMockTransport();
    const data = new TextEncoder().encode("test");
    await signData(data, transport, "myuser", "mypass", 90);
    expect(transport.signData).toHaveBeenCalledWith(data, "myuser", "mypass", 90);
  });

  it("uses default timeout of 120 when not provided", async () => {
    const transport = createMockTransport();
    const data = new TextEncoder().encode("test");
    await signData(data, transport, "user", "pass");
    expect(transport.signData).toHaveBeenCalledWith(data, "user", "pass", 120);
  });
});

// -- signPdfEmbedded ----------------------------------------------------------

describe("signPdfEmbedded", () => {
  it("rejects non-PDF input", async () => {
    const transport = createMockTransport();
    const badBytes = new Uint8Array([0x00, 0x01, 0x02]);
    await expect(signPdfEmbedded(badBytes, transport, "user", "pass")).rejects.toThrow(PDFError);
  });

  it("rejects empty input", async () => {
    const transport = createMockTransport();
    await expect(signPdfEmbedded(new Uint8Array(0), transport, "user", "pass")).rejects.toThrow(
      PDFError,
    );
  });

  it("rejects input with correct length but wrong magic bytes", async () => {
    // 5 bytes matching PDF_MAGIC length but last byte differs -- hits per-byte check (lines 29-31)
    const transport = createMockTransport();
    const wrongMagic = new Uint8Array([0x25, 0x50, 0x44, 0x46, 0x00]); // '%PDF\0'
    await expect(signPdfEmbedded(wrongMagic, transport, "user", "pass")).rejects.toThrow(PDFError);
  });

  it("rejects negative width", async () => {
    const transport = createMockTransport();
    const pdf = await createValidPdf();
    await expect(
      signPdfEmbedded(pdf, transport, "user", "pass", 120, { width: -10 }),
    ).rejects.toThrow(PDFError);
    await expect(
      signPdfEmbedded(pdf, transport, "user", "pass", 120, { width: -10 }),
    ).rejects.toThrow(/dimensions must be positive/);
  });

  it("rejects zero width", async () => {
    const transport = createMockTransport();
    const pdf = await createValidPdf();
    await expect(
      signPdfEmbedded(pdf, transport, "user", "pass", 120, { width: 0 }),
    ).rejects.toThrow(PDFError);
  });

  it("rejects negative height", async () => {
    const transport = createMockTransport();
    const pdf = await createValidPdf();
    await expect(
      signPdfEmbedded(pdf, transport, "user", "pass", 120, { height: -5 }),
    ).rejects.toThrow(PDFError);
  });

  it("rejects zero height", async () => {
    const transport = createMockTransport();
    const pdf = await createValidPdf();
    await expect(
      signPdfEmbedded(pdf, transport, "user", "pass", 120, { height: 0 }),
    ).rejects.toThrow(PDFError);
  });

  it("rejects negative x coordinate", async () => {
    const transport = createMockTransport();
    const pdf = await createValidPdf();
    await expect(signPdfEmbedded(pdf, transport, "user", "pass", 120, { x: -1 })).rejects.toThrow(
      PDFError,
    );
    await expect(signPdfEmbedded(pdf, transport, "user", "pass", 120, { x: -1 })).rejects.toThrow(
      /x-coordinate must be non-negative/,
    );
  });

  it("rejects negative y coordinate", async () => {
    const transport = createMockTransport();
    const pdf = await createValidPdf();
    await expect(signPdfEmbedded(pdf, transport, "user", "pass", 120, { y: -1 })).rejects.toThrow(
      PDFError,
    );
    await expect(signPdfEmbedded(pdf, transport, "user", "pass", 120, { y: -1 })).rejects.toThrow(
      /y-coordinate must be non-negative/,
    );
  });

  it("uses default timeout of 120 when not provided", async () => {
    const transport = createMockTransport();
    const pdf = await createValidPdf();
    await signPdfEmbedded(pdf, transport, "user", "pass");
    expect(transport.signData).toHaveBeenCalledWith(expect.any(Uint8Array), "user", "pass", 120);
  });

  it("calls transport with correct arguments", async () => {
    const transport = createMockTransport();
    const pdf = await createValidPdf();
    await signPdfEmbedded(pdf, transport, "testuser", "testpass", 60);
    expect(transport.signData).toHaveBeenCalledWith(
      expect.any(Uint8Array),
      "testuser",
      "testpass",
      60,
    );
  });

  it("returns a Uint8Array result", async () => {
    const transport = createMockTransport();
    const pdf = await createValidPdf();
    const result = await signPdfEmbedded(pdf, transport, "user", "pass");
    expect(result).toBeInstanceOf(Uint8Array);
    expect(result.length).toBeGreaterThan(0);
  });

  it("works with invisible signature option", async () => {
    const transport = createMockTransport();
    const pdf = await createValidPdf();
    const result = await signPdfEmbedded(pdf, transport, "user", "pass", 120, {
      visible: false,
    });
    expect(result).toBeInstanceOf(Uint8Array);
    expect(result.length).toBeGreaterThan(0);
  });

  it("works with explicit position", async () => {
    const transport = createMockTransport();
    const pdf = await createValidPdf();
    const result = await signPdfEmbedded(pdf, transport, "user", "pass", 120, {
      x: 100,
      y: 200,
      width: 200,
      height: 50,
    });
    expect(result).toBeInstanceOf(Uint8Array);
    expect(result.length).toBeGreaterThan(0);
  });

  it("accepts zero coordinates", async () => {
    const transport = createMockTransport();
    const pdf = await createValidPdf();
    const result = await signPdfEmbedded(pdf, transport, "user", "pass", 120, {
      x: 0,
      y: 0,
    });
    expect(result).toBeInstanceOf(Uint8Array);
  });

  it("does not crash with auto-sizing when fields are provided", async () => {
    const transport = createMockTransport();
    const pdf = await createValidPdf();
    const result = await signPdfEmbedded(pdf, transport, "user", "pass", 120, {
      fields: ["Signed by: Test User", "Date: 2026-01-01"],
      visible: true,
    });
    expect(result).toBeInstanceOf(Uint8Array);
    expect(result.length).toBeGreaterThan(0);
  });

  it("works with reason and name options", async () => {
    const transport = createMockTransport();
    const pdf = await createValidPdf();
    const result = await signPdfEmbedded(pdf, transport, "user", "pass", 120, {
      reason: "Approval",
      name: "Test Signer",
    });
    expect(result).toBeInstanceOf(Uint8Array);
  });

  it("result starts with PDF magic bytes", async () => {
    const transport = createMockTransport();
    const pdf = await createValidPdf();
    const result = await signPdfEmbedded(pdf, transport, "user", "pass");
    // %PDF-
    expect(result[0]).toBe(0x25);
    expect(result[1]).toBe(0x50);
    expect(result[2]).toBe(0x44);
    expect(result[3]).toBe(0x46);
    expect(result[4]).toBe(0x2d);
  });

  it("throws PDFError when post-sign verification fails", async () => {
    // Temporarily override the mock to return invalid verification
    const verifyMod = await import("../src/core/pdf/verify.js");
    const mockedVerify = vi.mocked(verifyMod.verifyEmbeddedSignature);
    mockedVerify.mockResolvedValueOnce({
      valid: false,
      structureOk: true,
      hashOk: false,
      details: ["Hash MISMATCH", "ByteRange SHA-1 does not match expected"],
      signer: null,
    });

    const transport = createMockTransport();
    const pdf = await createValidPdf();
    try {
      await signPdfEmbedded(pdf, transport, "user", "pass");
      expect.fail("should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(PDFError);
      if (e instanceof PDFError) {
        expect(e.message).toContain("Post-sign verification FAILED");
        expect(e.message).toContain("Hash MISMATCH");
      }
    }
  });

  it("includes verification details in the error message", async () => {
    const verifyMod = await import("../src/core/pdf/verify.js");
    const mockedVerify = vi.mocked(verifyMod.verifyEmbeddedSignature);
    mockedVerify.mockResolvedValueOnce({
      valid: false,
      structureOk: false,
      hashOk: false,
      details: ["Structure error: CMS is corrupt"],
      signer: null,
    });

    const transport = createMockTransport();
    const pdf = await createValidPdf();
    try {
      await signPdfEmbedded(pdf, transport, "user", "pass");
      expect.fail("should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(PDFError);
      if (e instanceof PDFError) {
        expect(e.message).toContain("Structure error");
        expect(e.message).toContain("corrupt");
      }
    }
  });
});
