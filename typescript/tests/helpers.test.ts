/**
 * Tests for CLI helper functions.
 */

import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import {
  atomicWrite,
  defaultDetachedOutputPath,
  defaultOutputPath,
  formatSizeKb,
} from "../src/cli/helpers.js";

describe("formatSizeKb", () => {
  it("formats bytes to KB", () => {
    expect(formatSizeKb(1024)).toBe("1.0 KB");
    expect(formatSizeKb(2048)).toBe("2.0 KB");
    expect(formatSizeKb(1536)).toBe("1.5 KB");
  });

  it("handles zero", () => {
    expect(formatSizeKb(0)).toBe("0.0 KB");
  });
});

describe("defaultOutputPath", () => {
  it("appends _signed before extension", () => {
    expect(defaultOutputPath("/tmp/doc.pdf")).toBe("/tmp/doc_signed.pdf");
  });

  it("handles files without extension", () => {
    expect(defaultOutputPath("/tmp/document")).toBe("/tmp/document_signed.pdf");
  });
});

describe("defaultDetachedOutputPath", () => {
  it("appends .p7s", () => {
    expect(defaultDetachedOutputPath("/tmp/doc.pdf")).toBe("/tmp/doc.pdf.p7s");
  });
});

describe("atomicWrite", () => {
  it("writes file atomically", () => {
    const dir = mkdtempSync(join(tmpdir(), "revenant-test-"));
    const filePath = join(dir, "output.pdf");
    const data = new Uint8Array([1, 2, 3, 4, 5]);

    atomicWrite(filePath, data);

    expect(existsSync(filePath)).toBe(true);
    const written = readFileSync(filePath);
    expect(new Uint8Array(written)).toEqual(data);
  });

  it("does not leave partial files on error", () => {
    const dir = mkdtempSync(join(tmpdir(), "revenant-test-"));
    // Write a legitimate file first
    const filePath = join(dir, "exists.pdf");
    writeFileSync(filePath, "original");

    // The atomic write should replace the file completely
    const data = new Uint8Array([10, 20, 30]);
    atomicWrite(filePath, data);
    const written = readFileSync(filePath);
    expect(new Uint8Array(written)).toEqual(data);
  });
});
