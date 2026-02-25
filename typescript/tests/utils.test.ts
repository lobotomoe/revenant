/**
 * Tests for shared low-level utility functions.
 */

import { describe, expect, it } from "vitest";

import { bytesToHex } from "../src/utils.js";

describe("bytesToHex", () => {
  it("returns empty string for empty array", () => {
    const result = bytesToHex(new Uint8Array([]));
    expect(result).toBe("");
  });

  it("converts single byte 0xff", () => {
    const result = bytesToHex(new Uint8Array([0xff]));
    expect(result).toBe("ff");
  });

  it("converts single byte 0x00", () => {
    const result = bytesToHex(new Uint8Array([0x00]));
    expect(result).toBe("00");
  });

  it("converts single byte 0x0a with leading zero", () => {
    const result = bytesToHex(new Uint8Array([0x0a]));
    expect(result).toBe("0a");
  });

  it("converts multiple bytes", () => {
    const result = bytesToHex(new Uint8Array([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]));
    expect(result).toBe("0123456789abcdef");
  });

  it("converts all zeros", () => {
    const result = bytesToHex(new Uint8Array([0x00, 0x00, 0x00, 0x00]));
    expect(result).toBe("00000000");
  });

  it("converts all 0xff", () => {
    const result = bytesToHex(new Uint8Array([0xff, 0xff, 0xff, 0xff]));
    expect(result).toBe("ffffffff");
  });

  it("produces lowercase hex", () => {
    const result = bytesToHex(new Uint8Array([0xab, 0xcd, 0xef]));
    expect(result).toBe("abcdef");
    expect(result).not.toMatch(/[A-F]/);
  });
});
