/**
 * Tests for shared signing and verification workflows.
 */

import { describe, expect, it } from "vitest";
import { formatVerifyResults as workflowFormatVerifyResults } from "../src/cli/workflows.js";
import type { VerificationResult } from "../src/core/pdf/index.js";

describe("formatVerifyResults", () => {
  it("formats single valid signature", () => {
    const results: VerificationResult[] = [
      {
        valid: true,
        structureOk: true,
        hashOk: true,
        details: ["ByteRange OK", "Hash OK"],
        signer: { name: "Alice", email: null, organization: null, dn: null },
      },
    ];
    const vr = workflowFormatVerifyResults(results);
    expect(vr.allValid).toBe(true);
    expect(vr.totalCount).toBe(1);
    expect(vr.failedCount).toBe(0);
    expect(vr.entries.length).toBe(1);
    const firstEntry = vr.entries[0];
    expect(firstEntry?.signerName).toBe("Alice");
  });

  it("formats multiple signatures with failures", () => {
    const results: VerificationResult[] = [
      {
        valid: true,
        structureOk: true,
        hashOk: true,
        details: ["OK"],
        signer: { name: "Alice", email: null, organization: null, dn: null },
      },
      {
        valid: false,
        structureOk: true,
        hashOk: false,
        details: ["Hash MISMATCH"],
        signer: { name: "Bob", email: null, organization: null, dn: null },
      },
    ];
    const vr = workflowFormatVerifyResults(results);
    expect(vr.allValid).toBe(false);
    expect(vr.totalCount).toBe(2);
    expect(vr.failedCount).toBe(1);
  });

  it("handles unknown signer", () => {
    const results: VerificationResult[] = [
      {
        valid: true,
        structureOk: true,
        hashOk: true,
        details: ["OK"],
        signer: null,
      },
    ];
    const vr = workflowFormatVerifyResults(results);
    const entry = vr.entries[0];
    expect(entry?.signerName).toBe("Unknown");
  });

  it("splits multi-line details", () => {
    const results: VerificationResult[] = [
      {
        valid: false,
        structureOk: true,
        hashOk: false,
        details: ["Hash MISMATCH!\n  Expected: abc\n  Got: def"],
        signer: null,
      },
    ];
    const vr = workflowFormatVerifyResults(results);
    const entry = vr.entries[0];
    expect(entry?.detailLines.length).toBe(3);
  });
});
