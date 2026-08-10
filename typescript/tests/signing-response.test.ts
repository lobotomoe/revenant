/**
 * Tests for core/signing-response — binding a response to its request.
 */

import { describe, expect, it, vi } from "vitest";
import { checkResponseOverContent, checkResponseOverDigest } from "../src/core/signing-response.js";
import { SigningResponseError } from "../src/errors.js";
import { setLogHandler, setLogLevel } from "../src/logger.js";
import { signCmsDetached } from "./cms-signer.js";
import { FAKE_CMS } from "./conftest.js";

const encode = (text: string): Uint8Array => new TextEncoder().encode(text);

/** Capture warnings emitted while `run` executes. */
async function captureWarnings(run: () => Promise<void>): Promise<string[]> {
  const messages: string[] = [];
  const handler = vi.fn((level: string, message: string) => {
    if (level === "warn") {
      messages.push(message);
    }
  });
  setLogLevel("warn");
  setLogHandler(handler);
  try {
    await run();
  } finally {
    setLogHandler(null);
  }
  return messages;
}

describe("checkResponseOverContent", () => {
  it("accepts a signature over the submitted bytes", async () => {
    const content = encode("the exact bytes that were submitted");
    const cms = await signCmsDetached(content);
    await expect(checkResponseOverContent(cms, content, "signData")).resolves.toBeUndefined();
  });

  it("rejects a signature over different bytes", async () => {
    const elsewhere = await signCmsDetached(encode("some other document"));
    await expect(
      checkResponseOverContent(elsewhere, encode("what we asked for"), "signData"),
    ).rejects.toThrow(/17 bytes submitted/);
  });

  it("rejects filler bytes shaped like DER", async () => {
    await expect(
      checkResponseOverContent(FAKE_CMS, encode("content"), "signPdfDetached"),
    ).rejects.toThrow(SigningResponseError);
  });

  it("rejects a truncated response", async () => {
    const cms = await signCmsDetached(encode("content"));
    await expect(
      checkResponseOverContent(
        cms.slice(0, Math.floor(cms.length / 2)),
        encode("content"),
        "signData",
      ),
    ).rejects.toThrow(SigningResponseError);
  });

  it("rejects a tampered signature", async () => {
    // Flip one bit deep in the signature, leaving the structure intact.
    const content = encode("the exact bytes that were submitted");
    const cms = await signCmsDetached(content);
    const tampered = new Uint8Array(cms);
    const last = tampered.length - 1;
    tampered[last] = (tampered[last] ?? 0) ^ 0x01;
    await expect(checkResponseOverContent(tampered, content, "signData")).rejects.toThrow(
      SigningResponseError,
    );
  });
});

describe("checkResponseOverDigest", () => {
  it("still requires a real signature", async () => {
    await expect(checkResponseOverDigest(FAKE_CMS, new Uint8Array(20), "signHash")).rejects.toThrow(
      /verifiable signature/,
    );
  });

  it("accepts a response that binds something else, but says so", async () => {
    // The test signer hashes what it is handed, exactly as the production
    // appliance does with a submitted digest: the signature is genuine, and
    // binds the hash of the digest rather than the digest. That is reported,
    // not rejected — the caller asked to sign these bytes, and they were signed.
    const digest = new Uint8Array(20).fill(0xab);
    const cms = await signCmsDetached(digest);
    const warnings = await captureWarnings(async () => {
      await checkResponseOverDigest(cms, digest, "signHash");
    });
    expect(warnings.join("\n")).toMatch(/pre-computed digest/);
  });
});
