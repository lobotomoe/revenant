/**
 * Tests for core/signing-response — binding a response to its request.
 */

import { describe, expect, it } from "vitest";
import { checkSigningResponse } from "../src/core/signing-response.js";
import { SigningResponseError } from "../src/errors.js";
import { signCmsDetached } from "./cms-signer.js";
import { FAKE_CMS } from "./conftest.js";

const encode = (text: string): Uint8Array => new TextEncoder().encode(text);

describe("checkSigningResponse", () => {
  it("accepts a signature over the submitted bytes", async () => {
    const content = encode("the exact bytes that were submitted");
    const cms = await signCmsDetached(content);
    await expect(checkSigningResponse(cms, content, "signData")).resolves.toBeUndefined();
  });

  it("rejects a signature over different bytes", async () => {
    const elsewhere = await signCmsDetached(encode("some other document"));
    await expect(
      checkSigningResponse(elsewhere, encode("what we asked for"), "signData"),
    ).rejects.toThrow(/17 bytes submitted/);
  });

  it("rejects filler bytes shaped like DER", async () => {
    await expect(
      checkSigningResponse(FAKE_CMS, encode("content"), "signPdfDetached"),
    ).rejects.toThrow(SigningResponseError);
  });

  it("rejects a truncated response", async () => {
    const cms = await signCmsDetached(encode("content"));
    await expect(
      checkSigningResponse(cms.slice(0, Math.floor(cms.length / 2)), encode("content"), "signData"),
    ).rejects.toThrow(SigningResponseError);
  });

  it("rejects a tampered signature", async () => {
    // Flip one bit deep in the signature, leaving the structure intact.
    const content = encode("the exact bytes that were submitted");
    const cms = await signCmsDetached(content);
    const tampered = new Uint8Array(cms);
    const last = tampered.length - 1;
    tampered[last] = (tampered[last] ?? 0) ^ 0x01;
    await expect(checkSigningResponse(tampered, content, "signData")).rejects.toThrow(
      SigningResponseError,
    );
  });

  it("still requires a verifiable signature when no content was submitted", async () => {
    const cms = await signCmsDetached(encode("anything at all"));
    await expect(checkSigningResponse(cms, null, "signHash")).resolves.toBeUndefined();

    await expect(checkSigningResponse(FAKE_CMS, null, "signHash")).rejects.toThrow(
      /verifiable signature/,
    );
  });
});
