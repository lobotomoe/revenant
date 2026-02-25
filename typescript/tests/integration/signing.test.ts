/**
 * Integration tests -- require a live CoSign server and credentials.
 *
 * NOT run by default. To run:
 *
 *   REVENANT_USER=... REVENANT_PASS=... pnpm test:integration
 *
 * Credentials are resolved from env vars or saved config (~/.revenant/config.json).
 */

import { describe, expect, it } from "vitest";
import { registerActiveProfileTls, resolveCredentials } from "../../src/config/index.js";
import {
  AuthError,
  RevenantError,
  sign,
  signData,
  signDetached,
  signHash,
  signPdfDetached,
  signPdfEmbedded,
  verifyAllEmbeddedSignatures,
  verifyEmbeddedSignature,
} from "../../src/index.js";
import { SoapSigningTransport } from "../../src/network/soap-transport.js";

// -- Credential resolution ----------------------------------------------------

const { username: USER, password: PASS } = resolveCredentials();
const SERVER_URL = process.env.REVENANT_URL ?? "https://ca.gov.am:8080/SAPIWS/DSS.asmx";

const hasCreds = Boolean(USER && PASS);

/** Narrow credentials to non-null strings (safe inside skipIf(!hasCreds)). */
function requireCreds(): { user: string; pass: string } {
  if (!USER || !PASS) {
    throw new Error("Credentials required but not available");
  }
  return { user: USER, pass: PASS };
}

// -- Minimal valid PDF --------------------------------------------------------

const TINY_PDF = new TextEncoder().encode(
  `%PDF-1.0
1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj
2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj
3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R>>endobj
xref
0 4
0000000000 65535 f \r
0000000010 00000 n \r
0000000059 00000 n \r
0000000116 00000 n \r
trailer<</Size 4/Root 1 0 R>>
startxref
191
%%EOF`,
);

// -- Setup transport ----------------------------------------------------------

async function getTransport(): Promise<SoapSigningTransport> {
  await registerActiveProfileTls();
  return new SoapSigningTransport(SERVER_URL);
}

// -- Detached signing ---------------------------------------------------------

describe.skipIf(!hasCreds)("Detached signing", () => {
  it("should return a valid CMS/DER blob", async () => {
    const { user, pass } = requireCreds();
    const transport = await getTransport();
    const cms = await signPdfDetached(TINY_PDF, transport, user, pass, 120);
    expect(cms).toBeInstanceOf(Uint8Array);
    expect(cms.length).toBeGreaterThan(100);
    // CMS/PKCS#7 starts with ASN.1 SEQUENCE tag
    expect(cms[0]).toBe(0x30);
  });

  it("should produce different CMS for different PDFs", async () => {
    const { user, pass } = requireCreds();
    const transport = await getTransport();
    const pdf2Text = new TextDecoder().decode(TINY_PDF).replace("612 792", "595 842");
    const pdf2 = new TextEncoder().encode(pdf2Text);
    const cms1 = await signPdfDetached(TINY_PDF, transport, user, pass, 120);
    const cms2 = await signPdfDetached(pdf2, transport, user, pass, 120);
    expect(Buffer.from(cms1).equals(Buffer.from(cms2))).toBe(false);
  });
});

// -- Hash signing -------------------------------------------------------------

describe.skipIf(!hasCreds)("Hash signing", () => {
  it("should sign a SHA-1 hash and return valid CMS", async () => {
    const { user, pass } = requireCreds();
    const { createHash } = await import("node:crypto");
    const digest = createHash("sha1").update("test data for integration tests").digest();
    const transport = await getTransport();
    const cms = await signHash(new Uint8Array(digest), transport, user, pass, 120);
    expect(cms).toBeInstanceOf(Uint8Array);
    expect(cms.length).toBeGreaterThan(100);
    expect(cms[0]).toBe(0x30);
  });

  it("should reject non-20-byte hash", async () => {
    const { user, pass } = requireCreds();
    const transport = await getTransport();
    await expect(signHash(new Uint8Array([1, 2, 3]), transport, user, pass, 120)).rejects.toThrow(
      /20/,
    );
  });
});

// -- Authentication -----------------------------------------------------------

describe.skipIf(!hasCreds)("Authentication", () => {
  it("should throw AuthError for wrong password", async () => {
    const { user } = requireCreds();
    const transport = await getTransport();
    await expect(
      signPdfDetached(TINY_PDF, transport, user, "WRONG_PASSWORD_12345", 120),
    ).rejects.toThrow(AuthError);
  });

  it("should throw for wrong username", async () => {
    const { pass } = requireCreds();
    const transport = await getTransport();
    await expect(
      signPdfDetached(TINY_PDF, transport, "NONEXISTENT_USER_XYZ", pass, 120),
    ).rejects.toThrow(RevenantError);
  });
});

// -- Embedded signing ---------------------------------------------------------

describe.skipIf(!hasCreds)("Embedded signing", () => {
  it("should produce a valid signed PDF", async () => {
    const { user, pass } = requireCreds();
    const transport = await getTransport();
    const signed = await signPdfEmbedded(TINY_PDF, transport, user, pass, 120, {
      page: "last",
      position: "bottom-right",
      reason: "Integration test",
      name: "Test Signer",
    });

    expect(signed).toBeInstanceOf(Uint8Array);
    expect(signed.length).toBeGreaterThan(TINY_PDF.length);

    // Our own verification should pass
    const result = await verifyEmbeddedSignature(signed);
    expect(result.valid).toBe(true);
  });

  it("should contain ByteRange and Contents in the signed PDF", async () => {
    const { user, pass } = requireCreds();
    const transport = await getTransport();
    const signed = await signPdfEmbedded(TINY_PDF, transport, user, pass, 120, {
      reason: "CMS check",
      name: "Test",
    });
    const text = new TextDecoder("latin1").decode(signed);
    expect(text).toContain("/ByteRange");
    expect(text).toContain("/Contents <");
  });

  it("should work without a signer name", async () => {
    const { user, pass } = requireCreds();
    const transport = await getTransport();
    const signed = await signPdfEmbedded(TINY_PDF, transport, user, pass, 120, {
      reason: "No name test",
      name: undefined,
    });
    const result = await verifyEmbeddedSignature(signed);
    expect(result.valid).toBe(true);
  });

  it("should work with invisible signature", async () => {
    const { user, pass } = requireCreds();
    const transport = await getTransport();
    const signed = await signPdfEmbedded(TINY_PDF, transport, user, pass, 120, {
      reason: "Invisible test",
      name: "Invisible Signer",
      visible: false,
    });
    expect(signed).toBeInstanceOf(Uint8Array);
    const text = new TextDecoder("latin1").decode(signed);
    expect(text).toContain("/Rect [0 0 0 0]");

    const result = await verifyEmbeddedSignature(signed);
    expect(result.valid).toBe(true);
  });
});

// -- High-level API -----------------------------------------------------------

describe.skipIf(!hasCreds)("High-level API (sign/signDetached)", () => {
  it("sign() with profile should produce valid signed PDF", async () => {
    const { user, pass } = requireCreds();
    await registerActiveProfileTls();
    const signed = await sign(TINY_PDF, user, pass, {
      profile: "ekeng",
      name: "Test Signer",
      reason: "API test",
    });
    expect(signed).toBeInstanceOf(Uint8Array);
    const result = await verifyEmbeddedSignature(signed);
    expect(result.valid).toBe(true);
  });

  it("signDetached() should return valid CMS blob", async () => {
    const { user, pass } = requireCreds();
    await registerActiveProfileTls();
    const cms = await signDetached(TINY_PDF, user, pass, {
      profile: "ekeng",
    });
    expect(cms).toBeInstanceOf(Uint8Array);
    expect(cms.length).toBeGreaterThan(100);
    expect(cms[0]).toBe(0x30);
  });
});

// -- Verification (negative cases) --------------------------------------------

describe.skipIf(!hasCreds)("Verification", () => {
  it("should detect tampered PDF content", async () => {
    const { user, pass } = requireCreds();
    const transport = await getTransport();
    const signed = await signPdfEmbedded(TINY_PDF, transport, user, pass, 120, {
      name: "Test Signer",
    });

    const result = await verifyEmbeddedSignature(signed);
    expect(result.valid).toBe(true);

    // Tamper: change MediaBox dimension
    const text = new TextDecoder("latin1").decode(signed);
    const tampered = new TextEncoder().encode(text.replace("612 792", "613 792"));

    const tamperedResult = await verifyEmbeddedSignature(tampered);
    expect(tamperedResult.valid).toBe(false);
  });

  it("should verify all signatures in a multi-signed PDF", async () => {
    const { user, pass } = requireCreds();
    const transport = await getTransport();

    // First signature
    const signedOnce = await signPdfEmbedded(TINY_PDF, transport, user, pass, 120, {
      position: "bottom-right",
      name: "First Signer",
      reason: "First",
    });

    // Second signature
    const signedTwice = await signPdfEmbedded(signedOnce, transport, user, pass, 120, {
      position: "bottom-left",
      name: "Second Signer",
      reason: "Second",
    });

    const results = await verifyAllEmbeddedSignatures(signedTwice);
    expect(results.length).toBe(2);
    for (const r of results) {
      expect(r.valid).toBe(true);
    }
  });
});

// -- Data signing -------------------------------------------------------------

describe.skipIf(!hasCreds)("Data signing", () => {
  it("should sign arbitrary bytes", async () => {
    const { user, pass } = requireCreds();
    const data = new TextEncoder().encode("Hello, arbitrary data to sign!");
    const transport = await getTransport();
    const cms = await signData(data, transport, user, pass, 120);
    expect(cms).toBeInstanceOf(Uint8Array);
    expect(cms.length).toBeGreaterThan(100);
    expect(cms[0]).toBe(0x30);
  });
});
