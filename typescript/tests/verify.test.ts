/**
 * Tests for PDF signature verification.
 *
 * Uses preparePdfWithSigField + insertCms from the builder to create
 * properly structured signed PDFs, then verifies them through the
 * full verify.ts code paths.
 */

import { createHash } from "node:crypto";

import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import { describe, expect, it } from "vitest";

import {
  computeByterangeHash,
  insertCms,
  preparePdfWithSigField,
  verifyAllEmbeddedSignatures,
  verifyDetachedSignature,
  verifyEmbeddedSignature,
} from "../src/core/pdf/index.js";
import { PDFError } from "../src/errors.js";
import { createValidPdf, FAKE_CMS } from "./conftest.js";

// -- Helpers ------------------------------------------------------------------

/**
 * Prepare a signed PDF with FAKE_CMS inserted. Returns the signed PDF bytes,
 * the hex offsets, and the ByteRange hash computed before CMS insertion.
 */
async function createSignedPdf(): Promise<{
  signedPdf: Uint8Array;
  hexStart: number;
  hexLen: number;
  byterangeHash: Uint8Array;
}> {
  const pdfBytes = await createValidPdf();
  const prepared = await preparePdfWithSigField(pdfBytes, { visible: false });
  const byterangeHash = computeByterangeHash(prepared.pdf, prepared.hexStart, prepared.hexLen);
  const signedPdf = insertCms(prepared.pdf, prepared.hexStart, prepared.hexLen, FAKE_CMS);
  return { signedPdf, hexStart: prepared.hexStart, hexLen: prepared.hexLen, byterangeHash };
}

/**
 * Build a CMS blob that is too small to pass MIN_CMS_SIZE but starts with 0x30.
 */
function buildTinyCms(): Uint8Array {
  return new Uint8Array([0x30, 0x01, 0xab]);
}

/**
 * Build a CMS blob that does NOT start with ASN.1 SEQUENCE (0x30).
 */
function buildBadTagCms(): Uint8Array {
  const blob = new Uint8Array(200);
  blob[0] = 0xff;
  blob.fill(0xab, 1);
  return blob;
}

/**
 * Corrupt a signed PDF to make pdf-lib fail to load it, while keeping
 * ByteRange and CMS data intact. Overwrites the original PDF header
 * (first 5 bytes: "%PDF-") with garbage.
 */
function corruptPdfForPdfLib(signedPdf: Uint8Array): Uint8Array {
  const corrupted = new Uint8Array(signedPdf);
  // Overwrite the %PDF- header magic bytes to break pdf-lib
  corrupted[0] = 0x00;
  corrupted[1] = 0x00;
  corrupted[2] = 0x00;
  corrupted[3] = 0x00;
  corrupted[4] = 0x00;
  return corrupted;
}

/**
 * OID constants for building CMS structures.
 */
const OID_SIGNED_DATA = "1.2.840.113549.1.7.2";
const OID_DATA = "1.2.840.113549.1.7.1";
const OID_SHA1 = "1.3.14.3.2.26";
const OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4";

/**
 * Build a minimal but structurally valid CMS/PKCS#7 SignedData blob
 * that contains a SignerInfo with a messageDigest attribute.
 *
 * This allows testing the digest verification paths in verify.ts.
 */
function buildCmsWithDigest(messageDigest: Uint8Array): Uint8Array {
  // Build the messageDigest attribute
  const digestOctetString = new asn1js.OctetString({
    valueHex: messageDigest.buffer.slice(
      messageDigest.byteOffset,
      messageDigest.byteOffset + messageDigest.byteLength,
    ),
  });

  const messageDigestAttr = new pkijs.Attribute({
    type: OID_MESSAGE_DIGEST,
    values: [digestOctetString],
  });

  // Build SignerInfo with SHA-1 algorithm and signed attributes
  const signerInfo = new pkijs.SignerInfo({
    version: 1,
    sid: new pkijs.IssuerAndSerialNumber({
      issuer: new pkijs.RelativeDistinguishedNames(),
      serialNumber: new asn1js.Integer({ value: 1 }),
    }),
    digestAlgorithm: new pkijs.AlgorithmIdentifier({
      algorithmId: OID_SHA1,
    }),
    signedAttrs: new pkijs.SignedAndUnsignedAttributes({
      type: 0,
      attributes: [messageDigestAttr],
    }),
    signatureAlgorithm: new pkijs.AlgorithmIdentifier({
      algorithmId: "1.2.840.113549.1.1.1", // rsaEncryption
    }),
    signature: new asn1js.OctetString({ valueHex: new ArrayBuffer(128) }),
  });

  // Build SignedData
  const signedData = new pkijs.SignedData({
    version: 1,
    digestAlgorithms: [new pkijs.AlgorithmIdentifier({ algorithmId: OID_SHA1 })],
    encapContentInfo: new pkijs.EncapsulatedContentInfo({
      eContentType: OID_DATA,
    }),
    signerInfos: [signerInfo],
  });

  // Wrap in ContentInfo
  const contentInfo = new pkijs.ContentInfo({
    contentType: OID_SIGNED_DATA,
    content: signedData.toSchema(true),
  });

  const berBytes = contentInfo.toSchema().toBER(false);
  return new Uint8Array(berBytes);
}

/**
 * Build a self-signed X.509 certificate for testing.
 * Constructs the ASN.1 structure directly because pkijs.Certificate.toSchema()
 * requires internal fields that are only set during crypto operations.
 * The certificate is structurally valid for parsing but cryptographically fake.
 */
function buildTestCertificate(cn: string): pkijs.Certificate {
  const OID_CN = "2.5.4.3";

  // Build TBSCertificate as raw ASN.1
  const tbsCertificate = new asn1js.Sequence({
    value: [
      // version [0] EXPLICIT INTEGER (v3 = 2)
      new asn1js.Constructed({
        idBlock: { tagClass: 3, tagNumber: 0 },
        value: [new asn1js.Integer({ value: 2 })],
      }),
      // serialNumber
      new asn1js.Integer({ value: 1 }),
      // signature algorithm (sha1WithRSAEncryption)
      new asn1js.Sequence({
        value: [new asn1js.ObjectIdentifier({ value: "1.2.840.113549.1.1.5" })],
      }),
      // issuer (CN=cn)
      new asn1js.Sequence({
        value: [
          new asn1js.Set({
            value: [
              new asn1js.Sequence({
                value: [
                  new asn1js.ObjectIdentifier({ value: OID_CN }),
                  new asn1js.Utf8String({ value: cn }),
                ],
              }),
            ],
          }),
        ],
      }),
      // validity
      new asn1js.Sequence({
        value: [
          new asn1js.UTCTime({ valueDate: new Date("2020-01-01T00:00:00Z") }),
          new asn1js.UTCTime({ valueDate: new Date("2050-01-01T00:00:00Z") }),
        ],
      }),
      // subject (CN=cn)
      new asn1js.Sequence({
        value: [
          new asn1js.Set({
            value: [
              new asn1js.Sequence({
                value: [
                  new asn1js.ObjectIdentifier({ value: OID_CN }),
                  new asn1js.Utf8String({ value: cn }),
                ],
              }),
            ],
          }),
        ],
      }),
      // subjectPublicKeyInfo (fake RSA key)
      new asn1js.Sequence({
        value: [
          new asn1js.Sequence({
            value: [
              new asn1js.ObjectIdentifier({
                value: "1.2.840.113549.1.1.1",
              }),
              new asn1js.Null(),
            ],
          }),
          new asn1js.BitString({ valueHex: new ArrayBuffer(128) }),
        ],
      }),
    ],
  });

  // Full certificate: SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
  const certAsn1 = new asn1js.Sequence({
    value: [
      tbsCertificate,
      new asn1js.Sequence({
        value: [new asn1js.ObjectIdentifier({ value: "1.2.840.113549.1.1.5" })],
      }),
      new asn1js.BitString({ valueHex: new ArrayBuffer(128) }),
    ],
  });

  // Serialize to DER and parse back into pkijs.Certificate
  const certDer = certAsn1.toBER(false);
  const asn1Result = asn1js.fromBER(certDer);
  return new pkijs.Certificate({ schema: asn1Result.result });
}

/**
 * Build a CMS blob with a messageDigest AND an embedded certificate.
 * This allows testing the signer name extraction path.
 */
function buildCmsWithDigestAndCert(messageDigest: Uint8Array, signerName: string): Uint8Array {
  const digestOctetString = new asn1js.OctetString({
    valueHex: messageDigest.buffer.slice(
      messageDigest.byteOffset,
      messageDigest.byteOffset + messageDigest.byteLength,
    ),
  });

  const messageDigestAttr = new pkijs.Attribute({
    type: OID_MESSAGE_DIGEST,
    values: [digestOctetString],
  });

  const signerInfo = new pkijs.SignerInfo({
    version: 1,
    sid: new pkijs.IssuerAndSerialNumber({
      issuer: new pkijs.RelativeDistinguishedNames(),
      serialNumber: new asn1js.Integer({ value: 1 }),
    }),
    digestAlgorithm: new pkijs.AlgorithmIdentifier({
      algorithmId: OID_SHA1,
    }),
    signedAttrs: new pkijs.SignedAndUnsignedAttributes({
      type: 0,
      attributes: [messageDigestAttr],
    }),
    signatureAlgorithm: new pkijs.AlgorithmIdentifier({
      algorithmId: "1.2.840.113549.1.1.1",
    }),
    signature: new asn1js.OctetString({ valueHex: new ArrayBuffer(128) }),
  });

  const cert = buildTestCertificate(signerName);

  const signedData = new pkijs.SignedData({
    version: 1,
    digestAlgorithms: [new pkijs.AlgorithmIdentifier({ algorithmId: OID_SHA1 })],
    encapContentInfo: new pkijs.EncapsulatedContentInfo({
      eContentType: OID_DATA,
    }),
    signerInfos: [signerInfo],
    certificates: [cert],
  });

  const contentInfo = new pkijs.ContentInfo({
    contentType: OID_SIGNED_DATA,
    content: signedData.toSchema(true),
  });

  const berBytes = contentInfo.toSchema().toBER(false);
  return new Uint8Array(berBytes);
}

// =============================================================================
// verifyEmbeddedSignature
// =============================================================================

describe("verifyEmbeddedSignature", () => {
  it("returns invalid for unsigned PDF", async () => {
    const pdf = new TextEncoder().encode("%PDF-1.7\nHello World");
    const result = await verifyEmbeddedSignature(new Uint8Array(pdf));
    expect(result.valid).toBe(false);
    expect(result.structureOk).toBe(false);
    expect(result.details.length).toBeGreaterThan(0);
    expect(result.details[0]).toContain("No /ByteRange");
  });

  it("returns invalid for non-PDF content", async () => {
    const garbage = new Uint8Array([0x00, 0x01, 0x02, 0x03]);
    const result = await verifyEmbeddedSignature(garbage);
    expect(result.valid).toBe(false);
  });

  it("verifies structure of a prepared+inserted PDF", async () => {
    const { signedPdf } = await createSignedPdf();
    const result = await verifyEmbeddedSignature(signedPdf);

    // FAKE_CMS starts with 0x30 and is large enough, so structure is OK
    expect(result.structureOk).toBe(true);
    // Hash won't match because FAKE_CMS has no real messageDigest
    expect(result.hashOk).toBe(false);
    expect(result.valid).toBe(false);

    // Should report ByteRange OK
    const byteRangeDetail = result.details.find((d) => d.includes("ByteRange OK"));
    expect(byteRangeDetail).toBeDefined();

    // Should report valid ASN.1
    const asnDetail = result.details.find((d) => d.includes("valid ASN.1"));
    expect(asnDetail).toBeDefined();

    // Should include pdf-lib structural check
    const pdfLibDetail = result.details.find((d) => d.includes("pdf-lib"));
    expect(pdfLibDetail).toBeDefined();
  });

  it("reports CMS blob size in details", async () => {
    const { signedPdf } = await createSignedPdf();
    const result = await verifyEmbeddedSignature(signedPdf);

    const cmsDetail = result.details.find((d) => d.includes("CMS blob:"));
    expect(cmsDetail).toBeDefined();
    if (cmsDetail !== undefined) {
      expect(cmsDetail).toContain("bytes");
    }
  });

  it("returns signer as null for FAKE_CMS (no real cert)", async () => {
    const { signedPdf } = await createSignedPdf();
    const result = await verifyEmbeddedSignature(signedPdf);
    // FAKE_CMS has no embedded certificate, so signer should be null
    expect(result.signer).toBeNull();
  });

  // -- expectedHash path (post-sign verification) --

  it("returns hashOk=true when expectedHash matches ByteRange SHA-1", async () => {
    const { signedPdf, byterangeHash } = await createSignedPdf();
    const result = await verifyEmbeddedSignature(signedPdf, byterangeHash);

    expect(result.structureOk).toBe(true);
    expect(result.hashOk).toBe(true);
    expect(result.valid).toBe(true);

    const hashDetail = result.details.find((d) => d.includes("Hash OK"));
    expect(hashDetail).toBeDefined();
    if (hashDetail !== undefined) {
      expect(hashDetail).toContain("SHA-1 matches expected");
    }
  });

  it("returns hashOk=false when expectedHash does not match", async () => {
    const { signedPdf } = await createSignedPdf();
    const wrongHash = new Uint8Array(20).fill(0xff);
    const result = await verifyEmbeddedSignature(signedPdf, wrongHash);

    expect(result.structureOk).toBe(true);
    expect(result.hashOk).toBe(false);
    expect(result.valid).toBe(false);

    const mismatchDetail = result.details.find((d) => d.includes("Hash MISMATCH"));
    expect(mismatchDetail).toBeDefined();
    if (mismatchDetail !== undefined) {
      expect(mismatchDetail).toContain("ByteRange SHA-1");
      expect(mismatchDetail).toContain("Expected");
    }
  });

  it("validates hash with correct hash computed from signed PDF", async () => {
    // Verify that the hash computed from the signed PDF matches what we passed
    const { signedPdf, hexStart, hexLen, byterangeHash } = await createSignedPdf();

    // Recompute the hash from the signed PDF directly
    const recomputedHash = computeByterangeHash(signedPdf, hexStart, hexLen);
    expect(Buffer.from(recomputedHash).equals(Buffer.from(byterangeHash))).toBe(true);

    // And verify succeeds
    const result = await verifyEmbeddedSignature(signedPdf, recomputedHash);
    expect(result.valid).toBe(true);
  });

  // -- Standalone verification (no expectedHash) --

  it("falls through to CMS digest extraction when no expectedHash", async () => {
    const { signedPdf } = await createSignedPdf();
    // No expectedHash passed -- verify will try to extract digest from CMS
    const result = await verifyEmbeddedSignature(signedPdf);

    // FAKE_CMS has no real SignerInfo, so extractDigestInfo returns null.
    // But CMS is structurally valid (0x30, large enough), so the
    // "non-standard CMS" path fires: hash computed but cannot verify.
    expect(result.structureOk).toBe(true);
    expect(result.hashOk).toBe(false);

    const hashComputedDetail = result.details.find(
      (d) => d.includes("Hash computed") || d.includes("cannot verify"),
    );
    expect(hashComputedDetail).toBeDefined();
  });

  // -- CMS structure edge cases --

  it("reports CMS too small for embedded signature", async () => {
    const pdfBytes = await createValidPdf();
    const prepared = await preparePdfWithSigField(pdfBytes, { visible: false });
    const tinyCms = buildTinyCms();
    const signed = insertCms(prepared.pdf, prepared.hexStart, prepared.hexLen, tinyCms);

    const result = await verifyEmbeddedSignature(signed);
    expect(result.structureOk).toBe(false);

    const tooSmallDetail = result.details.find((d) => d.includes("CMS too small"));
    expect(tooSmallDetail).toBeDefined();
  });

  it("reports structure error when CMS has wrong ASN.1 tag in embedded PDF", async () => {
    // When CMS hex doesn't start with 0x30, extractDerFromPaddedHex throws,
    // causing a structure error at extraction time (before the tag check).
    const pdfBytes = await createValidPdf();
    const prepared = await preparePdfWithSigField(pdfBytes, { visible: false });
    const badCms = buildBadTagCms();
    const signed = insertCms(prepared.pdf, prepared.hexStart, prepared.hexLen, badCms);

    const result = await verifyEmbeddedSignature(signed);
    expect(result.structureOk).toBe(false);
    expect(result.valid).toBe(false);

    // The error is caught as a structure error from extraction
    const structureDetail = result.details.find((d) => d.includes("Structure error"));
    expect(structureDetail).toBeDefined();
  });

  it("takes suspect CMS path for detached signature with bad tag", async () => {
    // The "CMS is suspect" path in verifySignatureMatch requires both:
    // - cmsDer successfully extracted (which enforces 0x30 tag)
    // - cmsDer[0] !== ASN1_SEQUENCE_TAG
    // This combination is unreachable for embedded sigs. But the "suspect"
    // message IS reachable through verifyDetachedSignature instead.
    // Here we test the detached path for bad tag CMS.
    const data = new TextEncoder().encode("test data");
    const badCms = buildBadTagCms();
    const result = await verifyDetachedSignature(data, badCms);

    expect(result.structureOk).toBe(false);
    expect(result.hashOk).toBe(false);
    expect(result.valid).toBe(false);

    const tagDetail = result.details.find((d) => d.includes("does not start with ASN.1 SEQUENCE"));
    expect(tagDetail).toBeDefined();
  });

  it("non-standard CMS computes SHA-1 but cannot verify", async () => {
    // FAKE_CMS starts with 0x30 and is >= MIN_CMS_SIZE, but extractDigestInfo
    // returns null. This triggers the "non-standard CMS" path.
    const { signedPdf } = await createSignedPdf();
    const result = await verifyEmbeddedSignature(signedPdf);

    expect(result.structureOk).toBe(true);
    const hashDetail = result.details.find(
      (d) => d.includes("SHA-1") && d.includes("cannot verify"),
    );
    expect(hashDetail).toBeDefined();
  });

  // -- pdf-lib structural check --

  it("includes pdf-lib page count in details", async () => {
    const { signedPdf } = await createSignedPdf();
    const result = await verifyEmbeddedSignature(signedPdf);

    const pdfLibDetail = result.details.find((d) => d.includes("pdf-lib"));
    expect(pdfLibDetail).toBeDefined();
    if (pdfLibDetail !== undefined) {
      expect(pdfLibDetail).toContain("1 page(s)");
    }
  });

  it("includes pdf-lib structural warning for corrupt PDF structure", async () => {
    const { signedPdf } = await createSignedPdf();
    const corrupted = corruptPdfForPdfLib(signedPdf);

    const result = await verifyEmbeddedSignature(corrupted);
    // Signature verification still works (ByteRange extraction is regex-based)
    expect(result.structureOk).toBe(true);

    // pdf-lib should report a warning
    const pdfLibDetail = result.details.find((d) => d.includes("pdf-lib: structural warning"));
    expect(pdfLibDetail).toBeDefined();
  });
});

// =============================================================================
// verifyAllEmbeddedSignatures
// =============================================================================

describe("verifyAllEmbeddedSignatures", () => {
  it("throws on unsigned PDF", async () => {
    const pdf = new TextEncoder().encode("%PDF-1.7\nHello World");
    await expect(verifyAllEmbeddedSignatures(pdf)).rejects.toThrow(PDFError);
  });

  it("returns results array for a single-signature PDF", async () => {
    const { signedPdf } = await createSignedPdf();
    const results = await verifyAllEmbeddedSignatures(signedPdf);

    expect(results.length).toBe(1);
    const first = results[0];
    expect(first).toBeDefined();
    if (first !== undefined) {
      expect(first.structureOk).toBe(true);
      // FAKE_CMS has no messageDigest, so hashOk is false
      expect(first.hashOk).toBe(false);
      expect(first.valid).toBe(false);

      // Should include ByteRange OK
      const byteRangeDetail = first.details.find((d) => d.includes("ByteRange OK"));
      expect(byteRangeDetail).toBeDefined();

      // Should include pdf-lib detail
      const pdfLibDetail = first.details.find((d) => d.includes("pdf-lib"));
      expect(pdfLibDetail).toBeDefined();
    }
  });

  it("includes pdf-lib page count in each result", async () => {
    const { signedPdf } = await createSignedPdf();
    const results = await verifyAllEmbeddedSignatures(signedPdf);

    for (const result of results) {
      const pdfLibDetail = result.details.find((d) => d.includes("pdf-lib"));
      expect(pdfLibDetail).toBeDefined();
      if (pdfLibDetail !== undefined) {
        expect(pdfLibDetail).toContain("1 page(s)");
      }
    }
  });

  it("verifies CMS structure for each signature", async () => {
    const { signedPdf } = await createSignedPdf();
    const results = await verifyAllEmbeddedSignatures(signedPdf);

    for (const result of results) {
      // FAKE_CMS passes structure checks
      expect(result.structureOk).toBe(true);
      const asnDetail = result.details.find((d) => d.includes("valid ASN.1"));
      expect(asnDetail).toBeDefined();
    }
  });

  it("reports signer as null for fake CMS in all results", async () => {
    const { signedPdf } = await createSignedPdf();
    const results = await verifyAllEmbeddedSignatures(signedPdf);

    for (const result of results) {
      expect(result.signer).toBeNull();
    }
  });

  it("verifies with multiple ByteRange markers in PDF", async () => {
    // Create a PDF that has two ByteRange arrays by signing twice
    const pdfBytes = await createValidPdf();
    const firstPrepared = await preparePdfWithSigField(pdfBytes, { visible: false });
    const firstSigned = insertCms(
      firstPrepared.pdf,
      firstPrepared.hexStart,
      firstPrepared.hexLen,
      FAKE_CMS,
    );

    // Sign again (incremental update on top of first signature)
    const secondPrepared = await preparePdfWithSigField(firstSigned, { visible: false });
    const doubleSigned = insertCms(
      secondPrepared.pdf,
      secondPrepared.hexStart,
      secondPrepared.hexLen,
      FAKE_CMS,
    );

    const results = await verifyAllEmbeddedSignatures(doubleSigned);
    expect(results.length).toBe(2);

    // Both should have valid structure
    for (const result of results) {
      expect(result.structureOk).toBe(true);
    }
  });

  it("includes pdf-lib structural warning when PDF is corrupted", async () => {
    const { signedPdf } = await createSignedPdf();
    const corrupted = corruptPdfForPdfLib(signedPdf);

    const results = await verifyAllEmbeddedSignatures(corrupted);
    expect(results.length).toBe(1);

    const first = results[0];
    expect(first).toBeDefined();
    if (first !== undefined) {
      const pdfLibDetail = first.details.find((d) => d.includes("pdf-lib: structural warning"));
      expect(pdfLibDetail).toBeDefined();
    }
  });
});

// =============================================================================
// verifyDetachedSignature
// =============================================================================

describe("verifyDetachedSignature", () => {
  it("returns invalid for mismatched data/signature", async () => {
    const data = new TextEncoder().encode("test data");
    // Use a minimal but structurally valid CMS blob
    const cms = FAKE_CMS;
    const result = await verifyDetachedSignature(data, cms);
    // Structure should be OK (starts with 0x30, length > MIN)
    expect(result.structureOk).toBe(true);
    // Hash won't match since the CMS is fake
    expect(result.valid).toBe(false);
  });

  it("detects corrupt CMS", async () => {
    const data = new TextEncoder().encode("test data");
    const badCms = new Uint8Array([0xff, 0x01]); // Not an ASN.1 SEQUENCE
    const result = await verifyDetachedSignature(data, badCms);
    expect(result.structureOk).toBe(false);
    expect(result.valid).toBe(false);
  });

  it("detects too-small CMS", async () => {
    const data = new TextEncoder().encode("test data");
    const tinyCms = new Uint8Array([0x30, 0x01]); // Valid tag but tiny
    const result = await verifyDetachedSignature(data, tinyCms);
    expect(result.structureOk).toBe(false);
    expect(result.valid).toBe(false);
  });

  it("reports CMS too small detail message", async () => {
    const data = new TextEncoder().encode("test data");
    const tinyCms = new Uint8Array([0x30, 0x01]);
    const result = await verifyDetachedSignature(data, tinyCms);

    const detail = result.details.find((d) => d.includes("CMS too small"));
    expect(detail).toBeDefined();
    if (detail !== undefined) {
      expect(detail).toContain("bytes");
      expect(detail).toContain("likely corrupt");
    }
  });

  it("reports wrong ASN.1 tag detail message", async () => {
    const data = new TextEncoder().encode("test data");
    const badCms = buildBadTagCms();
    const result = await verifyDetachedSignature(data, badCms);

    const detail = result.details.find((d) => d.includes("does not start with ASN.1 SEQUENCE"));
    expect(detail).toBeDefined();
  });

  it("reports valid ASN.1 structure for properly sized CMS", async () => {
    const data = new TextEncoder().encode("test data");
    const result = await verifyDetachedSignature(data, FAKE_CMS);

    const detail = result.details.find((d) => d.includes("valid ASN.1"));
    expect(detail).toBeDefined();
    if (detail !== undefined) {
      expect(detail).toContain(`${FAKE_CMS.length} bytes`);
    }
  });

  it("reports digest info unavailable for FAKE_CMS", async () => {
    const data = new TextEncoder().encode("test data");
    const result = await verifyDetachedSignature(data, FAKE_CMS);

    // extractDigestInfo returns null for FAKE_CMS, so we get the fallback message
    const detail = result.details.find((d) => d.includes("Could not extract digest info"));
    expect(detail).toBeDefined();
  });

  it("returns signer as null for FAKE_CMS", async () => {
    const data = new TextEncoder().encode("test data");
    const result = await verifyDetachedSignature(data, FAKE_CMS);
    expect(result.signer).toBeNull();
  });

  it("valid field is always structureOk AND hashOk", async () => {
    const data = new TextEncoder().encode("test data");

    // Case 1: structure bad, hash bad
    const badResult = await verifyDetachedSignature(data, new Uint8Array([0xff, 0x01]));
    expect(badResult.valid).toBe(false);
    expect(badResult.structureOk).toBe(false);
    expect(badResult.hashOk).toBe(false);

    // Case 2: structure ok, hash bad
    const structOnlyResult = await verifyDetachedSignature(data, FAKE_CMS);
    expect(structOnlyResult.valid).toBe(false);
    expect(structOnlyResult.structureOk).toBe(true);
    expect(structOnlyResult.hashOk).toBe(false);
  });
});

// =============================================================================
// verifySignatureMatch -- structure error handling (tested via verifyEmbeddedSignature)
// =============================================================================

describe("verifySignatureMatch structure errors", () => {
  it("handles ByteRange extraction failure gracefully", async () => {
    // Construct a PDF with a ByteRange that points to invalid offsets
    // This will cause extractSignatureDataFromMatch to throw
    const badContent = "%PDF-1.7\n" + "/ByteRange [0 50 99999 100]\n" + "%%EOF\n";
    const pdf = new TextEncoder().encode(badContent);

    const result = await verifyEmbeddedSignature(new Uint8Array(pdf));
    expect(result.valid).toBe(false);
    expect(result.structureOk).toBe(false);

    const structureDetail = result.details.find((d) => d.includes("Structure error"));
    expect(structureDetail).toBeDefined();
  });

  it("handles ByteRange with off1 != 0 gracefully", async () => {
    // Build a PDF with off1 != 0 which will be rejected by extractSignatureDataFromMatch
    const badContent = "%PDF-1.7\n" + "/ByteRange [5 50 100 50]\n" + "%%EOF\n";
    const pdf = new TextEncoder().encode(badContent);

    const result = await verifyEmbeddedSignature(new Uint8Array(pdf));
    expect(result.valid).toBe(false);
    expect(result.structureOk).toBe(false);
    expect(result.signer).toBeNull();
    expect(result.hashOk).toBe(false);
  });
});

// =============================================================================
// toNodeCryptoName (tested indirectly via verify paths)
// =============================================================================

describe("toNodeCryptoName via hash verification", () => {
  it("handles SHA-1 algorithm name correctly in expectedHash path", async () => {
    // The expectedHash path always uses SHA-1 (createHash("sha1"))
    // Verify that the hash computed matches what Node.js SHA-1 produces
    const { signedPdf, byterangeHash } = await createSignedPdf();

    // Manually compute what we expect
    const result = await verifyEmbeddedSignature(signedPdf, byterangeHash);
    expect(result.hashOk).toBe(true);

    const hashDetail = result.details.find((d) => d.includes("SHA-1"));
    expect(hashDetail).toBeDefined();
  });
});

// =============================================================================
// bytesEqual (tested indirectly)
// =============================================================================

describe("bytesEqual via hash comparison", () => {
  it("detects equal hashes", async () => {
    const { signedPdf, byterangeHash } = await createSignedPdf();
    const result = await verifyEmbeddedSignature(signedPdf, byterangeHash);
    expect(result.hashOk).toBe(true);
  });

  it("detects different-length hashes as mismatch", async () => {
    const { signedPdf } = await createSignedPdf();
    // SHA-1 produces 20 bytes; pass a 16-byte hash
    const shortHash = new Uint8Array(16).fill(0xaa);
    const result = await verifyEmbeddedSignature(signedPdf, shortHash);
    expect(result.hashOk).toBe(false);
  });

  it("detects different-content same-length hashes as mismatch", async () => {
    const { signedPdf } = await createSignedPdf();
    const wrongHash = new Uint8Array(20).fill(0x00);
    const result = await verifyEmbeddedSignature(signedPdf, wrongHash);
    expect(result.hashOk).toBe(false);
  });
});

// =============================================================================
// Integration: full round-trip with expectedHash
// =============================================================================

describe("full round-trip verification", () => {
  it("prepare -> compute hash -> insert CMS -> verify with expected hash", async () => {
    const pdfBytes = await createValidPdf();
    const prepared = await preparePdfWithSigField(pdfBytes, { visible: false });

    // Compute the ByteRange hash before inserting CMS
    const expectedHash = computeByterangeHash(prepared.pdf, prepared.hexStart, prepared.hexLen);
    expect(expectedHash.length).toBe(20);

    // Insert FAKE_CMS
    const signed = insertCms(prepared.pdf, prepared.hexStart, prepared.hexLen, FAKE_CMS);

    // Verify with expected hash -- should succeed because ByteRange excludes hex content
    const result = await verifyEmbeddedSignature(signed, expectedHash);
    expect(result.structureOk).toBe(true);
    expect(result.hashOk).toBe(true);
    expect(result.valid).toBe(true);

    // Verify details contain expected messages
    expect(result.details.some((d) => d.includes("ByteRange OK"))).toBe(true);
    expect(result.details.some((d) => d.includes("Hash OK"))).toBe(true);
    expect(result.details.some((d) => d.includes("pdf-lib"))).toBe(true);
  });

  it("ByteRange hash is stable regardless of CMS content", async () => {
    const pdfBytes = await createValidPdf();
    const prepared = await preparePdfWithSigField(pdfBytes, { visible: false });

    const hashBefore = computeByterangeHash(prepared.pdf, prepared.hexStart, prepared.hexLen);

    // Insert different CMS blobs and verify hash stays the same
    const signed1 = insertCms(prepared.pdf, prepared.hexStart, prepared.hexLen, FAKE_CMS);
    const hash1 = computeByterangeHash(signed1, prepared.hexStart, prepared.hexLen);

    const altCms = new Uint8Array(FAKE_CMS.length);
    altCms[0] = 0x30;
    altCms.fill(0xcd, 1);
    const signed2 = insertCms(prepared.pdf, prepared.hexStart, prepared.hexLen, altCms);
    const hash2 = computeByterangeHash(signed2, prepared.hexStart, prepared.hexLen);

    expect(Buffer.from(hashBefore).equals(Buffer.from(hash1))).toBe(true);
    expect(Buffer.from(hashBefore).equals(Buffer.from(hash2))).toBe(true);
  });

  it("verifyAll returns consistent results for double-signed PDF", async () => {
    const pdfBytes = await createValidPdf();

    // First signature
    const first = await preparePdfWithSigField(pdfBytes, { visible: false });
    const firstSigned = insertCms(first.pdf, first.hexStart, first.hexLen, FAKE_CMS);

    // Second signature (incremental update)
    const second = await preparePdfWithSigField(firstSigned, { visible: false });
    const doubleSigned = insertCms(second.pdf, second.hexStart, second.hexLen, FAKE_CMS);

    // verifyEmbeddedSignature checks only the last signature
    const singleResult = await verifyEmbeddedSignature(doubleSigned);
    expect(singleResult.structureOk).toBe(true);

    // verifyAllEmbeddedSignatures checks all signatures
    const allResults = await verifyAllEmbeddedSignatures(doubleSigned);
    expect(allResults.length).toBe(2);

    // Both should have valid structure since FAKE_CMS passes structure checks
    for (const result of allResults) {
      expect(result.structureOk).toBe(true);
      expect(result.hashOk).toBe(false);
    }
  });

  it("verifyEmbeddedSignature always checks last ByteRange", async () => {
    const pdfBytes = await createValidPdf();

    // First signature
    const first = await preparePdfWithSigField(pdfBytes, { visible: false });
    const firstHash = computeByterangeHash(first.pdf, first.hexStart, first.hexLen);
    const firstSigned = insertCms(first.pdf, first.hexStart, first.hexLen, FAKE_CMS);

    // Second signature
    const second = await preparePdfWithSigField(firstSigned, { visible: false });
    const secondHash = computeByterangeHash(second.pdf, second.hexStart, second.hexLen);
    const doubleSigned = insertCms(second.pdf, second.hexStart, second.hexLen, FAKE_CMS);

    // verifyEmbeddedSignature with the SECOND hash should succeed (it checks last)
    const resultWithSecondHash = await verifyEmbeddedSignature(doubleSigned, secondHash);
    expect(resultWithSecondHash.hashOk).toBe(true);
    expect(resultWithSecondHash.valid).toBe(true);

    // verifyEmbeddedSignature with the FIRST hash should fail (it doesn't match last)
    const resultWithFirstHash = await verifyEmbeddedSignature(doubleSigned, firstHash);
    expect(resultWithFirstHash.hashOk).toBe(false);
    expect(resultWithFirstHash.valid).toBe(false);
  });
});

// =============================================================================
// Edge cases: tiny CMS and bad CMS in embedded verification
// =============================================================================

describe("embedded verification with CMS edge cases", () => {
  it("tiny CMS triggers suspect path with no expectedHash", async () => {
    const pdfBytes = await createValidPdf();
    const prepared = await preparePdfWithSigField(pdfBytes, { visible: false });
    const tinyCms = buildTinyCms();
    const signed = insertCms(prepared.pdf, prepared.hexStart, prepared.hexLen, tinyCms);

    const result = await verifyEmbeddedSignature(signed);
    expect(result.structureOk).toBe(false);
    expect(result.hashOk).toBe(false);
    expect(result.valid).toBe(false);

    // Should include "CMS is suspect" since structure is bad and no digestInfo
    const suspectDetail = result.details.find((d) => d.includes("CMS is suspect"));
    expect(suspectDetail).toBeDefined();
  });

  it("tiny CMS with expectedHash still verifies hash correctly", async () => {
    const pdfBytes = await createValidPdf();
    const prepared = await preparePdfWithSigField(pdfBytes, { visible: false });
    const expectedHash = computeByterangeHash(prepared.pdf, prepared.hexStart, prepared.hexLen);
    const tinyCms = buildTinyCms();
    const signed = insertCms(prepared.pdf, prepared.hexStart, prepared.hexLen, tinyCms);

    const result = await verifyEmbeddedSignature(signed, expectedHash);
    // Structure is bad (CMS too small)
    expect(result.structureOk).toBe(false);
    // But hash should still match since expectedHash path is independent
    expect(result.hashOk).toBe(true);
    // Overall invalid because structure is bad
    expect(result.valid).toBe(false);
  });

  it("bad tag CMS causes extraction failure even with expectedHash", async () => {
    // When CMS hex doesn't start with 0x30, extractDerFromPaddedHex throws
    // before any hash verification can happen. The entire verification fails
    // as a structure error.
    const pdfBytes = await createValidPdf();
    const prepared = await preparePdfWithSigField(pdfBytes, { visible: false });
    const expectedHash = computeByterangeHash(prepared.pdf, prepared.hexStart, prepared.hexLen);
    const badCms = buildBadTagCms();
    const signed = insertCms(prepared.pdf, prepared.hexStart, prepared.hexLen, badCms);

    const result = await verifyEmbeddedSignature(signed, expectedHash);
    expect(result.structureOk).toBe(false);
    expect(result.hashOk).toBe(false);
    expect(result.valid).toBe(false);

    const structureDetail = result.details.find((d) => d.includes("Structure error"));
    expect(structureDetail).toBeDefined();
  });
});

// =============================================================================
// Digest verification with real CMS structures
// =============================================================================

describe("embedded verification with real CMS digest", () => {
  it("returns hashOk=true when CMS messageDigest matches ByteRange hash", async () => {
    const pdfBytes = await createValidPdf();
    const prepared = await preparePdfWithSigField(pdfBytes, { visible: false });

    // Compute the ByteRange SHA-1 hash
    const byterangeHash = computeByterangeHash(prepared.pdf, prepared.hexStart, prepared.hexLen);

    // Build a CMS with the correct messageDigest
    const cms = buildCmsWithDigest(byterangeHash);
    const signed = insertCms(prepared.pdf, prepared.hexStart, prepared.hexLen, cms);

    // Verify without expectedHash -- should use CMS digest extraction path
    const result = await verifyEmbeddedSignature(signed);
    expect(result.structureOk).toBe(true);
    expect(result.hashOk).toBe(true);
    expect(result.valid).toBe(true);

    const hashDetail = result.details.find(
      (d) => d.includes("Hash OK") && d.includes("SHA-1") && d.includes("CMS messageDigest"),
    );
    expect(hashDetail).toBeDefined();
  });

  it("returns hashOk=false when CMS messageDigest does not match", async () => {
    const pdfBytes = await createValidPdf();
    const prepared = await preparePdfWithSigField(pdfBytes, { visible: false });

    // Build CMS with an INCORRECT digest
    const wrongDigest = new Uint8Array(20).fill(0xbb);
    const cms = buildCmsWithDigest(wrongDigest);
    const signed = insertCms(prepared.pdf, prepared.hexStart, prepared.hexLen, cms);

    const result = await verifyEmbeddedSignature(signed);
    expect(result.structureOk).toBe(true);
    expect(result.hashOk).toBe(false);
    expect(result.valid).toBe(false);

    const mismatchDetail = result.details.find((d) => d.includes("Hash MISMATCH"));
    expect(mismatchDetail).toBeDefined();
    if (mismatchDetail !== undefined) {
      expect(mismatchDetail).toContain("CMS messageDigest");
    }
  });

  it("uses algorithm name from CMS digestAlgorithm", async () => {
    const pdfBytes = await createValidPdf();
    const prepared = await preparePdfWithSigField(pdfBytes, { visible: false });
    const byterangeHash = computeByterangeHash(prepared.pdf, prepared.hexStart, prepared.hexLen);
    const cms = buildCmsWithDigest(byterangeHash);
    const signed = insertCms(prepared.pdf, prepared.hexStart, prepared.hexLen, cms);

    const result = await verifyEmbeddedSignature(signed);
    // The digest detail should include the algorithm name (SHA-1)
    const hashDetail = result.details.find((d) => d.includes("SHA-1"));
    expect(hashDetail).toBeDefined();
  });
});

describe("detached verification with real CMS digest", () => {
  it("returns hashOk=true when data hash matches CMS messageDigest", async () => {
    const data = new TextEncoder().encode("test data for detached signature");
    const dataHash = new Uint8Array(createHash("sha1").update(data).digest());

    const cms = buildCmsWithDigest(dataHash);
    const result = await verifyDetachedSignature(data, cms);

    expect(result.structureOk).toBe(true);
    expect(result.hashOk).toBe(true);
    expect(result.valid).toBe(true);

    const hashDetail = result.details.find(
      (d) => d.includes("Hash OK") && d.includes("CMS messageDigest"),
    );
    expect(hashDetail).toBeDefined();
  });

  it("returns hashOk=false when data hash does not match CMS messageDigest", async () => {
    const data = new TextEncoder().encode("test data for detached signature");
    const wrongDigest = new Uint8Array(20).fill(0xcc);

    const cms = buildCmsWithDigest(wrongDigest);
    const result = await verifyDetachedSignature(data, cms);

    expect(result.structureOk).toBe(true);
    expect(result.hashOk).toBe(false);
    expect(result.valid).toBe(false);

    const mismatchDetail = result.details.find((d) => d.includes("Hash MISMATCH"));
    expect(mismatchDetail).toBeDefined();
    if (mismatchDetail !== undefined) {
      expect(mismatchDetail).toContain("CMS messageDigest");
    }
  });

  it("includes algorithm name in hash mismatch details", async () => {
    const data = new TextEncoder().encode("test data");
    const wrongDigest = new Uint8Array(20).fill(0xdd);
    const cms = buildCmsWithDigest(wrongDigest);

    const result = await verifyDetachedSignature(data, cms);
    const mismatchDetail = result.details.find((d) => d.includes("Hash MISMATCH"));
    expect(mismatchDetail).toBeDefined();
    if (mismatchDetail !== undefined) {
      expect(mismatchDetail).toContain("SHA-1");
    }
  });
});

describe("verifyAllEmbeddedSignatures with real CMS digest", () => {
  it("validates hash for each signature independently", async () => {
    const pdfBytes = await createValidPdf();
    const prepared = await preparePdfWithSigField(pdfBytes, { visible: false });

    // Build CMS with the correct hash for this signature
    const hash = computeByterangeHash(prepared.pdf, prepared.hexStart, prepared.hexLen);
    const cms = buildCmsWithDigest(hash);
    const signed = insertCms(prepared.pdf, prepared.hexStart, prepared.hexLen, cms);

    const results = await verifyAllEmbeddedSignatures(signed);
    expect(results.length).toBe(1);

    const first = results[0];
    expect(first).toBeDefined();
    if (first !== undefined) {
      expect(first.structureOk).toBe(true);
      expect(first.hashOk).toBe(true);
      expect(first.valid).toBe(true);
    }
  });
});

// =============================================================================
// Signer name extraction (covers signer?.name branches)
// =============================================================================

describe("signer name extraction via embedded verification", () => {
  it("extracts signer name from CMS with embedded certificate", async () => {
    const pdfBytes = await createValidPdf();
    const prepared = await preparePdfWithSigField(pdfBytes, { visible: false });
    const byterangeHash = computeByterangeHash(prepared.pdf, prepared.hexStart, prepared.hexLen);

    const cms = buildCmsWithDigestAndCert(byterangeHash, "Test Signer");
    const signed = insertCms(prepared.pdf, prepared.hexStart, prepared.hexLen, cms);

    const result = await verifyEmbeddedSignature(signed);
    expect(result.structureOk).toBe(true);
    expect(result.hashOk).toBe(true);
    expect(result.valid).toBe(true);

    // Should have signer info
    expect(result.signer).not.toBeNull();
    if (result.signer !== null) {
      expect(result.signer.name).toBe("Test Signer");
    }

    // Should include signer name in details
    const signerDetail = result.details.find((d) => d.includes("Signer:"));
    expect(signerDetail).toBeDefined();
    if (signerDetail !== undefined) {
      expect(signerDetail).toContain("Test Signer");
    }
  });

  it("extracts signer name in detached signature verification", async () => {
    const data = new TextEncoder().encode("data for detached verification");
    const dataHash = new Uint8Array(createHash("sha1").update(data).digest());

    const cms = buildCmsWithDigestAndCert(dataHash, "Detached Signer");
    const result = await verifyDetachedSignature(data, cms);

    expect(result.structureOk).toBe(true);
    expect(result.hashOk).toBe(true);
    expect(result.valid).toBe(true);

    expect(result.signer).not.toBeNull();
    if (result.signer !== null) {
      expect(result.signer.name).toBe("Detached Signer");
    }

    const signerDetail = result.details.find((d) => d.includes("Signer:"));
    expect(signerDetail).toBeDefined();
  });

  it("extracts signer name in verifyAll with certificate CMS", async () => {
    const pdfBytes = await createValidPdf();
    const prepared = await preparePdfWithSigField(pdfBytes, { visible: false });
    const hash = computeByterangeHash(prepared.pdf, prepared.hexStart, prepared.hexLen);
    const cms = buildCmsWithDigestAndCert(hash, "All Sigs Signer");
    const signed = insertCms(prepared.pdf, prepared.hexStart, prepared.hexLen, cms);

    const results = await verifyAllEmbeddedSignatures(signed);
    expect(results.length).toBe(1);

    const first = results[0];
    expect(first).toBeDefined();
    if (first !== undefined) {
      expect(first.signer).not.toBeNull();
      if (first.signer !== null) {
        expect(first.signer.name).toBe("All Sigs Signer");
      }
    }
  });
});
