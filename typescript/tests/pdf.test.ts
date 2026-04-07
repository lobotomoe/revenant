/**
 * Comprehensive tests for PDF core operations: position, objects, asn1,
 * cms-extraction, cms-info, incremental updates, builder, render, and verify.
 */

import { unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import * as asn1js from "asn1js";
import { PDFDocument, PDFName, PDFRef, PDFString } from "pdf-lib";
import * as pkijs from "pkijs";
import { describe, expect, it } from "vitest";

import {
  ANNOT_FLAGS_SIG_WIDGET,
  ASN1_SEQUENCE_TAG,
  allocateSigObjects,
  assembleIncrementalUpdate,
  BYTERANGE_PLACEHOLDER,
  buildCatalogOverride,
  buildObjectOverride,
  buildPageOverride,
  buildXrefAndTrailer,
  buildXrefStream,
  CMS_HEX_SIZE,
  CMS_RESERVED_SIZE,
  computeByterangeHash,
  computeSigRect,
  extractCmsFromByterange,
  extractCmsFromByterangeMatch,
  extractDerFromPaddedHex,
  extractDigestInfo,
  extractSignatureData,
  extractSignatureDataFromMatch,
  findByteRanges,
  findPageObjNum,
  findPrevStartxref,
  findRootObjNum,
  getPageDimensions,
  insertCms,
  inspectCmsBlob,
  MIN_CMS_SIZE,
  parsePageSpec,
  patchByterange,
  pdfString,
  preparePdfWithSigField,
  resolveHashAlgo,
  resolvePageIndex,
  resolvePosition,
  SIG_HEIGHT,
  SIG_WIDTH,
  serializePdfObject,
  verifyAllEmbeddedSignatures,
  verifyDetachedSignature,
  verifyEmbeddedSignature,
} from "../src/core/pdf/index.js";
import {
  buildAnnotWidget,
  buildEmbeddedFontObjects,
  buildFormXobjects,
  buildInvisibleAnnotWidget,
  buildSigDict,
} from "../src/core/pdf/render.js";
import { PDFError } from "../src/errors.js";
import { createValidPdf, FAKE_CMS } from "./conftest.js";

// =============================================================================
// position.ts
// =============================================================================

describe("resolvePosition", () => {
  it("accepts all canonical names", () => {
    expect(resolvePosition("bottom-right")).toBe("bottom-right");
    expect(resolvePosition("top-right")).toBe("top-right");
    expect(resolvePosition("bottom-left")).toBe("bottom-left");
    expect(resolvePosition("top-left")).toBe("top-left");
    expect(resolvePosition("bottom-center")).toBe("bottom-center");
  });

  it("resolves all aliases", () => {
    expect(resolvePosition("br")).toBe("bottom-right");
    expect(resolvePosition("tr")).toBe("top-right");
    expect(resolvePosition("bl")).toBe("bottom-left");
    expect(resolvePosition("tl")).toBe("top-left");
    expect(resolvePosition("bc")).toBe("bottom-center");
  });

  it("is case-insensitive", () => {
    expect(resolvePosition("BR")).toBe("bottom-right");
    expect(resolvePosition("Bottom-Right")).toBe("bottom-right");
    expect(resolvePosition("BOTTOM-RIGHT")).toBe("bottom-right");
    expect(resolvePosition("Tl")).toBe("top-left");
  });

  it("trims whitespace", () => {
    expect(resolvePosition("  br  ")).toBe("bottom-right");
    expect(resolvePosition("\tbottom-center\n")).toBe("bottom-center");
  });

  it("throws on unknown position", () => {
    expect(() => resolvePosition("invalid")).toThrow(PDFError);
    expect(() => resolvePosition("center")).toThrow(PDFError);
    expect(() => resolvePosition("")).toThrow(PDFError);
    expect(() => resolvePosition("middle")).toThrow(PDFError);
  });

  it("includes valid options in error message", () => {
    try {
      resolvePosition("xyz");
      expect.fail("should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(PDFError);
      if (e instanceof PDFError) {
        expect(e.message).toContain("bottom-right");
        expect(e.message).toContain("br");
      }
    }
  });
});

describe("parsePageSpec", () => {
  it("returns 'first' and 'last' as strings", () => {
    expect(parsePageSpec("first")).toBe("first");
    expect(parsePageSpec("last")).toBe("last");
  });

  it("is case-insensitive for keywords", () => {
    expect(parsePageSpec("FIRST")).toBe("first");
    expect(parsePageSpec("LAST")).toBe("last");
    expect(parsePageSpec("First")).toBe("first");
  });

  it("converts 1-based page numbers to 0-based", () => {
    expect(parsePageSpec("1")).toBe(0);
    expect(parsePageSpec("5")).toBe(4);
    expect(parsePageSpec("100")).toBe(99);
  });

  it("throws on non-numeric invalid specs", () => {
    expect(() => parsePageSpec("abc")).toThrow(PDFError);
    expect(() => parsePageSpec("first-page")).toThrow(PDFError);
  });

  it("throws on zero page number", () => {
    expect(() => parsePageSpec("0")).toThrow(PDFError);
  });

  it("throws on negative page number", () => {
    expect(() => parsePageSpec("-1")).toThrow(PDFError);
    expect(() => parsePageSpec("-100")).toThrow(PDFError);
  });

  it("trims whitespace", () => {
    expect(parsePageSpec("  first  ")).toBe("first");
    expect(parsePageSpec("  3  ")).toBe(2);
  });
});

describe("computeSigRect", () => {
  const W = 612;
  const H = 792;

  it("computes bottom-right correctly", () => {
    const rect = computeSigRect(W, H, "bottom-right");
    expect(rect.width).toBe(SIG_WIDTH);
    expect(rect.height).toBe(SIG_HEIGHT);
    // x = pageWidth - marginH - sigW = 612 - 36 - 210 = 366
    expect(rect.x).toBe(366);
    // y = marginV = 60
    expect(rect.y).toBe(60);
  });

  it("computes top-right correctly", () => {
    const rect = computeSigRect(W, H, "top-right");
    expect(rect.x).toBe(366); // same x as bottom-right
    expect(rect.y).toBe(H - 60 - SIG_HEIGHT); // 792 - 60 - 70 = 662
  });

  it("computes bottom-left correctly", () => {
    const rect = computeSigRect(W, H, "bottom-left");
    expect(rect.x).toBe(36); // marginH
    expect(rect.y).toBe(60); // marginV
  });

  it("computes top-left correctly", () => {
    const rect = computeSigRect(W, H, "top-left");
    expect(rect.x).toBe(36);
    expect(rect.y).toBe(H - 60 - SIG_HEIGHT);
  });

  it("computes bottom-center correctly", () => {
    const rect = computeSigRect(W, H, "bottom-center");
    const expectedX = (W - SIG_WIDTH) / 2;
    expect(rect.x).toBeCloseTo(expectedX, 5);
    expect(rect.y).toBe(60);
  });

  it("throws on zero page width", () => {
    expect(() => computeSigRect(0, H)).toThrow(PDFError);
  });

  it("throws on zero page height", () => {
    expect(() => computeSigRect(W, 0)).toThrow(PDFError);
  });

  it("throws on negative dimensions", () => {
    expect(() => computeSigRect(-100, H)).toThrow(PDFError);
    expect(() => computeSigRect(W, -100)).toThrow(PDFError);
  });

  it("throws when signature does not fit", () => {
    expect(() => computeSigRect(50, 50, "bottom-right")).toThrow(PDFError);
  });

  it("accepts custom margins", () => {
    const rect = computeSigRect(W, H, "bottom-left", SIG_WIDTH, SIG_HEIGHT, 10, 20);
    expect(rect.x).toBe(10);
    expect(rect.y).toBe(20);
  });

  it("uses bottom-right as default position", () => {
    const rect = computeSigRect(W, H);
    const explicit = computeSigRect(W, H, "bottom-right");
    expect(rect.x).toBe(explicit.x);
    expect(rect.y).toBe(explicit.y);
  });

  it("throws on zero signature width", () => {
    expect(() => computeSigRect(W, H, "bottom-right", 0, SIG_HEIGHT)).toThrow(PDFError);
    expect(() => computeSigRect(W, H, "bottom-right", 0, SIG_HEIGHT)).toThrow(
      /Invalid signature dimensions/,
    );
  });

  it("throws on negative signature width", () => {
    expect(() => computeSigRect(W, H, "bottom-right", -10, SIG_HEIGHT)).toThrow(PDFError);
  });

  it("throws on zero signature height", () => {
    expect(() => computeSigRect(W, H, "bottom-right", SIG_WIDTH, 0)).toThrow(PDFError);
    expect(() => computeSigRect(W, H, "bottom-right", SIG_WIDTH, 0)).toThrow(
      /Invalid signature dimensions/,
    );
  });

  it("throws on negative signature height", () => {
    expect(() => computeSigRect(W, H, "bottom-right", SIG_WIDTH, -1)).toThrow(PDFError);
  });
});

describe("getPageDimensions", () => {
  it("returns correct dimensions for standard letter-size page", async () => {
    const pdfDoc = await PDFDocument.create();
    pdfDoc.addPage([612, 792]);
    const dims = getPageDimensions(pdfDoc, 0);
    expect(dims.width).toBe(612);
    expect(dims.height).toBe(792);
  });

  it("returns correct dimensions for A4 page", async () => {
    const pdfDoc = await PDFDocument.create();
    pdfDoc.addPage([595.28, 841.89]);
    const dims = getPageDimensions(pdfDoc, 0);
    expect(dims.width).toBeCloseTo(595.28, 1);
    expect(dims.height).toBeCloseTo(841.89, 1);
  });

  it("swaps width/height for 90-degree rotation", async () => {
    const pdfDoc = await PDFDocument.create();
    const page = pdfDoc.addPage([612, 792]);
    page.setRotation({ type: "degrees", angle: 90 });
    const dims = getPageDimensions(pdfDoc, 0);
    expect(dims.width).toBe(792);
    expect(dims.height).toBe(612);
  });

  it("swaps width/height for 270-degree rotation", async () => {
    const pdfDoc = await PDFDocument.create();
    const page = pdfDoc.addPage([612, 792]);
    page.setRotation({ type: "degrees", angle: 270 });
    const dims = getPageDimensions(pdfDoc, 0);
    expect(dims.width).toBe(792);
    expect(dims.height).toBe(612);
  });

  it("keeps dimensions for 180-degree rotation", async () => {
    const pdfDoc = await PDFDocument.create();
    const page = pdfDoc.addPage([612, 792]);
    page.setRotation({ type: "degrees", angle: 180 });
    const dims = getPageDimensions(pdfDoc, 0);
    expect(dims.width).toBe(612);
    expect(dims.height).toBe(792);
  });
});

describe("resolvePageIndex", () => {
  it("resolves 'first' to 0", async () => {
    const pdfDoc = await PDFDocument.create();
    pdfDoc.addPage();
    pdfDoc.addPage();
    expect(resolvePageIndex(pdfDoc, "first")).toBe(0);
  });

  it("resolves 'last' to last page index", async () => {
    const pdfDoc = await PDFDocument.create();
    pdfDoc.addPage();
    pdfDoc.addPage();
    pdfDoc.addPage();
    expect(resolvePageIndex(pdfDoc, "last")).toBe(2);
  });

  it("accepts 0-based numeric index", async () => {
    const pdfDoc = await PDFDocument.create();
    pdfDoc.addPage();
    pdfDoc.addPage();
    expect(resolvePageIndex(pdfDoc, 0)).toBe(0);
    expect(resolvePageIndex(pdfDoc, 1)).toBe(1);
  });

  it("throws on out-of-range index", async () => {
    const pdfDoc = await PDFDocument.create();
    pdfDoc.addPage();
    expect(() => resolvePageIndex(pdfDoc, 5)).toThrow(PDFError);
    expect(() => resolvePageIndex(pdfDoc, -1)).toThrow(PDFError);
  });

  it("throws on invalid string", async () => {
    const pdfDoc = await PDFDocument.create();
    pdfDoc.addPage();
    expect(() => resolvePageIndex(pdfDoc, "xyz")).toThrow(PDFError);
  });

  it("parses numeric strings", async () => {
    const pdfDoc = await PDFDocument.create();
    pdfDoc.addPage();
    pdfDoc.addPage();
    expect(resolvePageIndex(pdfDoc, "0")).toBe(0);
    expect(resolvePageIndex(pdfDoc, "1")).toBe(1);
  });
});

// =============================================================================
// objects.ts
// =============================================================================

describe("pdfString", () => {
  it("escapes backslash", () => {
    expect(pdfString("a\\b")).toContain("\\\\");
  });

  it("escapes parentheses", () => {
    const result = pdfString("(hello)");
    expect(result).toContain("\\(");
    expect(result).toContain("\\)");
  });

  it("escapes newlines and tabs", () => {
    expect(pdfString("a\nb")).toContain("\\n");
    expect(pdfString("a\rb")).toContain("\\r");
    expect(pdfString("a\tb")).toContain("\\t");
  });

  it("escapes control characters with octal", () => {
    // 0x01 -> \\001
    const result = pdfString("\x01");
    expect(result).toBe("\\001");
  });

  it("replaces non-Latin1 characters with '?'", () => {
    // Emoji is above U+00FF
    const result = pdfString("hello \u{1F600} world");
    expect(result).toContain("?");
    expect(result).not.toContain("\u{1F600}");
  });

  it("preserves normal ASCII text", () => {
    expect(pdfString("Hello World 123")).toBe("Hello World 123");
  });

  it("handles empty string", () => {
    expect(pdfString("")).toBe("");
  });
});

describe("serializePdfObject", () => {
  it("returns 'null' for null", () => {
    expect(serializePdfObject(null)).toBe("null");
  });

  it("returns 'null' for undefined", () => {
    expect(serializePdfObject(undefined)).toBe("null");
  });

  it("calls toString() on regular objects", () => {
    const fakeObj = { toString: () => "<< /Type /Sig >>" };
    expect(serializePdfObject(fakeObj)).toBe("<< /Type /Sig >>");
  });

  it("formats PDFRef correctly", () => {
    const ref = PDFRef.of(5, 0);
    const result = serializePdfObject(ref);
    expect(result).toBe("5 0 R");
  });

  it("formats PDFRef with non-zero generation", () => {
    const ref = PDFRef.of(10, 2);
    const result = serializePdfObject(ref);
    expect(result).toBe("10 2 R");
  });
});

describe("allocateSigObjects", () => {
  it("allocates all objects for visible signature", () => {
    const nums = allocateSigObjects(10, false, false, true);
    expect(nums.sig).toBe(10);
    expect(nums.annot).toBe(11);
    expect(nums.font).toBe(12);
    expect(nums.cidfont).toBe(13);
    expect(nums.fontDesc).toBe(14);
    expect(nums.fontFile).toBe(15);
    expect(nums.tounicode).toBe(16);
    expect(nums.ap).toBe(17);
    expect(nums.frm).toBe(18);
    expect(nums.n0).toBe(19);
    expect(nums.n2).toBe(20);
    expect(nums.img).toBeNull();
    expect(nums.smask).toBeNull();
    expect(nums.newSize).toBe(21);
  });

  it("allocates minimal objects for invisible signature", () => {
    const nums = allocateSigObjects(10, false, false, false);
    expect(nums.sig).toBe(10);
    expect(nums.annot).toBe(11);
    expect(nums.font).toBeNull();
    expect(nums.cidfont).toBeNull();
    expect(nums.fontDesc).toBeNull();
    expect(nums.fontFile).toBeNull();
    expect(nums.tounicode).toBeNull();
    expect(nums.ap).toBeNull();
    expect(nums.frm).toBeNull();
    expect(nums.n0).toBeNull();
    expect(nums.n2).toBeNull();
    expect(nums.img).toBeNull();
    expect(nums.smask).toBeNull();
    expect(nums.newSize).toBe(12);
  });

  it("allocates image object when hasImage is true", () => {
    const nums = allocateSigObjects(10, true, false, true);
    expect(nums.img).toBe(21);
    expect(nums.smask).toBeNull();
    expect(nums.newSize).toBe(22);
  });

  it("allocates image and smask when both flags are true", () => {
    const nums = allocateSigObjects(10, true, true, true);
    expect(nums.img).toBe(21);
    expect(nums.smask).toBe(22);
    expect(nums.newSize).toBe(23);
  });

  it("starts from correct prevSize", () => {
    const nums = allocateSigObjects(100, false, false, false);
    expect(nums.sig).toBe(100);
    expect(nums.annot).toBe(101);
  });
});

describe("constants", () => {
  it("CMS_RESERVED_SIZE is 8192", () => {
    expect(CMS_RESERVED_SIZE).toBe(8192);
  });

  it("CMS_HEX_SIZE is double CMS_RESERVED_SIZE", () => {
    expect(CMS_HEX_SIZE).toBe(CMS_RESERVED_SIZE * 2);
  });

  it("BYTERANGE_PLACEHOLDER has correct format", () => {
    expect(BYTERANGE_PLACEHOLDER).toMatch(/^\/ByteRange \[/);
    expect(BYTERANGE_PLACEHOLDER).toContain("]");
    // Should have 4 groups of digits/spaces
    expect(BYTERANGE_PLACEHOLDER).toMatch(/\/ByteRange \[\s+0\s+0\s+0\s+0\]/);
  });

  it("ANNOT_FLAGS_SIG_WIDGET is Print + Locked (132)", () => {
    expect(ANNOT_FLAGS_SIG_WIDGET).toBe(132);
  });
});

describe("buildObjectOverride", () => {
  it("builds override with new entry replacing skipped key", async () => {
    const pdfBytes = await createValidPdf();
    const rootInfo = findRootObjNum(pdfBytes);
    const result = await buildObjectOverride(
      pdfBytes,
      rootInfo.objNum,
      "/AcroForm",
      "  /AcroForm << /Fields [] >>",
    );
    expect(result).toContain(`${rootInfo.objNum} 0 obj`);
    expect(result).toContain("/AcroForm << /Fields [] >>");
    expect(result).toContain("endobj");
  });
});

describe("buildPageOverride", () => {
  it("builds page override with annots list", async () => {
    const pdfBytes = await createValidPdf();
    const pageInfo = await findPageObjNum(pdfBytes, 0);
    const result = await buildPageOverride(pdfBytes, pageInfo.pageObjNum, "99 0 R");
    expect(result).toContain(`${pageInfo.pageObjNum} 0 obj`);
    expect(result).toContain("/Annots [99 0 R]");
  });
});

describe("buildCatalogOverride", () => {
  it("builds catalog override with AcroForm", async () => {
    const pdfBytes = await createValidPdf();
    const rootInfo = findRootObjNum(pdfBytes);
    const result = await buildCatalogOverride(pdfBytes, rootInfo.objNum, 50);
    expect(result).toContain(`${rootInfo.objNum} 0 obj`);
    expect(result).toContain("/AcroForm");
    expect(result).toContain("50 0 R");
    expect(result).toContain("/SigFlags 3");
  });
});

// =============================================================================
// asn1.ts
// =============================================================================

describe("ASN1 constants", () => {
  it("ASN1_SEQUENCE_TAG is 0x30", () => {
    expect(ASN1_SEQUENCE_TAG).toBe(0x30);
  });

  it("MIN_CMS_SIZE is a positive number", () => {
    expect(MIN_CMS_SIZE).toBeGreaterThan(0);
    expect(MIN_CMS_SIZE).toBe(100);
  });
});

describe("extractDerFromPaddedHex", () => {
  it("extracts short-form length DER", () => {
    // Tag=30, Len=02, Data=00AB -> total 4 bytes
    const hex = `300200AB${"00".repeat(50)}`;
    const der = extractDerFromPaddedHex(hex);
    expect(der[0]).toBe(0x30);
    expect(der.length).toBe(4);
  });

  it("extracts long-form 1-byte length", () => {
    // Tag=30, 81 80 -> 128 bytes of content
    const contentHex = "AB".repeat(128);
    const hex = `308180${contentHex}${"00".repeat(50)}`;
    const der = extractDerFromPaddedHex(hex);
    // header: tag(1) + 0x81(1) + lenByte(1) = 3; content: 128
    expect(der.length).toBe(131);
  });

  it("extracts long-form 2-byte length", () => {
    // Tag=30, 82 01 00 -> 256 bytes of content
    const contentHex = "AB".repeat(256);
    const hex = `30820100${contentHex}${"00".repeat(50)}`;
    const der = extractDerFromPaddedHex(hex);
    // header: 1 + 1 + 2 = 4; content: 256
    expect(der.length).toBe(260);
  });

  it("extracts exact-length hex (no padding)", () => {
    const hex = "300200AB";
    const der = extractDerFromPaddedHex(hex);
    expect(der.length).toBe(4);
  });

  it("throws for all-zeros (no SEQUENCE tag)", () => {
    const hex = "00".repeat(100);
    expect(() => extractDerFromPaddedHex(hex)).toThrow("Expected ASN.1 SEQUENCE");
  });

  it("throws for too-short hex string", () => {
    expect(() => extractDerFromPaddedHex("30")).toThrow("too short");
  });

  it("throws for wrong tag", () => {
    const hex = "FF0200AB";
    expect(() => extractDerFromPaddedHex(hex)).toThrow("Expected ASN.1 SEQUENCE");
  });

  it("parses BER indefinite length (0x80) and finds EOC", () => {
    // 0x30 0x80 = SEQUENCE with indefinite length
    // Contains one primitive: 0x04 0x02 0xAA 0xBB (OCTET STRING, 2 bytes)
    // Terminated by EOC: 0x00 0x00
    // Followed by zero padding from PDF placeholder
    const berHex = "3080" + "0402aabb" + "0000" + "000000";
    const result = extractDerFromPaddedHex(berHex);
    const expected = Buffer.from("3080" + "0402aabb" + "0000", "hex");
    expect(Buffer.from(result).equals(expected)).toBe(true);
  });

  it("throws when length exceeds available data", () => {
    // Claims 255 bytes of content but only 2 available
    const hex = "3081FF0000";
    expect(() => extractDerFromPaddedHex(hex)).toThrow("exceeds available");
  });

  it("throws when numLenBytes > 4", () => {
    // Tag=30, 0x85 means 5 length bytes (lower 7 bits of 0x85 = 5)
    // Followed by 5 length bytes + enough data
    const hex = `3085${"00".repeat(100)}`;
    expect(() => extractDerFromPaddedHex(hex)).toThrow("length field too large");
  });

  it("throws when hex too short for length field", () => {
    // Tag=30, 0x83 means 3 length bytes needed (neededHex = 4 + 3*2 = 10)
    // But only provide 8 hex chars total
    const hex = "30830001";
    expect(() => extractDerFromPaddedHex(hex)).toThrow("too short for ASN.1 length field");
  });

  it("throws when DER blob claims excessive size", () => {
    // Tag=30, 0x84 means 4 length bytes. Claim 0x01000001 = 16777217 bytes (~16 MB)
    // MAX_CMS_HEX_CHARS / 2 = 16 * 1024 * 1024 = 16777216 bytes
    // So claiming 16777217 exceeds the max
    const hex = `308401000001${"AB".repeat(100)}`;
    expect(() => extractDerFromPaddedHex(hex)).toThrow("exceeds maximum");
  });
});

// =============================================================================
// cms-extraction.ts
// =============================================================================

describe("findByteRanges", () => {
  it("finds a single ByteRange match", () => {
    const content = `%PDF-1.7\n/ByteRange [0 100 200 300]\n/Contents <${"AB".repeat(100)}>`;
    const bytes = new TextEncoder().encode(content);
    const matches = findByteRanges(bytes);
    expect(matches.length).toBe(1);
    const first = matches[0];
    expect(first).toBeDefined();
    if (first !== undefined) {
      expect(first.off1).toBe(0);
      expect(first.len1).toBe(100);
      expect(first.off2).toBe(200);
      expect(first.len2).toBe(300);
    }
  });

  it("finds multiple ByteRange matches", () => {
    const content = `/ByteRange [0 100 200 50]\n` + `/ByteRange [0 300 400 100]\n`;
    const bytes = new TextEncoder().encode(content);
    const matches = findByteRanges(bytes);
    expect(matches.length).toBe(2);
  });

  it("returns empty for unsigned PDF", () => {
    const bytes = new TextEncoder().encode("%PDF-1.7\nHello World");
    const matches = findByteRanges(bytes);
    expect(matches.length).toBe(0);
  });

  it("handles various whitespace in ByteRange", () => {
    const content = `/ByteRange [  0   100   200   300  ]`;
    const bytes = new TextEncoder().encode(content);
    const matches = findByteRanges(bytes);
    expect(matches.length).toBe(1);
  });
});

describe("extractCmsFromByterange", () => {
  it("extracts CMS from valid ByteRange", () => {
    // Build a PDF-like buffer with angle brackets around hex content
    // Structure: [before]<hex>[after]
    const before = new TextEncoder().encode("PDF-before-content");
    const hexContent = `300200AB${"00".repeat(50)}`; // valid ASN.1 SEQUENCE
    const middle = new TextEncoder().encode(`<${hexContent}>`);
    const after = new TextEncoder().encode("PDF-after-content");

    const pdf = new Uint8Array(before.length + middle.length + after.length);
    pdf.set(before, 0);
    pdf.set(middle, before.length);
    pdf.set(after, before.length + middle.length);

    const _len1 = before.length + 1; // position after '<'
    const _off2 = before.length + middle.length - 1; // position of '>'
    // The function expects pdfBytes[len1-1] === '<' and pdfBytes[off2] === '>'
    // len1 points to the start of hex (after '<'), off2 points to '>'
    // Actually: hexStart = len1, hexEnd = off2-1
    // pdfBytes[len1 - 1] should be '<'
    // pdfBytes[off2 - 1] should be '>'
    // Wait, let me re-read the source carefully

    // From the source:
    // hexStart = len1
    // hexEnd = off2 - 1
    // pdfBytes[hexStart - 1] must be 0x3C ('<')
    // pdfBytes[hexEnd] must be 0x3E ('>')

    // So: pdfBytes[len1 - 1] = '<', pdfBytes[off2 - 1] = '>'
    // len1 = index of first hex byte (after '<')
    // off2 = index after '>' (start of "after" chunk)

    const cmsLen1 = before.length + 1; // index after '<'
    const _cmsOff2 = before.length + middle.length - 1 + 1; // index after '>'
    // Actually off2 - 1 is where '>' sits, so off2 = position_of_close_bracket + 1
    const closeBracketPos = before.length + middle.length - 1;
    const extractOff2 = closeBracketPos + 1;

    const der = extractCmsFromByterange(pdf, cmsLen1, extractOff2);
    expect(der[0]).toBe(0x30);
    expect(der.length).toBe(4); // 300200AB = 4 bytes
  });

  it("throws on invalid len1 (non-positive)", () => {
    const pdf = new Uint8Array(100);
    expect(() => extractCmsFromByterange(pdf, 0, 50)).toThrow(PDFError);
    expect(() => extractCmsFromByterange(pdf, -1, 50)).toThrow(PDFError);
  });

  it("throws when off2 <= len1", () => {
    const pdf = new Uint8Array(100);
    expect(() => extractCmsFromByterange(pdf, 50, 50)).toThrow(PDFError);
    expect(() => extractCmsFromByterange(pdf, 50, 30)).toThrow(PDFError);
  });

  it("throws when off2 exceeds PDF size", () => {
    const pdf = new Uint8Array(100);
    expect(() => extractCmsFromByterange(pdf, 10, 200)).toThrow(PDFError);
  });
});

describe("extractCmsFromByterangeMatch", () => {
  it("delegates to extractCmsFromByterange", () => {
    // Build a minimal valid structure
    const hexContent = `300200AB${"00".repeat(50)}`;
    const content = `${"X".repeat(10)}<${hexContent}>${"Y".repeat(20)}`;
    const pdf = new TextEncoder().encode(content);
    const brMatch = {
      off1: 0,
      len1: 11, // after '<'
      off2: 11 + hexContent.length + 1, // after '>'
      len2: 20,
    };
    const der = extractCmsFromByterangeMatch(pdf, brMatch);
    expect(der[0]).toBe(0x30);
  });
});

describe("extractSignatureDataFromMatch", () => {
  it("throws when off1 is not 0", () => {
    const pdf = new Uint8Array(500);
    const brMatch = { off1: 5, len1: 100, off2: 200, len2: 100 };
    expect(() => extractSignatureDataFromMatch(pdf, brMatch)).toThrow(PDFError);
  });

  it("throws when off2 <= len1", () => {
    const pdf = new Uint8Array(500);
    const brMatch = { off1: 0, len1: 200, off2: 100, len2: 100 };
    expect(() => extractSignatureDataFromMatch(pdf, brMatch)).toThrow(PDFError);
  });

  it("throws when ByteRange extends beyond EOF", () => {
    const pdf = new Uint8Array(100);
    const brMatch = { off1: 0, len1: 10, off2: 50, len2: 200 };
    expect(() => extractSignatureDataFromMatch(pdf, brMatch)).toThrow(PDFError);
  });
});

describe("extractSignatureData", () => {
  it("throws on unsigned PDF", () => {
    const pdf = new TextEncoder().encode("%PDF-1.7\nHello World");
    expect(() => extractSignatureData(pdf)).toThrow(PDFError);
  });

  it("extracts signed data and CMS from a signed PDF", async () => {
    const pdfBytes = await createValidPdf();
    const prepared = await preparePdfWithSigField(pdfBytes, { visible: false });
    const signedPdf = insertCms(prepared.pdf, prepared.hexStart, prepared.hexLen, FAKE_CMS);
    const result = extractSignatureData(signedPdf);
    expect(result.signedData.length).toBeGreaterThan(0);
    // CMS DER starts with ASN.1 SEQUENCE tag (0x30)
    expect(result.cmsDer[0]).toBe(0x30);
    expect(result.cmsDer.length).toBeGreaterThan(0);
  });
});

// =============================================================================
// cms-info.ts
// =============================================================================

describe("resolveHashAlgo", () => {
  it("resolves SHA-1 OID", () => {
    expect(resolveHashAlgo("1.3.14.3.2.26")).toBe("SHA-1");
  });

  it("resolves SHA-256 OID", () => {
    expect(resolveHashAlgo("2.16.840.1.101.3.4.2.1")).toBe("SHA-256");
  });

  it("resolves SHA-384 OID", () => {
    expect(resolveHashAlgo("2.16.840.1.101.3.4.2.2")).toBe("SHA-384");
  });

  it("resolves SHA-512 OID", () => {
    expect(resolveHashAlgo("2.16.840.1.101.3.4.2.3")).toBe("SHA-512");
  });

  it("resolves CoSign sha1WithRSAEncryption OID", () => {
    expect(resolveHashAlgo("1.2.840.113549.1.1.5")).toBe("SHA-1");
  });

  it("resolves CoSign sha256WithRSAEncryption OID", () => {
    expect(resolveHashAlgo("1.2.840.113549.1.1.11")).toBe("SHA-256");
  });

  it("resolves CoSign sha384WithRSAEncryption OID", () => {
    expect(resolveHashAlgo("1.2.840.113549.1.1.12")).toBe("SHA-384");
  });

  it("resolves CoSign sha512WithRSAEncryption OID", () => {
    expect(resolveHashAlgo("1.2.840.113549.1.1.13")).toBe("SHA-512");
  });

  it("returns null for unknown OID", () => {
    expect(resolveHashAlgo("1.2.3.4.5")).toBeNull();
    expect(resolveHashAlgo("")).toBeNull();
  });
});

describe("extractDigestInfo", () => {
  it("returns null for fake CMS (no real signer info)", () => {
    const result = extractDigestInfo(FAKE_CMS);
    expect(result).toBeNull();
  });

  it("returns null for tiny CMS", () => {
    const tiny = new Uint8Array([0x30, 0x00]);
    const result = extractDigestInfo(tiny);
    expect(result).toBeNull();
  });

  it("returns null when signer has no message-digest attribute", () => {
    // Build a CMS with a signer but signed attrs contain no messageDigest OID.
    // This exercises the loop-without-match path (line 94: return null).
    const OID_SIGNED_DATA = "1.2.840.113549.1.7.2";
    const OID_DATA = "1.2.840.113549.1.7.1";
    const OID_SHA1 = "1.3.14.3.2.26";
    // Use a different OID (content type) in signed attrs -- not message-digest
    const OID_CONTENT_TYPE = "1.2.840.113549.1.9.3";

    const signerInfo = new pkijs.SignerInfo({
      version: 1,
      sid: new pkijs.IssuerAndSerialNumber({
        issuer: new pkijs.RelativeDistinguishedNames(),
        serialNumber: new asn1js.Integer({ value: 1 }),
      }),
      digestAlgorithm: new pkijs.AlgorithmIdentifier({ algorithmId: OID_SHA1 }),
      signedAttrs: new pkijs.SignedAndUnsignedAttributes({
        type: 0,
        attributes: [
          // Only content-type attribute -- no message-digest
          new pkijs.Attribute({
            type: OID_CONTENT_TYPE,
            values: [new asn1js.ObjectIdentifier({ value: OID_DATA })],
          }),
        ],
      }),
      signatureAlgorithm: new pkijs.AlgorithmIdentifier({ algorithmId: "1.2.840.113549.1.1.1" }),
      signature: new asn1js.OctetString({ valueHex: new ArrayBuffer(128) }),
    });

    const signedData = new pkijs.SignedData({
      version: 1,
      digestAlgorithms: [new pkijs.AlgorithmIdentifier({ algorithmId: OID_SHA1 })],
      encapContentInfo: new pkijs.EncapsulatedContentInfo({ eContentType: OID_DATA }),
      signerInfos: [signerInfo],
    });

    const contentInfo = new pkijs.ContentInfo({
      contentType: OID_SIGNED_DATA,
      content: signedData.toSchema(true),
    });

    const cmsBytes = new Uint8Array(contentInfo.toSchema().toBER(false));
    const result = extractDigestInfo(cmsBytes);
    expect(result).toBeNull();
  });
});

describe("inspectCmsBlob", () => {
  it("reports too-small CMS", async () => {
    const tiny = new Uint8Array(10);
    const result = await inspectCmsBlob(tiny);
    expect(result.signer).toBeNull();
    expect(result.digestAlgorithm).toBeNull();
    expect(result.cmsSize).toBe(10);
    expect(result.details.some((d) => d.includes("too small"))).toBe(true);
  });

  it("reports wrong tag", async () => {
    const wrongTag = new Uint8Array(200).fill(0xff);
    const result = await inspectCmsBlob(wrongTag);
    expect(result.signer).toBeNull();
    expect(result.details.some((d) => d.includes("Not a valid CMS"))).toBe(true);
  });

  it("inspects valid-looking CMS blob", async () => {
    const result = await inspectCmsBlob(FAKE_CMS);
    expect(result.cmsSize).toBe(FAKE_CMS.length);
    // The FAKE_CMS starts with 0x30, so structure check passes
    expect(result.details.some((d) => d.includes("valid ASN.1"))).toBe(true);
  });
});

// =============================================================================
// incremental.ts
// =============================================================================

describe("findRootObjNum", () => {
  it("finds /Root in a standard PDF", async () => {
    const pdfBytes = await createValidPdf();
    const root = findRootObjNum(pdfBytes);
    expect(root.objNum).toBeGreaterThan(0);
    expect(root.genNum).toBe(0);
  });

  it("throws when no /Root is found", () => {
    const bytes = new TextEncoder().encode("not a PDF at all");
    expect(() => findRootObjNum(bytes)).toThrow(PDFError);
  });
});

describe("findPageObjNum", () => {
  it("finds page 0 in a valid PDF", async () => {
    const pdfBytes = await createValidPdf();
    const info = await findPageObjNum(pdfBytes, 0);
    expect(info.pageObjNum).toBeGreaterThan(0);
    expect(info.pageWidth).toBe(612);
    expect(info.pageHeight).toBe(792);
    expect(info.hasAnnots).toBe(false);
    expect(info.existingAnnots.length).toBe(0);
  });

  it("resolves 'first' page spec", async () => {
    const pdfBytes = await createValidPdf();
    const info = await findPageObjNum(pdfBytes, "first");
    expect(info.pageObjNum).toBeGreaterThan(0);
  });

  it("resolves 'last' page spec", async () => {
    const pdfBytes = await createValidPdf();
    const info = await findPageObjNum(pdfBytes, "last");
    expect(info.pageObjNum).toBeGreaterThan(0);
  });

  it("detects existing annotations and returns them as refs", async () => {
    // Create a PDF with a widget annotation already on the page
    const pdfDoc = await PDFDocument.create();
    const page = pdfDoc.addPage([612, 792]);

    // Allocate an indirect ref for the annotation and add it to the page
    const annotRef = pdfDoc.context.nextRef();
    const annotDict = pdfDoc.context.obj({
      Type: PDFName.of("Annot"),
      Subtype: PDFName.of("Widget"),
      FT: PDFName.of("Sig"),
      Rect: [0, 0, 0, 0],
      T: PDFString.of("ExistingSig"),
    });
    pdfDoc.context.assign(annotRef, annotDict);
    page.node.set(PDFName.of("Annots"), pdfDoc.context.obj([annotRef]));

    const pdfBytes = new Uint8Array(await pdfDoc.save());
    const info = await findPageObjNum(pdfBytes, 0);

    expect(info.hasAnnots).toBe(true);
    expect(info.existingAnnots.length).toBe(1);
    const firstAnnot = info.existingAnnots[0];
    expect(firstAnnot).toBeDefined();
    if (firstAnnot !== undefined) {
      // Should be formatted as "N M R"
      expect(firstAnnot).toMatch(/^\d+ \d+ R$/);
    }
  });
});

describe("findPrevStartxref", () => {
  it("finds startxref in a valid PDF", async () => {
    const pdfBytes = await createValidPdf();
    const result = await findPrevStartxref(pdfBytes);
    expect(result.prevXref).toBeGreaterThan(0);
    expect(result.maxSize).toBeGreaterThan(0);
  });

  it("throws when no startxref is found", async () => {
    const bytes = new TextEncoder().encode("not a PDF");
    await expect(findPrevStartxref(bytes)).rejects.toThrow(PDFError);
  });

  it("extracts /Info and /ID from traditional trailer", async () => {
    // Create a valid PDF using pdf-lib, then manually append an incremental
    // update with a trailer containing /Info and /ID entries.
    const basePdf = await createValidPdf();
    const rootInfo = findRootObjNum(basePdf);

    // Build a fake incremental update with /Info and /ID in the trailer
    const incUpdate =
      "\n99 0 obj\n<< /Type /Test >>\nendobj\n" +
      "xref\n99 1\n" +
      "0000000100 00000 n\r\n" +
      "trailer\n<<\n" +
      `  /Size 100\n` +
      `  /Prev 0\n` +
      `  /Root ${rootInfo.objNum} ${rootInfo.genNum} R\n` +
      `  /Info 5 0 R\n` +
      `  /ID [<abc123> <def456>]\n` +
      ">>\n" +
      "startxref\n100\n%%EOF\n";
    const incBytes = new TextEncoder().encode(incUpdate);
    const combined = new Uint8Array(basePdf.length + incBytes.length);
    combined.set(basePdf, 0);
    combined.set(incBytes, basePdf.length);

    const result = await findPrevStartxref(combined);
    expect(result.trailerExtra.length).toBeGreaterThan(0);
    const hasInfo = result.trailerExtra.some((e) => e.includes("/Info"));
    const hasId = result.trailerExtra.some((e) => e.includes("/ID"));
    expect(hasInfo).toBe(true);
    expect(hasId).toBe(true);
  });

  it("extracts /Info from standard pdf-lib generated PDF", async () => {
    const pdfBytes = await createValidPdf();
    const result = await findPrevStartxref(pdfBytes);
    // pdf-lib generated PDFs have /Info in their trailer
    const hasInfo = result.trailerExtra.some((e) => e.includes("/Info"));
    expect(hasInfo).toBe(true);
  });

  it("extracts /ID from xref stream object when it contains /ID entry", async () => {
    // pdf-lib generates XRef stream PDFs (no traditional trailer).
    // The base pdf-lib XRef stream has /Info but no /ID.
    // Strip /Info from the base so the original XRef stream yields no matches,
    // then append a new XRef stream carrying BOTH /Info AND /ID.
    // This forces extractTrailerEntries to reach lines 224-225 (the /ID branch).
    const basePdf = await createValidPdf();
    const rootInfo = findRootObjNum(basePdf);

    // Remove /Info from the base so the original XRef stream no longer matches
    const basePdfText = new TextDecoder("latin1").decode(basePdf);
    const strippedText = basePdfText.replace(/\/Info\s+\d+\s+\d+\s+R/g, "/InfoRemoved");
    const strippedBase = new TextEncoder().encode(strippedText);

    const xrefStreamObj =
      `\n10 0 obj\n` +
      `<< /Type /XRef /Size 11 /Root ${rootInfo.objNum} ${rootInfo.genNum} R` +
      ` /Info 3 0 R /ID [<aabbcc> <ddeeff>] /W [1 2 1] /Length 5 >>\n` +
      `stream\n00000\nendstream\nendobj\n`;
    const xrefStreamBytes = new TextEncoder().encode(xrefStreamObj);
    const newStartxrefOffset = strippedBase.length + xrefStreamBytes.length;
    const footer = new TextEncoder().encode(`startxref\n${newStartxrefOffset}\n%%EOF\n`);

    const combined = new Uint8Array(strippedBase.length + xrefStreamBytes.length + footer.length);
    combined.set(strippedBase, 0);
    combined.set(xrefStreamBytes, strippedBase.length);
    combined.set(footer, strippedBase.length + xrefStreamBytes.length);

    const result = await findPrevStartxref(combined);
    const hasInfo = result.trailerExtra.some((e) => e.includes("/Info"));
    const hasId = result.trailerExtra.some((e) => e.includes("/ID"));
    expect(hasInfo).toBe(true);
    expect(hasId).toBe(true);
  });

  it("returns empty trailerExtra when xref stream has no /Info or /ID", async () => {
    // Build a PDF whose XRef streams carry /Type /XRef but neither /Info nor /ID.
    // extractTrailerEntries should return an empty array, reaching the final return.
    const basePdf = await createValidPdf();
    const rootInfo = findRootObjNum(basePdf);

    // Strip /Info from the base PDF bytes so the original XRef stream no longer carries it
    const basePdfText = new TextDecoder("latin1").decode(basePdf);
    const strippedText = basePdfText.replace(/\/Info\s+\d+\s+\d+\s+R/g, "/InfoRemoved");
    const strippedBase = new TextEncoder().encode(strippedText);

    const xrefStreamObj =
      `\n10 0 obj\n` +
      `<< /Type /XRef /Size 11 /Root ${rootInfo.objNum} ${rootInfo.genNum} R` +
      ` /W [1 2 1] /Length 5 >>\n` +
      `stream\n00000\nendstream\nendobj\n`;
    const xrefStreamBytes = new TextEncoder().encode(xrefStreamObj);
    const newStartxrefOffset = strippedBase.length + xrefStreamBytes.length;
    const footer = new TextEncoder().encode(`startxref\n${newStartxrefOffset}\n%%EOF\n`);

    const combined = new Uint8Array(strippedBase.length + xrefStreamBytes.length + footer.length);
    combined.set(strippedBase, 0);
    combined.set(xrefStreamBytes, strippedBase.length);
    combined.set(footer, strippedBase.length + xrefStreamBytes.length);

    const result = await findPrevStartxref(combined);
    expect(result.trailerExtra.length).toBe(0);
  });
});

describe("assembleIncrementalUpdate", () => {
  it("creates a valid incremental update", async () => {
    const pdfBytes = await createValidPdf();
    const rawObj = new TextEncoder().encode("99 0 obj\n<< /Type /Test >>\nendobj\n");
    const result = assembleIncrementalUpdate(
      pdfBytes,
      [{ raw: rawObj, objNum: 99 }],
      100,
      500,
      1,
      0,
      [],
    );
    const text = new TextDecoder().decode(result);
    expect(text).toContain("xref");
    expect(text).toContain("trailer");
    expect(text).toContain("/Size 100");
    expect(text).toContain("/Prev 500");
    expect(text).toContain("/Root 1 0 R");
    expect(text).toContain("%%EOF");
    expect(text).toContain("99 0 obj");
  });

  it("appends newline if original PDF does not end with one", () => {
    const base = new Uint8Array([0x50, 0x44, 0x46]); // no trailing newline
    const rawObj = new TextEncoder().encode("10 0 obj\n<< >>\nendobj\n");
    const result = assembleIncrementalUpdate(base, [{ raw: rawObj, objNum: 10 }], 11, 0, 1, 0, []);
    // Base should get a trailing newline appended (4 bytes total base)
    expect(result[3]).toBe(0x0a);
  });

  it("preserves trailer extras", async () => {
    const pdfBytes = await createValidPdf();
    const rawObj = new TextEncoder().encode("99 0 obj\n<< >>\nendobj\n");
    const result = assembleIncrementalUpdate(
      pdfBytes,
      [{ raw: rawObj, objNum: 99 }],
      100,
      500,
      1,
      0,
      ["/Info 5 0 R", "/ID [<abc> <def>]"],
    );
    const text = new TextDecoder().decode(result);
    expect(text).toContain("/Info 5 0 R");
    expect(text).toContain("/ID [<abc> <def>]");
  });
});

describe("buildXrefAndTrailer", () => {
  it("builds xref for consecutive objects", () => {
    const entries = new Map([
      [10, 1000],
      [11, 2000],
      [12, 3000],
    ]);
    const result = buildXrefAndTrailer({
      xrefEntries: entries,
      newSize: 13,
      prevXref: 500,
      rootObjNum: 1,
      rootGen: 0,
      trailerExtra: [],
      xrefOffset: 5000,
    });
    const text = new TextDecoder().decode(result);
    expect(text).toContain("xref");
    expect(text).toContain("10 3"); // consecutive group: 10, 11, 12
    expect(text).toContain("/Size 13");
    expect(text).toContain("/Prev 500");
    expect(text).toContain("startxref");
    expect(text).toContain("5000");
    expect(text).toContain("%%EOF");
  });

  it("builds xref for non-consecutive objects", () => {
    const entries = new Map([
      [5, 100],
      [10, 200],
      [11, 300],
    ]);
    const result = buildXrefAndTrailer({
      xrefEntries: entries,
      newSize: 12,
      prevXref: 400,
      rootObjNum: 1,
      rootGen: 0,
      trailerExtra: [],
      xrefOffset: 1000,
    });
    const text = new TextDecoder().decode(result);
    // Should have two groups: [5] and [10,11]
    expect(text).toContain("5 1");
    expect(text).toContain("10 2");
  });

  it("throws on empty entries", () => {
    expect(() =>
      buildXrefAndTrailer({
        xrefEntries: new Map(),
        newSize: 10,
        prevXref: 0,
        rootObjNum: 1,
        rootGen: 0,
        trailerExtra: [],
        xrefOffset: 0,
      }),
    ).toThrow(PDFError);
  });

  it("includes trailer extras", () => {
    const entries = new Map([[5, 100]]);
    const result = buildXrefAndTrailer({
      xrefEntries: entries,
      newSize: 6,
      prevXref: 0,
      rootObjNum: 1,
      rootGen: 0,
      trailerExtra: ["/Info 2 0 R"],
      xrefOffset: 500,
    });
    const text = new TextDecoder().decode(result);
    expect(text).toContain("/Info 2 0 R");
  });
});

describe("buildXrefStream", () => {
  it("produces a valid XRef stream object", () => {
    const entries = new Map([
      [10, 1000],
      [11, 2000],
    ]);
    const result = buildXrefStream({
      xrefEntries: entries,
      newSize: 12,
      prevXref: 500,
      rootObjNum: 1,
      rootGen: 0,
      trailerExtra: [],
      xrefOffset: 5000,
      xrefObjNum: 12,
    });
    const text = new TextDecoder("latin1").decode(result);
    expect(text).toContain("12 0 obj");
    expect(text).toContain("/Type /XRef");
    expect(text).toContain("/Size 13"); // xrefObjNum + 1
    expect(text).toContain("/Prev 500");
    expect(text).toContain("/Root 1 0 R");
    expect(text).toContain("/Filter /FlateDecode");
    expect(text).toContain("stream");
    expect(text).toContain("endstream");
    expect(text).toContain("startxref");
    expect(text).toContain("5000");
    expect(text).toContain("%%EOF");
    // Should NOT contain traditional "trailer" keyword
    expect(text).not.toContain("trailer");
  });

  it("includes trailer extras in XRef stream dict", () => {
    const entries = new Map([[5, 100]]);
    const result = buildXrefStream({
      xrefEntries: entries,
      newSize: 6,
      prevXref: 0,
      rootObjNum: 1,
      rootGen: 0,
      trailerExtra: ["/Info 2 0 R", "/ID [<abc> <def>]"],
      xrefOffset: 500,
      xrefObjNum: 6,
    });
    const text = new TextDecoder("latin1").decode(result);
    expect(text).toContain("/Info 2 0 R");
    expect(text).toContain("/ID [<abc> <def>]");
  });

  it("includes itself in /Index", () => {
    const entries = new Map([[10, 1000]]);
    const result = buildXrefStream({
      xrefEntries: entries,
      newSize: 11,
      prevXref: 0,
      rootObjNum: 1,
      rootGen: 0,
      trailerExtra: [],
      xrefOffset: 5000,
      xrefObjNum: 11,
    });
    const text = new TextDecoder("latin1").decode(result);
    // Should have two groups: obj 10 and obj 11 (the xref stream itself)
    expect(text).toContain("/Index [10 2]");
  });
});

describe("findPrevStartxref useXrefStream detection", () => {
  it("returns useXrefStream=true for pdf-lib PDFs", async () => {
    const pdfBytes = await createValidPdf();
    const result = await findPrevStartxref(pdfBytes);
    // pdf-lib generates XRef stream PDFs
    expect(result.useXrefStream).toBe(true);
  });

  it("returns useXrefStream=false for traditional xref PDFs", async () => {
    const basePdf = await createValidPdf();
    const rootInfo = findRootObjNum(basePdf);

    // Append a traditional xref incremental update so startxref points to "xref"
    const xrefStart = basePdf.length + 50;
    const incUpdate =
      "\n99 0 obj\n<< /Type /Test >>\nendobj\n" +
      "xref\n99 1\n" +
      `${xrefStart.toString().padStart(10, "0")} 00000 n\r\n` +
      "trailer\n<<\n" +
      `  /Size 100\n` +
      `  /Prev 0\n` +
      `  /Root ${rootInfo.objNum} ${rootInfo.genNum} R\n` +
      ">>\n" +
      `startxref\n${basePdf.length + 50}\n%%EOF\n`;
    const incBytes = new TextEncoder().encode(incUpdate);
    const combined = new Uint8Array(basePdf.length + incBytes.length);
    combined.set(basePdf, 0);
    combined.set(incBytes, basePdf.length);

    // Fix: startxref should point to "xref" keyword
    const xrefPos = new TextDecoder().decode(combined).lastIndexOf("xref\n99");
    const fixedInc =
      "\n99 0 obj\n<< /Type /Test >>\nendobj\n" +
      "xref\n99 1\n" +
      `${xrefStart.toString().padStart(10, "0")} 00000 n\r\n` +
      "trailer\n<<\n" +
      `  /Size 100\n` +
      `  /Prev 0\n` +
      `  /Root ${rootInfo.objNum} ${rootInfo.genNum} R\n` +
      ">>\n" +
      `startxref\n${xrefPos}\n%%EOF\n`;
    const fixedIncBytes = new TextEncoder().encode(fixedInc);
    const fixedCombined = new Uint8Array(basePdf.length + fixedIncBytes.length);
    fixedCombined.set(basePdf, 0);
    fixedCombined.set(fixedIncBytes, basePdf.length);

    const result = await findPrevStartxref(fixedCombined);
    expect(result.useXrefStream).toBe(false);
  });
});

describe("assembleIncrementalUpdate with useXrefStream", () => {
  it("produces XRef stream when useXrefStream=true", async () => {
    const pdfBytes = await createValidPdf();
    const rawObj = new TextEncoder().encode("99 0 obj\n<< /Type /Test >>\nendobj\n");
    const result = assembleIncrementalUpdate(
      pdfBytes,
      [{ raw: rawObj, objNum: 99 }],
      100,
      500,
      1,
      0,
      [],
      true,
    );
    const text = new TextDecoder("latin1").decode(result);
    expect(text).toContain("/Type /XRef");
    expect(text).not.toContain("trailer\n<<");
    expect(text).toContain("%%EOF");
  });

  it("produces traditional xref when useXrefStream=false", async () => {
    const pdfBytes = await createValidPdf();
    const rawObj = new TextEncoder().encode("99 0 obj\n<< /Type /Test >>\nendobj\n");
    const result = assembleIncrementalUpdate(
      pdfBytes,
      [{ raw: rawObj, objNum: 99 }],
      100,
      500,
      1,
      0,
      [],
      false,
    );
    // Check only the appended portion (original pdf-lib PDF already has /Type /XRef)
    const appended = result.slice(pdfBytes.length);
    const text = new TextDecoder().decode(appended);
    expect(text).toContain("xref\n");
    expect(text).toContain("trailer");
    expect(text).not.toContain("/Type /XRef");
  });
});

describe("patchByterange", () => {
  it("patches placeholder with actual values", () => {
    const contentsHex = "0".repeat(CMS_HEX_SIZE);
    const contentsField = `/Contents <${contentsHex}>`;
    const incrementalUpdate = `${BYTERANGE_PLACEHOLDER}\n${contentsField}\nendobj\n`;
    const originalPdf = "%PDF-1.7\noriginal content\n";
    const fullPdfText = originalPdf + incrementalUpdate;
    const fullPdf = new TextEncoder().encode(fullPdfText);
    const originalLen = new TextEncoder().encode(originalPdf).length;

    const result = patchByterange(fullPdf, originalLen);
    const text = new TextDecoder().decode(result.pdf);
    expect(text).toContain("/ByteRange [");
    // Placeholder zeros should be replaced with actual offsets
    expect(text).not.toContain("         0          0          0          0");
    expect(result.hexStart).toBeGreaterThan(0);
    expect(result.hexLen).toBe(CMS_HEX_SIZE);
  });

  it("throws when placeholder is not found", () => {
    const pdf = new TextEncoder().encode("%PDF-1.7\nno placeholder here\n");
    expect(() => patchByterange(pdf, 0)).toThrow(PDFError);
  });

  it("throws when Contents placeholder is found but ByteRange placeholder is missing", () => {
    // Build a PDF that has the /Contents <0...0> marker but no BYTERANGE_PLACEHOLDER.
    // This exercises the branch where contentsPos succeeds but brPos === -1.
    const contentsHex = "0".repeat(CMS_HEX_SIZE);
    const pdfText = `%PDF-1.7\n/Contents <${contentsHex}>\nendobj\n`;
    const pdf = new TextEncoder().encode(pdfText);
    expect(() => patchByterange(pdf, 0)).toThrow(PDFError);
    expect(() => patchByterange(pdf, 0)).toThrow(/ByteRange placeholder/);
  });
});

// =============================================================================
// builder.ts
// =============================================================================

describe("preparePdfWithSigField", () => {
  it("prepares PDF with invisible signature", async () => {
    const pdfBytes = await createValidPdf();
    const result = await preparePdfWithSigField(pdfBytes, { visible: false });
    expect(result.pdf.length).toBeGreaterThan(pdfBytes.length);
    expect(result.hexStart).toBeGreaterThan(0);
    expect(result.hexLen).toBe(CMS_HEX_SIZE);

    // The prepared PDF should contain ByteRange and Contents
    const text = new TextDecoder("latin1").decode(result.pdf);
    expect(text).toContain("/ByteRange [");
    expect(text).toContain("/Type /Sig");
    expect(text).toContain("/SubFilter /adbe.pkcs7.detached");
  });
});

describe("computeByterangeHash", () => {
  it("computes hash for valid hex range", async () => {
    const pdfBytes = await createValidPdf();
    const prepared = await preparePdfWithSigField(pdfBytes, { visible: false });
    const hash = computeByterangeHash(prepared.pdf, prepared.hexStart, prepared.hexLen);
    expect(hash.length).toBe(20); // SHA-1 digest size
  });

  it("throws on invalid hexStart (<=0)", async () => {
    const pdf = new Uint8Array(100);
    expect(() => computeByterangeHash(pdf, 0, 10)).toThrow(PDFError);
  });

  it("throws when range extends beyond PDF", async () => {
    const pdf = new Uint8Array(100);
    expect(() => computeByterangeHash(pdf, 10, 200)).toThrow(PDFError);
  });

  it("throws on missing angle brackets", () => {
    // Build a PDF-like buffer without proper '<' and '>'
    const pdf = new Uint8Array(200);
    pdf.fill(0x41); // 'A'
    expect(() => computeByterangeHash(pdf, 50, 50)).toThrow(PDFError);
  });
});

describe("insertCms", () => {
  it("inserts CMS that fits exactly", async () => {
    const pdfBytes = await createValidPdf();
    const prepared = await preparePdfWithSigField(pdfBytes, { visible: false });

    // Create a fake CMS that fits within hexLen
    const fakeCms = new Uint8Array(100);
    fakeCms.fill(0xab);
    const result = insertCms(prepared.pdf, prepared.hexStart, prepared.hexLen, fakeCms);
    expect(result.length).toBe(prepared.pdf.length);

    // Verify the hex was inserted at the right position
    const hexSlice = new TextDecoder().decode(
      result.slice(prepared.hexStart, prepared.hexStart + 200),
    );
    expect(hexSlice.startsWith("ab".repeat(100))).toBe(true);
  });

  it("throws when CMS is too large", async () => {
    const pdfBytes = await createValidPdf();
    const prepared = await preparePdfWithSigField(pdfBytes, { visible: false });

    // Create CMS larger than reserved space
    const hugeCms = new Uint8Array(CMS_RESERVED_SIZE + 1);
    expect(() => insertCms(prepared.pdf, prepared.hexStart, prepared.hexLen, hugeCms)).toThrow(
      PDFError,
    );
  });

  it("zero-pads remaining space", async () => {
    const pdfBytes = await createValidPdf();
    const prepared = await preparePdfWithSigField(pdfBytes, { visible: false });

    const tinyCms = new Uint8Array([0x30, 0x01, 0xab]);
    const result = insertCms(prepared.pdf, prepared.hexStart, prepared.hexLen, tinyCms);

    // After the CMS hex, the rest should be zeros
    const hexSlice = new TextDecoder().decode(
      result.slice(prepared.hexStart, prepared.hexStart + prepared.hexLen),
    );
    expect(hexSlice.startsWith("3001ab")).toBe(true);
    // Rest should be '0' characters
    const padding = hexSlice.slice(6);
    expect(padding).toMatch(/^0+$/);
  });
});

// =============================================================================
// render.ts
// =============================================================================

describe("buildSigDict", () => {
  it("builds a signature dictionary", () => {
    const result = buildSigDict(50, "Test reason", null);
    expect(result).toContain("50 0 obj");
    expect(result).toContain("/Type /Sig");
    expect(result).toContain("/Filter /Adobe.PPKLite");
    expect(result).toContain("/SubFilter /adbe.pkcs7.detached");
    expect(result).toContain(BYTERANGE_PLACEHOLDER);
    expect(result).toContain("/Contents <");
    expect(result).toContain("/Reason (Test reason)");
    expect(result).toContain("endobj");
  });

  it("includes /Name when provided", () => {
    const result = buildSigDict(50, "Reason", "John Doe");
    expect(result).toContain("/Name (John Doe)");
  });

  it("omits signer /Name entry when null", () => {
    const result = buildSigDict(50, "Reason", null);
    // The /Name (signerName) entry should not be present.
    // Note: /Name /Revenant in /Prop_Build is different and should still exist.
    expect(result).not.toMatch(/\/Name\s*\(/);
  });

  it("escapes special characters in reason", () => {
    const result = buildSigDict(50, "Test (with parens)", null);
    expect(result).toContain("Test \\(with parens\\)");
  });

  it("includes Prop_Build with Revenant", () => {
    const result = buildSigDict(50, "Reason", null);
    expect(result).toContain("/Prop_Build");
    expect(result).toContain("/Name /Revenant");
  });
});

describe("buildAnnotWidget", () => {
  it("builds annotation widget with correct structure", () => {
    const objNums = allocateSigObjects(10, false, false, true);
    const result = buildAnnotWidget(objNums, 5, 100, 200, 210, 70);
    expect(result).toContain(`${objNums.annot} 0 obj`);
    expect(result).toContain("/Type /Annot");
    expect(result).toContain("/Subtype /Widget");
    expect(result).toContain("/FT /Sig");
    expect(result).toContain("/Rect [100.00 200.00 310.00 270.00]");
    expect(result).toContain(`/V ${objNums.sig} 0 R`);
    expect(result).toContain(`/F ${ANNOT_FLAGS_SIG_WIDGET}`);
    expect(result).toContain("/P 5 0 R");
    expect(result).toContain(`/AP << /N ${objNums.ap} 0 R >>`);
    expect(result).toContain("/Border [0 0 0]");
    expect(result).toContain("endobj");
  });
});

describe("buildInvisibleAnnotWidget", () => {
  it("builds invisible widget with zero-size rect", () => {
    const objNums = allocateSigObjects(10, false, false, false);
    const result = buildInvisibleAnnotWidget(objNums, 5);
    expect(result).toContain(`${objNums.annot} 0 obj`);
    expect(result).toContain("/Rect [0 0 0 0]");
    expect(result).toContain("/Type /Annot");
    expect(result).toContain("/Subtype /Widget");
    expect(result).toContain("/FT /Sig");
    expect(result).toContain(`/V ${objNums.sig} 0 R`);
    expect(result).toContain(`/F ${ANNOT_FLAGS_SIG_WIDGET}`);
    expect(result).toContain("/P 5 0 R");
    // Should NOT have /AP entry
    expect(result).not.toContain("/AP");
  });
});

// =============================================================================
// verify.ts
// =============================================================================

describe("verifyEmbeddedSignature", () => {
  it("returns invalid for unsigned PDF", async () => {
    const pdf = new TextEncoder().encode("%PDF-1.7\nHello World");
    const result = await verifyEmbeddedSignature(new Uint8Array(pdf));
    expect(result.valid).toBe(false);
    expect(result.structureOk).toBe(false);
    expect(result.details.length).toBeGreaterThan(0);
    const firstDetail = result.details[0];
    expect(firstDetail).toBeDefined();
    if (firstDetail !== undefined) {
      expect(firstDetail).toContain("No /ByteRange");
    }
  });

  it("returns invalid for non-PDF content", async () => {
    const garbage = new Uint8Array([0x00, 0x01, 0x02, 0x03]);
    const result = await verifyEmbeddedSignature(garbage);
    expect(result.valid).toBe(false);
    expect(result.structureOk).toBe(false);
  });
});

describe("verifyDetachedSignature", () => {
  it("returns structureOk for valid CMS structure", async () => {
    const data = new TextEncoder().encode("test data");
    const result = await verifyDetachedSignature(data, FAKE_CMS);
    expect(result.structureOk).toBe(true);
    // Hash won't match since the CMS is fake
    expect(result.valid).toBe(false);
  });

  it("detects corrupt CMS (wrong tag)", async () => {
    const data = new TextEncoder().encode("test data");
    const badCms = new Uint8Array([0xff, 0x01]);
    const result = await verifyDetachedSignature(data, badCms);
    expect(result.structureOk).toBe(false);
    expect(result.valid).toBe(false);
  });

  it("detects too-small CMS", async () => {
    const data = new TextEncoder().encode("test data");
    const tinyCms = new Uint8Array([0x30, 0x01]);
    const result = await verifyDetachedSignature(data, tinyCms);
    expect(result.structureOk).toBe(false);
    expect(result.valid).toBe(false);
  });
});

describe("verifyAllEmbeddedSignatures", () => {
  it("throws on unsigned PDF", async () => {
    const pdf = new TextEncoder().encode("%PDF-1.7\nHello World");
    await expect(verifyAllEmbeddedSignatures(pdf)).rejects.toThrow(PDFError);
  });
});

// =============================================================================
// Integration: prepare + insert + verify round-trip
// =============================================================================

// =============================================================================
// render.ts -- buildEmbeddedFontObjects
// =============================================================================

describe("buildEmbeddedFontObjects", () => {
  it("returns 5 font objects with correct object numbers", async () => {
    const { buildEmbeddedFontObjects } = await import("../src/core/pdf/render.js");
    const { getFont } = await import("../src/core/appearance/fonts.js");
    const font = await getFont(null);
    const objNums = allocateSigObjects(100, false, false, true);
    const result = buildEmbeddedFontObjects(objNums, font.metrics);

    expect(result).toHaveLength(5);

    // Verify object numbers match: Type0, CIDFont, FontDescriptor, FontFile2, ToUnicode
    const objNumbers = result.map((o) => o.objNum);
    expect(objNumbers).toContain(objNums.font);
    expect(objNumbers).toContain(objNums.cidfont);
    expect(objNumbers).toContain(objNums.fontDesc);
    expect(objNumbers).toContain(objNums.fontFile);
    expect(objNumbers).toContain(objNums.tounicode);
  });

  it("Type0 font object references CIDFont and ToUnicode", async () => {
    const { buildEmbeddedFontObjects } = await import("../src/core/pdf/render.js");
    const { getFont } = await import("../src/core/appearance/fonts.js");
    const font = await getFont(null);
    const objNums = allocateSigObjects(100, false, false, true);
    const result = buildEmbeddedFontObjects(objNums, font.metrics);

    const type0Obj = result.find((o) => o.objNum === objNums.font);
    expect(type0Obj).toBeDefined();
    if (type0Obj !== undefined) {
      const text = new TextDecoder().decode(type0Obj.raw);
      expect(text).toContain("/Type /Font");
      expect(text).toContain("/Subtype /Type0");
      expect(text).toContain(`/DescendantFonts [${objNums.cidfont} 0 R]`);
      expect(text).toContain(`/ToUnicode ${objNums.tounicode} 0 R`);
      expect(text).toContain("/Encoding /Identity-H");
      expect(text).toContain("/BaseFont /NotoSans");
    }
  });

  it("CIDFontType2 object references FontDescriptor", async () => {
    const { buildEmbeddedFontObjects } = await import("../src/core/pdf/render.js");
    const { getFont } = await import("../src/core/appearance/fonts.js");
    const font = await getFont(null);
    const objNums = allocateSigObjects(100, false, false, true);
    const result = buildEmbeddedFontObjects(objNums, font.metrics);

    const cidfontObj = result.find((o) => o.objNum === objNums.cidfont);
    expect(cidfontObj).toBeDefined();
    if (cidfontObj !== undefined) {
      const text = new TextDecoder().decode(cidfontObj.raw);
      expect(text).toContain("/Subtype /CIDFontType2");
      expect(text).toContain(`/FontDescriptor ${objNums.fontDesc} 0 R`);
      expect(text).toContain("/CIDSystemInfo");
    }
  });

  it("FontDescriptor references FontFile2", async () => {
    const { buildEmbeddedFontObjects } = await import("../src/core/pdf/render.js");
    const { getFont } = await import("../src/core/appearance/fonts.js");
    const font = await getFont(null);
    const objNums = allocateSigObjects(100, false, false, true);
    const result = buildEmbeddedFontObjects(objNums, font.metrics);

    const fontDescObj = result.find((o) => o.objNum === objNums.fontDesc);
    expect(fontDescObj).toBeDefined();
    if (fontDescObj !== undefined) {
      const text = new TextDecoder().decode(fontDescObj.raw);
      expect(text).toContain("/Type /FontDescriptor");
      expect(text).toContain(`/FontFile2 ${objNums.fontFile} 0 R`);
      expect(text).toContain("/Flags 32");
    }
  });

  it("FontFile2 contains compressed TTF with stream markers", async () => {
    const { buildEmbeddedFontObjects } = await import("../src/core/pdf/render.js");
    const { getFont } = await import("../src/core/appearance/fonts.js");
    const font = await getFont(null);
    const objNums = allocateSigObjects(100, false, false, true);
    const result = buildEmbeddedFontObjects(objNums, font.metrics);

    const fontFileObj = result.find((o) => o.objNum === objNums.fontFile);
    expect(fontFileObj).toBeDefined();
    if (fontFileObj !== undefined) {
      // The raw bytes contain the header as text, then compressed binary
      const rawText = new TextDecoder("latin1").decode(fontFileObj.raw);
      expect(rawText).toContain(`${objNums.fontFile} 0 obj`);
      expect(rawText).toContain("/Filter /FlateDecode");
      expect(rawText).toContain("/Length1");
      expect(rawText).toContain("stream");
      expect(rawText).toContain("endstream");
      expect(rawText).toContain("endobj");
    }
  });

  it("ToUnicode contains CMap stream", async () => {
    const { buildEmbeddedFontObjects } = await import("../src/core/pdf/render.js");
    const { getFont } = await import("../src/core/appearance/fonts.js");
    const font = await getFont(null);
    const objNums = allocateSigObjects(100, false, false, true);
    const result = buildEmbeddedFontObjects(objNums, font.metrics);

    const tounicodeObj = result.find((o) => o.objNum === objNums.tounicode);
    expect(tounicodeObj).toBeDefined();
    if (tounicodeObj !== undefined) {
      const rawText = new TextDecoder("latin1").decode(tounicodeObj.raw);
      expect(rawText).toContain(`${objNums.tounicode} 0 obj`);
      expect(rawText).toContain("stream");
      expect(rawText).toContain("endstream");
    }
  });

  it("throws when font object numbers are null (invisible signature)", async () => {
    const { buildEmbeddedFontObjects } = await import("../src/core/pdf/render.js");
    const { getFont } = await import("../src/core/appearance/fonts.js");
    const font = await getFont(null);
    const objNums = allocateSigObjects(100, false, false, false); // invisible = no font nums
    expect(() => buildEmbeddedFontObjects(objNums, font.metrics)).toThrow(PDFError);
  });
});

// =============================================================================
// render.ts -- buildFormXobjects
// =============================================================================

describe("buildFormXobjects", () => {
  it("returns n0, n2, frm, ap objects without image data", async () => {
    const { buildFormXobjects } = await import("../src/core/pdf/render.js");
    const { buildAppearanceStream, getFont } = await import("../src/core/appearance/index.js");

    const font = await getFont(null);
    const objNums = allocateSigObjects(100, false, false, true);
    const apInfo = await buildAppearanceStream(200, 70, ["Name: Test"], false, font);

    const result = buildFormXobjects(objNums, 200, 70, apInfo, null);

    // n0, n2, frm, ap should have content
    expect(result.n0.length).toBeGreaterThan(0);
    expect(result.n2.length).toBeGreaterThan(0);
    expect(result.frm.length).toBeGreaterThan(0);
    expect(result.ap.length).toBeGreaterThan(0);

    // img and smask should be empty (no image data)
    expect(result.img.length).toBe(0);
    expect(result.smask.length).toBe(0);
  });

  it("n0 object contains DSBlank placeholder", async () => {
    const { buildFormXobjects } = await import("../src/core/pdf/render.js");
    const { buildAppearanceStream, getFont } = await import("../src/core/appearance/index.js");

    const font = await getFont(null);
    const objNums = allocateSigObjects(100, false, false, true);
    const apInfo = await buildAppearanceStream(200, 70, ["Name: Test"], false, font);
    const result = buildFormXobjects(objNums, 200, 70, apInfo, null);

    const n0Text = new TextDecoder("latin1").decode(result.n0);
    expect(n0Text).toContain("% DSBlank");
    expect(n0Text).toContain("/Type /XObject");
    expect(n0Text).toContain("/Subtype /Form");
  });

  it("n2 object references font", async () => {
    const { buildFormXobjects } = await import("../src/core/pdf/render.js");
    const { buildAppearanceStream, getFont } = await import("../src/core/appearance/index.js");

    const font = await getFont(null);
    const objNums = allocateSigObjects(100, false, false, true);
    const apInfo = await buildAppearanceStream(200, 70, ["Test"], false, font);
    const result = buildFormXobjects(objNums, 200, 70, apInfo, null);

    const n2Text = new TextDecoder("latin1").decode(result.n2);
    expect(n2Text).toContain(`/Font << /F1 ${objNums.font} 0 R >>`);
  });

  it("frm object delegates to n0 and n2", async () => {
    const { buildFormXobjects } = await import("../src/core/pdf/render.js");
    const { buildAppearanceStream, getFont } = await import("../src/core/appearance/index.js");

    const font = await getFont(null);
    const objNums = allocateSigObjects(100, false, false, true);
    const apInfo = await buildAppearanceStream(200, 70, ["Test"], false, font);
    const result = buildFormXobjects(objNums, 200, 70, apInfo, null);

    const frmText = new TextDecoder("latin1").decode(result.frm);
    expect(frmText).toContain("/n0 Do");
    expect(frmText).toContain("/n2 Do");
    expect(frmText).toContain(`/n0 ${objNums.n0} 0 R`);
    expect(frmText).toContain(`/n2 ${objNums.n2} 0 R`);
  });

  it("ap object delegates to FRM", async () => {
    const { buildFormXobjects } = await import("../src/core/pdf/render.js");
    const { buildAppearanceStream, getFont } = await import("../src/core/appearance/index.js");

    const font = await getFont(null);
    const objNums = allocateSigObjects(100, false, false, true);
    const apInfo = await buildAppearanceStream(200, 70, ["Test"], false, font);
    const result = buildFormXobjects(objNums, 200, 70, apInfo, null);

    const apText = new TextDecoder("latin1").decode(result.ap);
    expect(apText).toContain("/FRM Do");
    expect(apText).toContain(`/FRM ${objNums.frm} 0 R`);
  });

  it("returns image and smask objects when imgData is provided", async () => {
    const { buildFormXobjects } = await import("../src/core/pdf/render.js");
    const { buildAppearanceStream, getFont } = await import("../src/core/appearance/index.js");

    const font = await getFont(null);
    const objNums = allocateSigObjects(100, true, true, true);
    const apInfo = await buildAppearanceStream(200, 70, ["Test"], true, font);

    const fakeImgData = {
      samples: new Uint8Array([0x78, 0x9c, 0x01, 0x00, 0x00]),
      smask: new Uint8Array([0x78, 0x9c, 0x01, 0x00, 0x00]),
      width: 10,
      height: 10,
      bpc: 8,
    };

    const result = buildFormXobjects(objNums, 200, 70, apInfo, fakeImgData);

    // Image and smask should have content
    expect(result.img.length).toBeGreaterThan(0);
    expect(result.smask.length).toBeGreaterThan(0);

    // Image object should reference SMask
    const imgText = new TextDecoder("latin1").decode(result.img);
    expect(imgText).toContain("/Type /XObject");
    expect(imgText).toContain("/Subtype /Image");
    expect(imgText).toContain("/Width 10");
    expect(imgText).toContain("/Height 10");
    expect(imgText).toContain("/ColorSpace /DeviceRGB");
    expect(imgText).toContain(`/SMask ${objNums.smask} 0 R`);

    // SMask object should be DeviceGray
    const smaskText = new TextDecoder("latin1").decode(result.smask);
    expect(smaskText).toContain("/ColorSpace /DeviceGray");
    expect(smaskText).toContain("/Width 10");
    expect(smaskText).toContain("/Height 10");
  });

  it("returns image without smask when smask data is null", async () => {
    const { buildFormXobjects } = await import("../src/core/pdf/render.js");
    const { buildAppearanceStream, getFont } = await import("../src/core/appearance/index.js");

    const font = await getFont(null);
    const objNums = allocateSigObjects(100, true, false, true);
    const apInfo = await buildAppearanceStream(200, 70, ["Test"], true, font);

    const fakeImgData = {
      samples: new Uint8Array([0x78, 0x9c, 0x01, 0x00, 0x00]),
      smask: null,
      width: 10,
      height: 10,
      bpc: 8,
    };

    const result = buildFormXobjects(objNums, 200, 70, apInfo, fakeImgData);

    expect(result.img.length).toBeGreaterThan(0);
    expect(result.smask.length).toBe(0);

    // Image object should NOT reference SMask
    const imgText = new TextDecoder("latin1").decode(result.img);
    expect(imgText).not.toContain("/SMask");
  });

  it("n2 references image XObject when imgData is provided", async () => {
    const { buildFormXobjects } = await import("../src/core/pdf/render.js");
    const { buildAppearanceStream, getFont } = await import("../src/core/appearance/index.js");

    const font = await getFont(null);
    const objNums = allocateSigObjects(100, true, false, true);
    const apInfo = await buildAppearanceStream(200, 70, ["Test"], true, font);

    const fakeImgData = {
      samples: new Uint8Array([0x78, 0x9c, 0x01, 0x00, 0x00]),
      smask: null,
      width: 10,
      height: 10,
      bpc: 8,
    };

    const result = buildFormXobjects(objNums, 200, 70, apInfo, fakeImgData);
    const n2Text = new TextDecoder("latin1").decode(result.n2);
    expect(n2Text).toContain(`/Img1 ${objNums.img} 0 R`);
  });

  it("throws when form object numbers are null (invisible signature)", async () => {
    const { buildFormXobjects } = await import("../src/core/pdf/render.js");
    const { buildAppearanceStream, getFont } = await import("../src/core/appearance/index.js");

    const font = await getFont(null);
    const objNums = allocateSigObjects(100, false, false, false); // invisible
    const apInfo = await buildAppearanceStream(200, 70, ["Test"], false, font);

    expect(() => buildFormXobjects(objNums, 200, 70, apInfo, null)).toThrow(PDFError);
  });
});

// =============================================================================
// Integration: prepare + insert + verify round-trip
// =============================================================================

describe("prepare-insert round-trip", () => {
  it("creates a structurally valid signed PDF", async () => {
    const pdfBytes = await createValidPdf();
    const prepared = await preparePdfWithSigField(pdfBytes, { visible: false });

    // Insert the FAKE_CMS
    const signed = insertCms(prepared.pdf, prepared.hexStart, prepared.hexLen, FAKE_CMS);

    // The result should be loadable by pdf-lib
    const pdfDoc = await PDFDocument.load(signed, { updateMetadata: false });
    expect(pdfDoc.getPageCount()).toBe(1);

    // Verify structure detects the signature
    const brMatches = findByteRanges(signed);
    expect(brMatches.length).toBe(1);
  });

  it("hash computed before and after insert differs from expectation for fake CMS", async () => {
    const pdfBytes = await createValidPdf();
    const prepared = await preparePdfWithSigField(pdfBytes, { visible: false });

    const hash = computeByterangeHash(prepared.pdf, prepared.hexStart, prepared.hexLen);
    expect(hash.length).toBe(20);

    // Insert FAKE_CMS -- the byterange hash should be the same since CMS is inside the gap
    const signed = insertCms(prepared.pdf, prepared.hexStart, prepared.hexLen, FAKE_CMS);
    const hashAfter = computeByterangeHash(signed, prepared.hexStart, prepared.hexLen);

    // ByteRange hash must be identical since both exclude the hex content area
    expect(Buffer.from(hash).equals(Buffer.from(hashAfter))).toBe(true);
  });
});

// =============================================================================
// cms-extraction.ts -- additional coverage
// =============================================================================

describe("extractSignatureData (unsigned)", () => {
  it("throws PDFError with descriptive message for unsigned PDF", () => {
    const pdf = new TextEncoder().encode("%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF");
    expect(() => extractSignatureData(pdf)).toThrow(PDFError);
    expect(() => extractSignatureData(pdf)).toThrow(/No \/ByteRange/);
  });
});

describe("extractCmsFromByterange (angle bracket errors)", () => {
  it("throws when opening angle bracket is missing at both positions", () => {
    // Build a buffer where neither len1-1 nor len1 is '<'
    const pdf = new Uint8Array(100);
    pdf.fill(0x41); // 'A' everywhere
    // Set a '>' at the expected closing position
    pdf[49] = 0x3e; // '>'
    // len1=10, off2=50: checks '<' at position 9 and 10, neither is '<'
    expect(() => extractCmsFromByterange(pdf, 10, 50)).toThrow(PDFError);
    expect(() => extractCmsFromByterange(pdf, 10, 50)).toThrow(/Expected '</);
  });

  it("throws when closing angle bracket is missing", () => {
    const pdf = new Uint8Array(100);
    pdf.fill(0x41); // 'A' everywhere
    // Set '<' at the expected opening position (Revenant convention)
    pdf[9] = 0x3c; // '<'
    // But '>' is missing at position off2-1 = 49
    expect(() => extractCmsFromByterange(pdf, 10, 50)).toThrow(PDFError);
    expect(() => extractCmsFromByterange(pdf, 10, 50)).toThrow(/Expected '>/);
  });

  it("accepts cosign bracket convention (< at len1)", () => {
    // Original cosign: '<' at position len1 (outside chunk1)
    // DER: 0x30 0x03 0xAA 0xBB 0xCC = 5 bytes = 10 hex chars
    const derHex = "3003aabbcc";
    const paddedHex = derHex + "0".repeat(20);
    const pdf = new Uint8Array(100);
    pdf.fill(0x58); // 'X' everywhere
    // '<' at position len1=10 (cosign convention, NOT at 9)
    pdf[10] = 0x3c;
    // Write hex content starting at position 11
    const hexBytes = new TextEncoder().encode(paddedHex);
    pdf.set(hexBytes, 11);
    // '>' right after hex content
    const closePos = 11 + paddedHex.length;
    pdf[closePos] = 0x3e;
    // off2 = closePos + 1
    const result = extractCmsFromByterange(pdf, 10, closePos + 1);
    expect(Buffer.from(result).equals(Buffer.from(derHex, "hex"))).toBe(true);
  });
});

// =============================================================================
// cms-info.ts -- additional coverage
// =============================================================================

describe("inspectCmsBlob (structured CMS)", () => {
  it("inspects a CMS-sized blob with valid SEQUENCE header", async () => {
    // Create a blob large enough (>= MIN_CMS_SIZE = 100) with ASN.1 SEQUENCE tag
    const cmsBlob = new Uint8Array(200);
    cmsBlob[0] = 0x30; // ASN.1 SEQUENCE tag
    cmsBlob[1] = 0x81; // long-form length (1 byte)
    cmsBlob[2] = 0xc4; // 196 bytes of content
    // Fill remaining with some bytes
    cmsBlob.fill(0xab, 3);

    const result = await inspectCmsBlob(cmsBlob);
    expect(result.cmsSize).toBe(200);
    // Should report valid ASN.1 structure
    expect(result.details.some((d) => d.includes("valid ASN.1"))).toBe(true);
    // Signer extraction will fail since it's not a real CMS
    // but the structure check should pass
  });

  it("reports correct size for the blob", async () => {
    const cmsBlob = new Uint8Array(150);
    cmsBlob[0] = 0x30;
    cmsBlob.fill(0x00, 1);
    const result = await inspectCmsBlob(cmsBlob);
    expect(result.cmsSize).toBe(150);
  });

  it("extracts signer info and digest algorithm from a real CMS", async () => {
    // Build a CMS blob with a certificate and messageDigest
    const OID_SIGNED_DATA = "1.2.840.113549.1.7.2";
    const OID_DATA = "1.2.840.113549.1.7.1";
    const OID_SHA1 = "1.3.14.3.2.26";
    const OID_MESSAGE_DIGEST_LOCAL = "1.2.840.113549.1.9.4";
    const OID_CN = "2.5.4.3";
    const OID_EMAIL = "1.2.840.113549.1.9.1";
    const OID_ORG = "2.5.4.10";

    // Build test certificate
    const subjectRdns = [
      new asn1js.Set({
        value: [
          new asn1js.Sequence({
            value: [
              new asn1js.ObjectIdentifier({ value: OID_CN }),
              new asn1js.Utf8String({ value: "Inspector Signer" }),
            ],
          }),
        ],
      }),
      new asn1js.Set({
        value: [
          new asn1js.Sequence({
            value: [
              new asn1js.ObjectIdentifier({ value: OID_EMAIL }),
              new asn1js.IA5String({ value: "inspect@example.com" }),
            ],
          }),
        ],
      }),
      new asn1js.Set({
        value: [
          new asn1js.Sequence({
            value: [
              new asn1js.ObjectIdentifier({ value: OID_ORG }),
              new asn1js.Utf8String({ value: "Inspect Corp" }),
            ],
          }),
        ],
      }),
    ];

    const tbsCert = new asn1js.Sequence({
      value: [
        new asn1js.Constructed({
          idBlock: { tagClass: 3, tagNumber: 0 },
          value: [new asn1js.Integer({ value: 2 })],
        }),
        new asn1js.Integer({ value: 1 }),
        new asn1js.Sequence({
          value: [new asn1js.ObjectIdentifier({ value: "1.2.840.113549.1.1.5" })],
        }),
        new asn1js.Sequence({ value: subjectRdns }),
        new asn1js.Sequence({
          value: [
            new asn1js.UTCTime({ valueDate: new Date("2020-01-01T00:00:00Z") }),
            new asn1js.UTCTime({ valueDate: new Date("2040-01-01T00:00:00Z") }),
          ],
        }),
        new asn1js.Sequence({ value: subjectRdns }),
        new asn1js.Sequence({
          value: [
            new asn1js.Sequence({
              value: [
                new asn1js.ObjectIdentifier({ value: "1.2.840.113549.1.1.1" }),
                new asn1js.Null(),
              ],
            }),
            new asn1js.BitString({ valueHex: new ArrayBuffer(128) }),
          ],
        }),
      ],
    });

    const certAsn1 = new asn1js.Sequence({
      value: [
        tbsCert,
        new asn1js.Sequence({
          value: [new asn1js.ObjectIdentifier({ value: "1.2.840.113549.1.1.5" })],
        }),
        new asn1js.BitString({ valueHex: new ArrayBuffer(128) }),
      ],
    });

    const certDer = certAsn1.toBER(false);
    const certParsed = asn1js.fromBER(certDer);
    const cert = new pkijs.Certificate({ schema: certParsed.result });

    // Build CMS with digest and cert
    const digest = new Uint8Array(20).fill(0xaa);
    const digestOctetString = new asn1js.OctetString({
      valueHex: digest.buffer.slice(digest.byteOffset, digest.byteOffset + digest.byteLength),
    });

    const signerInfo = new pkijs.SignerInfo({
      version: 1,
      sid: new pkijs.IssuerAndSerialNumber({
        issuer: new pkijs.RelativeDistinguishedNames(),
        serialNumber: new asn1js.Integer({ value: 1 }),
      }),
      digestAlgorithm: new pkijs.AlgorithmIdentifier({ algorithmId: OID_SHA1 }),
      signedAttrs: new pkijs.SignedAndUnsignedAttributes({
        type: 0,
        attributes: [
          new pkijs.Attribute({
            type: OID_MESSAGE_DIGEST_LOCAL,
            values: [digestOctetString],
          }),
        ],
      }),
      signatureAlgorithm: new pkijs.AlgorithmIdentifier({ algorithmId: "1.2.840.113549.1.1.1" }),
      signature: new asn1js.OctetString({ valueHex: new ArrayBuffer(128) }),
    });

    const signedData = new pkijs.SignedData({
      version: 1,
      digestAlgorithms: [new pkijs.AlgorithmIdentifier({ algorithmId: OID_SHA1 })],
      encapContentInfo: new pkijs.EncapsulatedContentInfo({ eContentType: OID_DATA }),
      signerInfos: [signerInfo],
      certificates: [cert],
    });

    const contentInfo = new pkijs.ContentInfo({
      contentType: OID_SIGNED_DATA,
      content: signedData.toSchema(true),
    });

    const cmsBytes = new Uint8Array(contentInfo.toSchema().toBER(false));

    // Test inspectCmsBlob
    const inspection = await inspectCmsBlob(cmsBytes);
    expect(inspection.cmsSize).toBe(cmsBytes.length);
    expect(inspection.signer).not.toBeNull();
    if (inspection.signer !== null) {
      expect(inspection.signer.name).toBe("Inspector Signer");
      expect(inspection.signer.email).toBe("inspect@example.com");
      expect(inspection.signer.organization).toBe("Inspect Corp");
    }
    expect(inspection.digestAlgorithm).toBe("SHA-1");
    expect(inspection.details.some((d) => d.includes("Signer:"))).toBe(true);
    expect(inspection.details.some((d) => d.includes("Organization:"))).toBe(true);
    expect(inspection.details.some((d) => d.includes("Email:"))).toBe(true);
    expect(inspection.details.some((d) => d.includes("Digest algorithm:"))).toBe(true);

    // Test extractDigestInfo
    const digestResult = extractDigestInfo(cmsBytes);
    expect(digestResult).not.toBeNull();
    if (digestResult !== null) {
      expect(digestResult.algorithm).toBe("SHA-1");
      expect(digestResult.digest.length).toBe(20);
    }
  });
});

// =============================================================================
// Coverage gaps: render.ts -- buildEmbeddedFontObjects lines 79-80
// =============================================================================

describe("buildEmbeddedFontObjects (descriptor/file/tounicode null)", () => {
  it("throws when fontDesc is null but font and cidfont are set", async () => {
    const { getFont } = await import("../src/core/appearance/fonts.js");
    const font = await getFont(null);

    // Construct SigObjectNums where font/cidfont are present but fontDesc is null.
    // This exercises lines 78-80 (the second null check after font/cidfont pass).
    const objNums: import("../src/core/pdf/objects.js").SigObjectNums = {
      sig: 10,
      annot: 11,
      font: 12,
      cidfont: 13,
      fontDesc: null,
      fontFile: null,
      tounicode: null,
      ap: 17,
      frm: 18,
      n0: 19,
      n2: 20,
      img: null,
      smask: null,
      newSize: 21,
    };

    expect(() => buildEmbeddedFontObjects(objNums, font.metrics)).toThrow(PDFError);
    expect(() => buildEmbeddedFontObjects(objNums, font.metrics)).toThrow(
      /missing descriptor\/file\/tounicode/,
    );
  });
});

// =============================================================================
// Coverage gaps: render.ts -- buildFormXobjects lines 182-184
// =============================================================================

describe("buildFormXobjects (n0/n2 null)", () => {
  it("throws when n0 is null but font/ap/frm are set", async () => {
    const { buildAppearanceStream, getFont } = await import("../src/core/appearance/index.js");

    const font = await getFont(null);
    const apInfo = await buildAppearanceStream(200, 70, ["Test"], false, font);

    // Construct SigObjectNums where font/ap/frm are non-null but n0/n2 are null.
    // This exercises lines 182-184 (second null check after font/ap/frm pass).
    const objNums: import("../src/core/pdf/objects.js").SigObjectNums = {
      sig: 10,
      annot: 11,
      font: 12,
      cidfont: 13,
      fontDesc: 14,
      fontFile: 15,
      tounicode: 16,
      ap: 17,
      frm: 18,
      n0: null,
      n2: null,
      img: null,
      smask: null,
      newSize: 19,
    };

    expect(() => buildFormXobjects(objNums, 200, 70, apInfo, null)).toThrow(PDFError);
    expect(() => buildFormXobjects(objNums, 200, 70, apInfo, null)).toThrow(
      /missing n0\/n2 numbers/,
    );
  });
});

// =============================================================================
// Coverage gaps: objects.ts -- buildObjectOverride lines 136-139
// =============================================================================

describe("buildObjectOverride (non-dictionary object)", () => {
  it("throws PDFError when the target object is not a dictionary", async () => {
    // Create a PDF with a PDFString at a known object number
    const pdfDoc = await PDFDocument.create();
    pdfDoc.addPage([612, 792]);

    // Allocate an indirect ref and assign a non-dict value (PDFString)
    const ref = pdfDoc.context.nextRef();
    pdfDoc.context.assign(ref, PDFString.of("this is not a dict"));

    const pdfBytes = new Uint8Array(await pdfDoc.save());

    await expect(
      buildObjectOverride(pdfBytes, ref.objectNumber, "/Foo", "  /Foo /Bar"),
    ).rejects.toThrow(PDFError);

    await expect(
      buildObjectOverride(pdfBytes, ref.objectNumber, "/Foo", "  /Foo /Bar"),
    ).rejects.toThrow(/is not a dictionary/);
  });
});

// =============================================================================
// Coverage gaps: builder.ts -- computeByterangeHash lines 192-194
// =============================================================================

describe("computeByterangeHash (missing closing angle bracket)", () => {
  it("throws when '<' is present before hex but '>' is missing after hex", () => {
    // Build a buffer:
    //   - byte at hexStart-1 is 0x3c ('<')  -- passes first check
    //   - byte at hexStart+hexLen is NOT 0x3e ('>')  -- triggers second check
    const HEX_LEN = 20;
    const HEX_START = 10;
    // Total size must be > HEX_START + HEX_LEN + 1
    const buf = new Uint8Array(100);
    buf.fill(0x41); // 'A' everywhere
    buf[HEX_START - 1] = 0x3c; // '<' before hex
    // buf[HEX_START + HEX_LEN] remains 'A', not '>'

    expect(() => computeByterangeHash(buf, HEX_START, HEX_LEN)).toThrow(PDFError);
    expect(() => computeByterangeHash(buf, HEX_START, HEX_LEN)).toThrow(
      /expected '>' after hex data/,
    );
  });
});

// =============================================================================
// Coverage gaps: builder.ts collectObjects lines 414-419 (img/smask embedding)
// =============================================================================

describe("preparePdfWithSigField with image (collectObjects img/smask paths)", () => {
  it("embeds image and smask objects when a PNG with transparency is provided", async () => {
    // Create a minimal 2x2 RGBA PNG with semi-transparent pixels using raw bytes.
    // PNG structure: signature + IHDR + IDAT + IEND
    const { PNG } = await import("pngjs");

    const png = new PNG({ width: 2, height: 2, filterType: -1 });
    // RGBA pixels: red semi-transparent, green opaque, blue semi-transparent, white opaque
    png.data = Buffer.from([
      255,
      0,
      0,
      128, // pixel (0,0): red, semi-transparent
      0,
      255,
      0,
      255, // pixel (1,0): green, opaque
      0,
      0,
      255,
      128, // pixel (0,1): blue, semi-transparent
      255,
      255,
      255,
      255, // pixel (1,1): white, opaque
    ]);

    const pngBuffer = PNG.sync.write(png);

    const imgPath = join(tmpdir(), `revenant-test-${Date.now()}.png`);
    writeFileSync(imgPath, pngBuffer);

    try {
      const pdfBytes = await createValidPdf();
      const result = await preparePdfWithSigField(pdfBytes, {
        visible: true,
        imagePath: imgPath,
      });

      // The result should be larger than a visible sig without an image
      expect(result.pdf.length).toBeGreaterThan(pdfBytes.length);
      expect(result.hexStart).toBeGreaterThan(0);
      expect(result.hexLen).toBe(CMS_HEX_SIZE);

      // The PDF should contain the signature structure
      const text = new TextDecoder("latin1").decode(result.pdf);
      expect(text).toContain("/Type /Sig");
      expect(text).toContain("/Type /XObject");
    } finally {
      unlinkSync(imgPath);
    }
  });

  it("embeds image without smask when PNG has no transparency", async () => {
    const { PNG } = await import("pngjs");

    const png = new PNG({ width: 2, height: 2, filterType: -1 });
    // RGBA pixels: all fully opaque
    png.data = Buffer.from([
      255,
      0,
      0,
      255, // red, opaque
      0,
      255,
      0,
      255, // green, opaque
      0,
      0,
      255,
      255, // blue, opaque
      255,
      255,
      255,
      255, // white, opaque
    ]);

    const pngBuffer = PNG.sync.write(png);

    const imgPath = join(tmpdir(), `revenant-test-${Date.now()}.png`);
    writeFileSync(imgPath, pngBuffer);

    try {
      const pdfBytes = await createValidPdf();
      const result = await preparePdfWithSigField(pdfBytes, {
        visible: true,
        imagePath: imgPath,
      });

      expect(result.pdf.length).toBeGreaterThan(pdfBytes.length);
      expect(result.hexStart).toBeGreaterThan(0);
    } finally {
      unlinkSync(imgPath);
    }
  });
});
