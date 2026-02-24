/**
 * Tests for the appearance layer: fonts, fields, text measurement, image loading, and stream building.
 */

import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { CertField, SigField } from "../src/config/profiles.js";
import {
  buildAppearanceStream,
  computeOptimalHeight,
  computeOptimalWidth,
  encodeTextHex,
  extractCertFields,
  extractDisplayFields,
  formatUtcOffset,
  getFont,
  loadSignatureImage,
  makeDateStr,
  pdfEscape,
  textWidth,
  wrapLines,
} from "../src/core/appearance/index.js";

// -- Shared fixtures ----------------------------------------------------------

/** A valid 1x1 PNG (red pixel, fully opaque), generated with pngjs. */
const PNG_1X1 = Buffer.from(
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4AWP4z8DwHwAFAAH/e+m+7wAAAABJRU5ErkJggg==",
  "base64",
);

let tmpDir: string;

beforeAll(() => {
  tmpDir = mkdtempSync(join(tmpdir(), "revenant-test-"));
});

afterAll(() => {
  rmSync(tmpDir, { recursive: true, force: true });
});

// -- Font loading -------------------------------------------------------------

describe("getFont", () => {
  it("loads noto-sans by default", async () => {
    const font = await getFont(null);
    expect(font.name).toBe("NotoSans");
    expect(font.metrics.unitsPerEm).toBeGreaterThan(0);
  });

  it("loads noto-sans explicitly", async () => {
    const font = await getFont("noto-sans");
    expect(font.name).toBe("NotoSans");
  });

  it("loads ghea-grapalat", async () => {
    const font = await getFont("ghea-grapalat");
    expect(font.name).toBe("GHEAGrapalat");
    expect(font.metrics.unitsPerEm).toBeGreaterThan(0);
  });

  it("throws on unknown font", async () => {
    await expect(getFont("nonexistent")).rejects.toThrow();
  });
});

// -- Text measurement via font.textWidth --------------------------------------

describe("font.textWidth", () => {
  it("returns 0 for empty string", async () => {
    const font = await getFont(null);
    const width = font.textWidth("", 10);
    expect(width).toBe(0);
  });

  it("increases with text length", async () => {
    const font = await getFont(null);
    const w1 = font.textWidth("a", 10);
    const w2 = font.textWidth("aaaa", 10);
    expect(w2).toBeGreaterThan(w1);
  });

  it("scales with font size", async () => {
    const font = await getFont(null);
    const w10 = font.textWidth("hello", 10);
    const w20 = font.textWidth("hello", 20);
    expect(w20).toBeCloseTo(w10 * 2, 1);
  });
});

// -- wrapLines ----------------------------------------------------------------

describe("wrapLines", () => {
  it("returns empty array for empty text", async () => {
    const font = await getFont(null);
    const lines = wrapLines("", 10, 200, font.textWidth);
    expect(lines).toEqual([]);
  });

  it("keeps short text on one line", async () => {
    const font = await getFont(null);
    const lines = wrapLines("Hello", 10, 200, font.textWidth);
    expect(lines).toHaveLength(1);
    expect(lines[0]).toBe("Hello");
  });

  it("wraps long text across multiple lines", async () => {
    const font = await getFont(null);
    const longText = "The quick brown fox jumps over the lazy dog and keeps running far away";
    const lines = wrapLines(longText, 10, 80, font.textWidth);
    expect(lines.length).toBeGreaterThan(1);
    // All words should still be present
    const joined = lines.join(" ");
    expect(joined).toBe(longText);
  });

  it("handles single word wider than maxWidth", async () => {
    const font = await getFont(null);
    const lines = wrapLines("Supercalifragilisticexpialidocious", 10, 20, font.textWidth);
    // The word cannot be split, so it should appear on its own line
    expect(lines.length).toBeGreaterThanOrEqual(1);
    expect(lines[0]).toBe("Supercalifragilisticexpialidocious");
  });

  it("handles whitespace-only text", async () => {
    const font = await getFont(null);
    const lines = wrapLines("   ", 10, 200, font.textWidth);
    expect(lines).toEqual([]);
  });
});

// -- Optimal dimensions -------------------------------------------------------

describe("computeOptimalWidth", () => {
  it("computes a reasonable width", async () => {
    const font = await getFont(null);
    const fields = ["Name: John Doe", "Date: 2024-01-01"];
    const width = computeOptimalWidth(fields, 70, false, font);
    expect(width).toBeGreaterThan(50);
    expect(width).toBeLessThan(1000);
  });

  it("returns MIN_SIG_WIDTH for empty fields", async () => {
    const font = await getFont(null);
    const width = computeOptimalWidth([], 70, false, font);
    // MIN_SIG_WIDTH = 150
    expect(width).toBe(150);
  });

  it("handles single field", async () => {
    const font = await getFont(null);
    const width = computeOptimalWidth(["Name: Alice"], 70, false, font);
    expect(width).toBeGreaterThanOrEqual(150);
    expect(width).toBeLessThanOrEqual(300);
  });

  it("handles many fields", async () => {
    const font = await getFont(null);
    const fields = [
      "Name: John Doe",
      "Date: 2024-01-01",
      "Email: john@example.com",
      "Organization: ACME Corp International",
      "SSN: 12345",
    ];
    const width = computeOptimalWidth(fields, 70, false, font);
    expect(width).toBeGreaterThanOrEqual(150);
    expect(width).toBeLessThanOrEqual(300);
  });

  it("produces wider result with image flag", async () => {
    const font = await getFont(null);
    const fields = ["Name: John Doe", "Date: 2024-01-01"];
    const withoutImage = computeOptimalWidth(fields, 70, false, font);
    const withImage = computeOptimalWidth(fields, 70, true, font);
    expect(withImage).toBeGreaterThanOrEqual(withoutImage);
  });
});

describe("computeOptimalHeight", () => {
  it("computes a reasonable height", async () => {
    const font = await getFont(null);
    const fields = ["Name: John", "Email: john@example.com"];
    const height = computeOptimalHeight(fields, 210, false, font);
    expect(height).toBeGreaterThan(20);
    expect(height).toBeLessThan(500);
  });

  it("returns MIN_SIG_HEIGHT for empty fields", async () => {
    const font = await getFont(null);
    const height = computeOptimalHeight([], 210, false, font);
    // MIN_SIG_HEIGHT = 40
    expect(height).toBe(40);
  });

  it("handles single field", async () => {
    const font = await getFont(null);
    const height = computeOptimalHeight(["Name: Alice"], 210, false, font);
    expect(height).toBeGreaterThanOrEqual(40);
    expect(height).toBeLessThanOrEqual(120);
  });

  it("handles many fields", async () => {
    const font = await getFont(null);
    const fields = [
      "Name: John Doe",
      "Date: 2024-01-01",
      "Email: john@example.com",
      "Organization: ACME",
      "SSN: 12345",
    ];
    const height = computeOptimalHeight(fields, 210, false, font);
    expect(height).toBeGreaterThanOrEqual(40);
    expect(height).toBeLessThanOrEqual(120);
  });

  it("accounts for image column reducing text area", async () => {
    const font = await getFont(null);
    const fields = ["Name: John Doe", "Date: 2024-01-01", "Email: john@example.com"];
    const withoutImage = computeOptimalHeight(fields, 210, false, font);
    const withImage = computeOptimalHeight(fields, 210, true, font);
    // With image, text area is narrower, so text may wrap more and need more height
    expect(withImage).toBeGreaterThanOrEqual(withoutImage);
  });
});

// -- Field extraction ---------------------------------------------------------

describe("extractCertFields", () => {
  it("extracts matching fields from signer info", () => {
    const certFields: CertField[] = [
      { id: "signer_name", source: "name", label: "Name" },
      { id: "signer_email", source: "email", label: "Email" },
    ];
    const signerInfo = { name: "John Doe", email: "john@test.com", organization: null, dn: null };
    const result = extractCertFields(certFields, { ...signerInfo });
    expect(result.signer_name).toBe("John Doe");
    expect(result.signer_email).toBe("john@test.com");
  });

  it("applies regex extraction", () => {
    const certFields: CertField[] = [
      { id: "country", source: "dn", label: "Country", regex: "C=([A-Z]+)" },
    ];
    const signerInfo = { name: null, email: null, organization: null, dn: "CN=Test, C=AM, O=Org" };
    const result = extractCertFields(certFields, { ...signerInfo });
    expect(result.country).toBe("AM");
  });

  it("skips fields with unknown source", () => {
    const certFields = [{ id: "x", source: "unknown_source", label: "X" }];
    const signerInfo = { name: "Alice", email: null, organization: null, dn: null };
    // unknown source should be skipped
    const result = extractCertFields(certFields, { ...signerInfo });
    expect(result.x).toBeUndefined();
  });

  it("skips fields when regex has no capture group match", () => {
    const certFields: CertField[] = [
      { id: "gov_id", source: "name", label: "ID", regex: "(\\d{5,})$" },
    ];
    const signerInfo = { name: "Alice Smith", email: null, organization: null, dn: null };
    const result = extractCertFields(certFields, { ...signerInfo });
    expect(result.gov_id).toBeUndefined();
  });

  it("skips fields when source value is null", () => {
    const certFields: CertField[] = [{ id: "org", source: "organization", label: "Org" }];
    const signerInfo = { name: null, email: null, organization: null, dn: null };
    const result = extractCertFields(certFields, { ...signerInfo });
    expect(result.org).toBeUndefined();
  });

  it("returns empty object for empty certFields", () => {
    const signerInfo = { name: "Alice", email: "a@b.com", organization: null, dn: null };
    const result = extractCertFields([], { ...signerInfo });
    expect(Object.keys(result)).toHaveLength(0);
  });

  it("extracts organization via 'org' alias", () => {
    const certFields: CertField[] = [
      { id: "company", source: "org" as CertField["source"], label: "Company" },
    ];
    const signerInfo = { name: null, email: null, organization: "ACME", dn: null };
    const result = extractCertFields(certFields, { ...signerInfo });
    expect(result.company).toBe("ACME");
  });

  it("handles invalid regex gracefully", () => {
    const certFields: CertField[] = [
      { id: "bad", source: "name", label: "Bad", regex: "[invalid(" },
    ];
    const signerInfo = { name: "Alice", email: null, organization: null, dn: null };
    // Should not throw -- the catch in extractCertFields swallows the error
    const result = extractCertFields(certFields, { ...signerInfo });
    expect(result.bad).toBeUndefined();
  });
});

describe("extractDisplayFields", () => {
  it("generates date auto-field", () => {
    const sigFields: SigField[] = [{ auto: "date", label: "Signed" }];
    const certValues = {};
    const result = extractDisplayFields(sigFields, certValues);
    expect(result.length).toBe(1);
    expect(result[0]).toContain("Signed:");
  });

  it("generates cert field references", () => {
    const sigFields: SigField[] = [{ certField: "signer_name", label: "Signer" }];
    const certValues = { signer_name: "Alice" };
    const result = extractDisplayFields(sigFields, certValues);
    expect(result[0]).toBe("Signer: Alice");
  });

  it("generates date auto-field with default label", () => {
    const sigFields: SigField[] = [{ auto: "date" }];
    const result = extractDisplayFields(sigFields, {});
    expect(result).toHaveLength(1);
    expect(result[0]).toMatch(/^Date: /);
  });

  it("skips cert fields with missing values", () => {
    const sigFields: SigField[] = [{ certField: "missing_field", label: "X" }];
    const result = extractDisplayFields(sigFields, {});
    expect(result).toHaveLength(0);
  });

  it("outputs cert field value without label when label is undefined", () => {
    const sigFields: SigField[] = [{ certField: "name" }];
    const result = extractDisplayFields(sigFields, { name: "Bob" });
    expect(result).toHaveLength(1);
    expect(result[0]).toBe("Bob");
  });

  it("handles mixed auto and cert fields", () => {
    const sigFields: SigField[] = [
      { certField: "name" },
      { certField: "gov_id", label: "SSN" },
      { auto: "date" },
    ];
    const certValues = { name: "Alice", gov_id: "12345" };
    const result = extractDisplayFields(sigFields, certValues);
    expect(result).toHaveLength(3);
    expect(result[0]).toBe("Alice");
    expect(result[1]).toBe("SSN: 12345");
    expect(result[2]).toMatch(/^Date: /);
  });

  it("returns empty array for no fields", () => {
    const result = extractDisplayFields([], {});
    expect(result).toHaveLength(0);
  });
});

// -- makeDateStr --------------------------------------------------------------

describe("makeDateStr", () => {
  it("returns a string in expected format", () => {
    const dateStr = makeDateStr();
    // Expected format: "7 Feb 2026, 09:51:42 UTC+4" or similar
    expect(dateStr).toMatch(/^\d{1,2} \w{3} \d{4}, \d{2}:\d{2}:\d{2} UTC/);
  });

  it("contains the current year", () => {
    const dateStr = makeDateStr();
    const currentYear = new Date().getFullYear().toString();
    expect(dateStr).toContain(currentYear);
  });
});

// -- formatUtcOffset ----------------------------------------------------------

describe("formatUtcOffset", () => {
  it("returns 'UTC' for zero offset", () => {
    // Construct a date whose getTimezoneOffset() returns 0
    // We test by passing offsetMinutes=0 indirectly via a frozen date trick,
    // but since the function takes a Date and reads getTimezoneOffset(),
    // we verify the whole-hour path via makeDateStr and test the minutes path
    // by using a Date mock.
    // Direct unit test: spy on a date object's getTimezoneOffset.
    const date = { getTimezoneOffset: () => 0 } as unknown as Date;
    expect(formatUtcOffset(date)).toBe("UTC");
  });

  it("formats whole-hour positive offset", () => {
    // getTimezoneOffset() returns negative of UTC offset: UTC+4 -> -(-240) = 240 offset in minutes
    // But getTimezoneOffset = -(UTC offset), so UTC+4 -> getTimezoneOffset = -240
    const date = { getTimezoneOffset: () => -240 } as unknown as Date;
    expect(formatUtcOffset(date)).toBe("UTC+4");
  });

  it("formats fractional offset with minutes (UTC+5:30)", () => {
    // UTC+5:30 -> offsetMinutes = 330 -> getTimezoneOffset = -330
    const date = { getTimezoneOffset: () => -330 } as unknown as Date;
    expect(formatUtcOffset(date)).toBe("UTC+5:30");
  });

  it("formats fractional offset with minutes (UTC+5:45)", () => {
    // UTC+5:45 -> offsetMinutes = 345 -> getTimezoneOffset = -345
    const date = { getTimezoneOffset: () => -345 } as unknown as Date;
    expect(formatUtcOffset(date)).toBe("UTC+5:45");
  });

  it("formats negative fractional offset (UTC-3:30)", () => {
    // UTC-3:30 -> offsetMinutes = -210 -> getTimezoneOffset = 210
    const date = { getTimezoneOffset: () => 210 } as unknown as Date;
    expect(formatUtcOffset(date)).toBe("UTC-3:30");
  });
});

// -- Appearance stream --------------------------------------------------------

describe("buildAppearanceStream", () => {
  it("generates a PDF stream with text content", async () => {
    const font = await getFont(null);
    const result = await buildAppearanceStream(200, 70, ["Line 1", "Line 2"], false, font);
    expect(result.stream.length).toBeGreaterThan(0);
    expect(result.resources.fontName).toBeTruthy();
    expect(result.bbox).toHaveLength(4);
  });

  it("handles empty fields", async () => {
    const font = await getFont(null);
    const result = await buildAppearanceStream(200, 70, [], false, font);
    expect(result.stream.length).toBeGreaterThan(0);
  });

  it("sets needsImage to true when hasImage is true", async () => {
    const font = await getFont(null);
    const result = await buildAppearanceStream(200, 70, ["Name: Alice"], true, font);
    expect(result.needsImage).toBe(true);
  });

  it("sets needsImage to false when hasImage is false", async () => {
    const font = await getFont(null);
    const result = await buildAppearanceStream(200, 70, ["Name: Alice"], false, font);
    expect(result.needsImage).toBe(false);
  });

  it("includes image command in stream when hasImage is true", async () => {
    const font = await getFont(null);
    const result = await buildAppearanceStream(200, 70, ["Name: Alice"], true, font);
    const streamText = new TextDecoder().decode(result.stream);
    expect(streamText).toContain("/Img1 Do");
  });

  it("does not include image command when hasImage is false", async () => {
    const font = await getFont(null);
    const result = await buildAppearanceStream(200, 70, ["Name: Alice"], false, font);
    const streamText = new TextDecoder().decode(result.stream);
    expect(streamText).not.toContain("/Img1 Do");
  });

  it("uses imageAspect for image layout", async () => {
    const font = await getFont(null);
    const withAspect = await buildAppearanceStream(200, 70, ["Name: Alice"], true, font, 1.5);
    const withoutAspect = await buildAppearanceStream(200, 70, ["Name: Alice"], true, font);
    // Both should produce valid streams; the aspect ratio changes image sizing
    expect(withAspect.stream.length).toBeGreaterThan(0);
    expect(withoutAspect.stream.length).toBeGreaterThan(0);
    // Stream content should differ due to different image dimensions
    const textWith = new TextDecoder().decode(withAspect.stream);
    const textWithout = new TextDecoder().decode(withoutAspect.stream);
    expect(textWith).not.toBe(textWithout);
  });

  it("handles many fields that overflow", async () => {
    const font = await getFont(null);
    const manyFields = [
      "Name: John Doe The Third",
      "Date: 1 January 2026, 12:00:00 UTC+4",
      "Email: john.doe@longdomainname.example.com",
      "Organization: Very Long Organization Name International",
      "SSN: 123456789",
      "Country: AM",
      "Extra Field: Some Additional Content Here",
    ];
    const result = await buildAppearanceStream(180, 60, manyFields, false, font);
    expect(result.stream.length).toBeGreaterThan(0);
    expect(result.bbox).toEqual([0, 0, 180, 60]);
  });

  it("sets correct bbox", async () => {
    const font = await getFont(null);
    const result = await buildAppearanceStream(250, 80, ["Test"], false, font);
    expect(result.bbox).toEqual([0, 0, 250, 80]);
  });

  it("reports bgOpacity", async () => {
    const font = await getFont(null);
    const result = await buildAppearanceStream(200, 70, ["Test"], false, font);
    expect(result.bgOpacity).toBe(0.9);
  });

  it("loads default font when no font provided", async () => {
    const result = await buildAppearanceStream(200, 70, ["Test"], false);
    expect(result.resources.baseFont).toBe("NotoSans");
  });

  it("handles long text that would wrap", async () => {
    const font = await getFont(null);
    const longLine = "A ".repeat(100).trim();
    const result = await buildAppearanceStream(150, 70, [longLine], false, font);
    const streamText = new TextDecoder().decode(result.stream);
    // Multiple Td (text position) commands indicate wrapped lines
    const tdCount = (streamText.match(/Td/g) ?? []).length;
    expect(tdCount).toBeGreaterThan(1);
  });

  it("logs warning when text overflows with image", async () => {
    const font = await getFont(null);
    // Lots of text in a tiny box with image -> triggers overflow warning
    const manyFields = [
      "Name: John Doe The Third Junior",
      "Date: 1 January 2026, 12:00:00 UTC+4",
      "Email: john.doe@verylongdomainname.example.com",
      "Organization: International Corp of Very Long Names",
      "SSN: 123456789",
      "Country: AM",
      "Position: Senior Vice President",
      "Department: Engineering Division",
    ];
    const result = await buildAppearanceStream(160, 40, manyFields, true, font);
    expect(result.stream.length).toBeGreaterThan(0);
    expect(result.needsImage).toBe(true);
  });

  it("handles image with small aspect ratio (tall image)", async () => {
    const font = await getFont(null);
    // imageAspect = 0.1 means very tall image (width/height = 0.1)
    // This should trigger the else branch: drawW = contentH * imageAspect
    const result = await buildAppearanceStream(200, 70, ["Test"], true, font, 0.1);
    const streamText = new TextDecoder().decode(result.stream);
    expect(streamText).toContain("/Img1 Do");
  });
});

// -- loadSignatureImage -------------------------------------------------------

describe("loadSignatureImage", () => {
  it("loads a valid PNG file", async () => {
    const pngPath = join(tmpDir, "test.png");
    writeFileSync(pngPath, PNG_1X1);
    const result = await loadSignatureImage(pngPath);
    expect(result.width).toBe(1);
    expect(result.height).toBe(1);
    expect(result.bpc).toBe(8);
    expect(result.samples.length).toBeGreaterThan(0);
  });

  it("throws for non-existent file", async () => {
    const badPath = join(tmpDir, "no-such-file.png");
    await expect(loadSignatureImage(badPath)).rejects.toThrow("not found");
  });

  it("throws for empty file", async () => {
    const emptyPath = join(tmpDir, "empty.png");
    writeFileSync(emptyPath, Buffer.alloc(0));
    await expect(loadSignatureImage(emptyPath)).rejects.toThrow("empty");
  });

  it("throws for unsupported format", async () => {
    const randomPath = join(tmpDir, "random.bmp");
    writeFileSync(randomPath, Buffer.from([0x42, 0x4d, 0x00, 0x00, 0x00, 0x00]));
    await expect(loadSignatureImage(randomPath)).rejects.toThrow("Unsupported image format");
  });

  it("loads a JPEG file", async () => {
    const jpeg = await import("jpeg-js");
    const rawData = Buffer.alloc(2 * 2 * 4); // 2x2 RGBA
    for (let i = 0; i < rawData.length; i += 4) {
      rawData[i] = 255; // R
      rawData[i + 1] = 0; // G
      rawData[i + 2] = 0; // B
      rawData[i + 3] = 255; // A
    }
    const encoded = jpeg.encode({ data: rawData, width: 2, height: 2 }, 50);
    const jpgPath = join(tmpDir, "test.jpg");
    writeFileSync(jpgPath, encoded.data);

    const result = await loadSignatureImage(jpgPath);
    expect(result.width).toBe(2);
    expect(result.height).toBe(2);
    expect(result.bpc).toBe(8);
    expect(result.samples.length).toBeGreaterThan(0);
    // JPEG has no alpha channel
    expect(result.smask).toBeNull();
  });

  it("loads a PNG with transparency and extracts alpha channel", async () => {
    const { PNG } = await import("pngjs");
    const png = new PNG({ width: 2, height: 2 });
    for (let i = 0; i < 4; i++) {
      const idx = i * 4;
      png.data[idx] = 255; // R
      png.data[idx + 1] = 0; // G
      png.data[idx + 2] = 0; // B
      png.data[idx + 3] = i === 0 ? 0 : 255; // First pixel transparent
    }
    const pngBuffer = PNG.sync.write(png);
    const pngPath = join(tmpDir, "transparent.png");
    writeFileSync(pngPath, pngBuffer);

    const result = await loadSignatureImage(pngPath);
    expect(result.width).toBe(2);
    expect(result.height).toBe(2);
    expect(result.bpc).toBe(8);
    expect(result.samples.length).toBeGreaterThan(0);
    // Has transparency, so smask should not be null
    expect(result.smask).not.toBeNull();
  });

  it("loads an opaque PNG without alpha channel", async () => {
    const { PNG } = await import("pngjs");
    const png = new PNG({ width: 2, height: 2 });
    for (let i = 0; i < 4; i++) {
      const idx = i * 4;
      png.data[idx] = 128; // R
      png.data[idx + 1] = 64; // G
      png.data[idx + 2] = 32; // B
      png.data[idx + 3] = 255; // Fully opaque
    }
    const pngBuffer = PNG.sync.write(png);
    const pngPath = join(tmpDir, "opaque.png");
    writeFileSync(pngPath, pngBuffer);

    const result = await loadSignatureImage(pngPath);
    expect(result.width).toBe(2);
    expect(result.height).toBe(2);
    expect(result.bpc).toBe(8);
    expect(result.samples.length).toBeGreaterThan(0);
    // Fully opaque, so smask should be null
    expect(result.smask).toBeNull();
  });

  it("throws for file exceeding max size", async () => {
    // Create a file slightly over 5MB
    const MAX_FILE_SIZE = 5 * 1024 * 1024;
    const largePath = join(tmpDir, "large.png");
    const largeBuffer = Buffer.alloc(MAX_FILE_SIZE + 1);
    // Write PNG magic bytes so it doesn't fail on format detection first
    largeBuffer[0] = 0x89;
    largeBuffer[1] = 0x50;
    largeBuffer[2] = 0x4e;
    largeBuffer[3] = 0x47;
    writeFileSync(largePath, largeBuffer);

    await expect(loadSignatureImage(largePath)).rejects.toThrow("too large");
  });

  it("throws when decoded PNG pixel count exceeds maximum", async () => {
    // MAX_IMAGE_PIXELS = 2000 * 2000 = 4,000,000
    // Create a 2001x2001 PNG (4,004,001 pixels > limit)
    const { PNG } = await import("pngjs");
    const width = 2001;
    const height = 2001;
    const png = new PNG({ width, height });
    // Fill with a uniform color to allow maximum compression
    png.data.fill(128);
    const pngBuffer = PNG.sync.write(png);
    const pngPath = join(tmpDir, "too-many-pixels.png");
    writeFileSync(pngPath, pngBuffer);

    await expect(loadSignatureImage(pngPath)).rejects.toThrow(/Image too large/);
  });

  it("throws when decoded JPEG pixel count exceeds maximum", async () => {
    // MAX_IMAGE_PIXELS = 2000 * 2000 = 4,000,000
    // Create a 2001x2001 JPEG (4,004,001 pixels > limit)
    const jpeg = await import("jpeg-js");
    const width = 2001;
    const height = 2001;
    const rawData = Buffer.alloc(width * height * 4);
    // Fill with uniform gray to allow JPEG to compress efficiently
    rawData.fill(128);
    const encoded = jpeg.encode({ data: rawData, width, height }, 1);
    const jpgPath = join(tmpDir, "too-many-pixels.jpg");
    writeFileSync(jpgPath, encoded.data);

    await expect(loadSignatureImage(jpgPath)).rejects.toThrow(/Image too large/);
  });

  it("downscales large PNG images to max 200px", async () => {
    const { PNG } = await import("pngjs");
    // Create a 400x300 PNG (will be downscaled)
    const png = new PNG({ width: 400, height: 300 });
    for (let i = 0; i < 400 * 300 * 4; i += 4) {
      png.data[i] = 200; // R
      png.data[i + 1] = 100; // G
      png.data[i + 2] = 50; // B
      png.data[i + 3] = 255; // A
    }
    const pngBuffer = PNG.sync.write(png);
    const pngPath = join(tmpDir, "large-dims.png");
    writeFileSync(pngPath, pngBuffer);

    const result = await loadSignatureImage(pngPath);
    // Max dimension should be 200
    expect(Math.max(result.width, result.height)).toBe(200);
    // Aspect ratio preserved: 400x300 -> 200x150
    expect(result.width).toBe(200);
    expect(result.height).toBe(150);
  });

  it("downscales large JPEG images to max 200px", async () => {
    const jpeg = await import("jpeg-js");
    // Create a 300x400 JPEG (will be downscaled)
    const rawData = Buffer.alloc(300 * 400 * 4);
    for (let i = 0; i < rawData.length; i += 4) {
      rawData[i] = 100; // R
      rawData[i + 1] = 150; // G
      rawData[i + 2] = 200; // B
      rawData[i + 3] = 255; // A
    }
    const encoded = jpeg.encode({ data: rawData, width: 300, height: 400 }, 50);
    const jpgPath = join(tmpDir, "large-dims.jpg");
    writeFileSync(jpgPath, encoded.data);

    const result = await loadSignatureImage(jpgPath);
    // Max dimension should be 200
    expect(Math.max(result.width, result.height)).toBe(200);
    // Aspect ratio preserved: 300x400 -> 150x200
    expect(result.width).toBe(150);
    expect(result.height).toBe(200);
    expect(result.smask).toBeNull();
  });
});

// -- Convenience functions from fonts.ts --------------------------------------

describe("textWidth (convenience)", () => {
  it("measures text using the default font", async () => {
    const width = await textWidth("Hello", 10);
    expect(width).toBeGreaterThan(0);
  });

  it("returns 0 for empty string", async () => {
    const width = await textWidth("", 10);
    expect(width).toBe(0);
  });

  it("scales with font size", async () => {
    const w10 = await textWidth("Hello", 10);
    const w20 = await textWidth("Hello", 20);
    expect(w20).toBeCloseTo(w10 * 2, 1);
  });
});

describe("pdfEscape (convenience)", () => {
  it("escapes text using the default font cmap", async () => {
    const escaped = await pdfEscape("Hi");
    // Should return hex-encoded glyph IDs wrapped in angle brackets
    expect(escaped.startsWith("<")).toBe(true);
    expect(escaped.endsWith(">")).toBe(true);
    // Each character maps to a 4-digit hex glyph ID
    // "Hi" = 2 chars -> 8 hex digits inside the brackets
    const inner = escaped.slice(1, -1);
    expect(inner.length).toBe(8);
  });

  it("returns empty hex string for empty text", async () => {
    const escaped = await pdfEscape("");
    expect(escaped).toBe("<>");
  });
});

describe("encodeTextHex", () => {
  it("encodes ASCII text to hex glyph IDs", async () => {
    const font = await getFont(null);
    const hex = encodeTextHex("A", font.metrics.cmap);
    // Should be a 4-digit hex string (one glyph ID)
    expect(hex.length).toBe(4);
    // Should be uppercase hex
    expect(hex).toMatch(/^[0-9A-F]{4}$/);
  });

  it("maps unknown characters to question mark glyph", async () => {
    const font = await getFont(null);
    // Use a codepoint that's likely not in the font
    const hex = encodeTextHex("\u{1F600}", font.metrics.cmap);
    // Should still produce valid hex (question mark glyph fallback)
    expect(hex.length).toBe(4);
    expect(hex).toMatch(/^[0-9A-F]{4}$/);
  });

  it("produces correct length for multi-character text", async () => {
    const font = await getFont(null);
    const hex = encodeTextHex("Hello", font.metrics.cmap);
    // 5 chars -> 5 glyph IDs -> 20 hex digits
    expect(hex.length).toBe(20);
  });

  it("returns empty string for empty input", async () => {
    const font = await getFont(null);
    const hex = encodeTextHex("", font.metrics.cmap);
    expect(hex).toBe("");
  });
});
