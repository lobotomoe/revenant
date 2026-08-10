/**
 * Tests for reading image dimensions out of file headers without decoding.
 */

import { describe, expect, it } from "vitest";
import { readJpegDimensions, readPngDimensions } from "../src/core/appearance/image-header.js";

/** A valid 1x1 PNG (red pixel, fully opaque), generated with pngjs. */
const PNG_1X1 = Buffer.from(
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4AWP4z8DwHwAFAAH/e+m+7wAAAABJRU5ErkJggg==",
  "base64",
);

describe("readPngDimensions", () => {
  it("reads dimensions from the IHDR chunk", () => {
    expect(readPngDimensions(PNG_1X1)).toEqual({ width: 1, height: 1 });
  });

  it("reads dimensions from a header alone, without the pixel data", () => {
    const headerOnly = PNG_1X1.subarray(0, 24);
    expect(readPngDimensions(headerOnly)).toEqual({ width: 1, height: 1 });
  });

  it("rejects a file too short to hold a header", () => {
    expect(() => readPngDimensions(PNG_1X1.subarray(0, 23))).toThrow("too short");
  });

  it("rejects a bad signature", () => {
    const corrupted = Buffer.from(PNG_1X1);
    corrupted[1] = 0x00;
    expect(() => readPngDimensions(corrupted)).toThrow("bad file signature");
  });

  it("rejects a first chunk that is not IHDR", () => {
    const corrupted = Buffer.from(PNG_1X1);
    corrupted.write("IDAT", 12, "ascii");
    expect(() => readPngDimensions(corrupted)).toThrow("expected IHDR");
  });
});

/** Build a JPEG carrying only the markers needed to declare a frame size. */
function jpegWithFrame(width: number, height: number, marker = 0xc0): Buffer {
  const sof = Buffer.alloc(11);
  sof.writeUInt16BE(0xff00 | marker, 0);
  sof.writeUInt16BE(9, 2); // segment length
  sof.writeUInt8(8, 4); // sample precision
  sof.writeUInt16BE(height, 5);
  sof.writeUInt16BE(width, 7);
  sof.writeUInt8(1, 9); // component count
  return Buffer.concat([Buffer.from([0xff, 0xd8]), sof]);
}

describe("readJpegDimensions", () => {
  it("reads dimensions from a baseline frame header", () => {
    expect(readJpegDimensions(jpegWithFrame(640, 480))).toEqual({ width: 640, height: 480 });
  });

  it("reads dimensions from a progressive frame header", () => {
    expect(readJpegDimensions(jpegWithFrame(640, 480, 0xc2))).toEqual({ width: 640, height: 480 });
  });

  it("skips application segments before the frame header", () => {
    const app0 = Buffer.from([0xff, 0xe0, 0x00, 0x06, 0x4a, 0x46, 0x49, 0x46]);
    const framed = jpegWithFrame(320, 200);
    const withApp = Buffer.concat([framed.subarray(0, 2), app0, framed.subarray(2)]);
    expect(readJpegDimensions(withApp)).toEqual({ width: 320, height: 200 });
  });

  it("does not mistake a huffman table for a frame header", () => {
    // 0xC4 sits inside the 0xC0-0xCF range but is DHT, not a frame header.
    const dht = Buffer.from([0xff, 0xc4, 0x00, 0x04, 0x00, 0x00]);
    const framed = jpegWithFrame(320, 200);
    const withDht = Buffer.concat([framed.subarray(0, 2), dht, framed.subarray(2)]);
    expect(readJpegDimensions(withDht)).toEqual({ width: 320, height: 200 });
  });

  it("rejects a bad signature", () => {
    expect(() => readJpegDimensions(Buffer.from([0xff, 0xd9, 0x00, 0x00]))).toThrow(
      "bad file signature",
    );
  });

  it("rejects scan data that arrives before any frame header", () => {
    const sos = Buffer.from([0xff, 0xd8, 0xff, 0xda, 0x00, 0x02]);
    expect(() => readJpegDimensions(sos)).toThrow("scan data begins before");
  });

  it("rejects a truncated frame header", () => {
    const truncated = jpegWithFrame(640, 480).subarray(0, 8);
    expect(() => readJpegDimensions(truncated)).toThrow("truncated frame header");
  });

  it("rejects stray data where a marker was expected", () => {
    const stray = Buffer.from([0xff, 0xd8, 0x00, 0x01, 0x02, 0x03]);
    expect(() => readJpegDimensions(stray)).toThrow("expected a marker");
  });

  it("rejects a stream that ends on a fill byte", () => {
    const dangling = Buffer.from([0xff, 0xd8, 0xff, 0xff]);
    expect(() => readJpegDimensions(dangling)).toThrow("truncated before the frame header");
  });

  it("rejects a segment whose length field is cut off", () => {
    const cut = Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0x00]);
    expect(() => readJpegDimensions(cut)).toThrow("truncated segment length");
  });

  it("rejects a segment length that cannot include itself", () => {
    const tooShort = Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x01]);
    expect(() => readJpegDimensions(tooShort)).toThrow("invalid segment length");
  });

  it("skips a standalone restart marker", () => {
    const rst = Buffer.from([0xff, 0xd0]);
    const framed = jpegWithFrame(64, 48);
    const withRst = Buffer.concat([framed.subarray(0, 2), rst, framed.subarray(2)]);
    expect(readJpegDimensions(withRst)).toEqual({ width: 64, height: 48 });
  });

  it("rejects a stream that ends without a frame header", () => {
    const app0 = Buffer.from([0xff, 0xe0, 0x00, 0x04, 0x00, 0x00]);
    const noFrame = Buffer.concat([Buffer.from([0xff, 0xd8]), app0]);
    expect(() => readJpegDimensions(noFrame)).toThrow("no frame header found");
  });
});
