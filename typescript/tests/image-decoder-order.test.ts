/**
 * The pixel budget must be enforced before a decoder runs.
 *
 * A size check that happens after decoding is not a size check: the decoder
 * has already allocated width * height * 4 bytes by the time it returns.
 * These tests stub both decoders so that reaching one is itself the failure,
 * which pins the ordering rather than the eventual error message -- the
 * message is the same either way.
 */

import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { crc32 } from "node:zlib";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { loadSignatureImage } from "../src/core/appearance/index.js";

const DECODER_REACHED = "decoder was reached";

vi.mock("pngjs", () => ({
  PNG: {
    sync: {
      read: () => {
        throw new Error(DECODER_REACHED);
      },
    },
  },
}));

vi.mock("jpeg-js", () => ({
  decode: () => {
    throw new Error(DECODER_REACHED);
  },
}));

/** A valid 1x1 PNG (red pixel, fully opaque), generated with pngjs. */
const PNG_1X1 = Buffer.from(
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4AWP4z8DwHwAFAAH/e+m+7wAAAABJRU5ErkJggg==",
  "base64",
);

/** A PNG header claiming the given dimensions, with a corrected IHDR checksum. */
function pngClaiming(width: number, height: number): Buffer {
  const png = Buffer.from(PNG_1X1);
  png.writeUInt32BE(width, 16);
  png.writeUInt32BE(height, 20);
  png.writeUInt32BE(crc32(png.subarray(12, 29)), 29);
  return png;
}

/** A JPEG carrying a baseline frame header claiming the given dimensions. */
function jpegClaiming(width: number, height: number): Buffer {
  const sof = Buffer.alloc(11);
  sof.writeUInt16BE(0xffc0, 0);
  sof.writeUInt16BE(9, 2); // segment length
  sof.writeUInt8(8, 4); // sample precision
  sof.writeUInt16BE(height, 5);
  sof.writeUInt16BE(width, 7);
  sof.writeUInt8(1, 9); // component count
  return Buffer.concat([Buffer.from([0xff, 0xd8]), sof]);
}

let tmpDir: string;

beforeAll(() => {
  tmpDir = mkdtempSync(join(tmpdir(), "revenant-decoder-order-"));
});

afterAll(() => {
  rmSync(tmpDir, { recursive: true, force: true });
});

function write(name: string, data: Buffer): string {
  const path = join(tmpDir, name);
  writeFileSync(path, data);
  return path;
}

describe("pixel budget enforcement order", () => {
  it("refuses an oversized PNG without calling the decoder", async () => {
    const path = write("oversized.png", pngClaiming(12000, 12000));
    await expect(loadSignatureImage(path)).rejects.toThrow("Image too large: 12000x12000");
  });

  it("refuses an oversized JPEG without calling the decoder", async () => {
    const path = write("oversized.jpg", jpegClaiming(20000, 20000));
    await expect(loadSignatureImage(path)).rejects.toThrow("Image too large: 20000x20000");
  });

  it("reaches the PNG decoder for an image within budget", async () => {
    // Proves the stub is wired in, so the refusals above are not vacuous.
    const path = write("small.png", PNG_1X1);
    await expect(loadSignatureImage(path)).rejects.toThrow(DECODER_REACHED);
  });

  it("reaches the JPEG decoder for an image within budget", async () => {
    const path = write("small.jpg", jpegClaiming(64, 64));
    await expect(loadSignatureImage(path)).rejects.toThrow(DECODER_REACHED);
  });
});
