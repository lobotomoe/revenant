// SPDX-License-Identifier: Apache-2.0
/**
 * Image loading and preparation for PDF signature fields.
 *
 * Loads PNG/JPEG images, downscales if needed, extracts alpha channels,
 * and returns deflate-compressed pixel data ready for PDF embedding.
 */

import { readFileSync, statSync } from "node:fs";
import { resolve } from "node:path";
import { deflateSync } from "node:zlib";

export interface SignatureImageData {
  samples: Uint8Array; // Deflate-compressed RGB pixel data
  smask: Uint8Array | null; // Deflate-compressed alpha channel
  width: number;
  height: number;
  bpc: number; // Bits per component (always 8)
}

/** Maximum image dimension in pixels before downscaling. */
const MAX_IMAGE_PX = 200;

/** Maximum input file size (5 MB). */
const MAX_FILE_SIZE = 5 * 1024 * 1024;

/** Maximum pixel count to prevent decompression bombs. */
const MAX_IMAGE_PIXELS = 2000 * 2000;

/**
 * Load an image file and prepare it for embedding in a PDF signature.
 *
 * Supports PNG (with transparency) and JPEG.
 * Images are downscaled if larger than 200px on any side.
 */
export async function loadSignatureImage(imagePath: string): Promise<SignatureImageData> {
  const fullPath = resolve(imagePath);

  let stat: ReturnType<typeof statSync>;
  try {
    stat = statSync(fullPath);
  } catch {
    throw new Error(`Signature image not found: ${fullPath}`);
  }

  if (stat.size > MAX_FILE_SIZE) {
    const sizeMb = (stat.size / 1024 / 1024).toFixed(1);
    const maxMb = (MAX_FILE_SIZE / 1024 / 1024).toFixed(0);
    throw new Error(`Signature image too large: ${sizeMb} MB (max ${maxMb} MB)`);
  }
  if (stat.size === 0) {
    throw new Error("Signature image file is empty");
  }

  const data = readFileSync(fullPath);

  // Detect format by magic bytes
  if (isPng(data)) {
    return loadPng(data);
  }
  if (isJpeg(data)) {
    return loadJpeg(data);
  }

  throw new Error("Unsupported image format. Supported: PNG, JPEG");
}

function isPng(data: Buffer): boolean {
  return (
    data.length > 8 && data[0] === 0x89 && data[1] === 0x50 && data[2] === 0x4e && data[3] === 0x47
  );
}

function isJpeg(data: Buffer): boolean {
  return data.length > 2 && data[0] === 0xff && data[1] === 0xd8;
}

async function loadPng(data: Buffer): Promise<SignatureImageData> {
  const { PNG } = await import("pngjs");

  const png = PNG.sync.read(data);

  if (png.width * png.height > MAX_IMAGE_PIXELS) {
    throw new Error(
      `Image too large: ${png.width}x${png.height}. Maximum: ${MAX_IMAGE_PIXELS} pixels.`,
    );
  }

  // Downscale if needed
  let pixels: Uint8Array | Buffer = png.data;
  let w = png.width;
  let h = png.height;
  const maxDim = Math.max(w, h);
  if (maxDim > MAX_IMAGE_PX) {
    const scale = MAX_IMAGE_PX / maxDim;
    const newW = Math.max(1, Math.round(w * scale));
    const newH = Math.max(1, Math.round(h * scale));
    pixels = nearestNeighborResize(pixels, w, h, newW, newH, 4);
    w = newW;
    h = newH;
  }

  // Extract alpha if present, separate RGB
  const pixelCount = w * h;
  const rgb = new Uint8Array(pixelCount * 3);
  let hasAlpha = false;
  let alpha: Uint8Array | null = null;

  // Check if any pixel has non-255 alpha
  for (let i = 0; i < pixelCount; i++) {
    if (pixels[i * 4 + 3] !== 255) {
      hasAlpha = true;
      break;
    }
  }

  if (hasAlpha) {
    alpha = new Uint8Array(pixelCount);
    for (let i = 0; i < pixelCount; i++) {
      const base = i * 4;
      rgb[i * 3] = pixels[base] ?? 0;
      rgb[i * 3 + 1] = pixels[base + 1] ?? 0;
      rgb[i * 3 + 2] = pixels[base + 2] ?? 0;
      alpha[i] = pixels[base + 3] ?? 0;
    }
  } else {
    for (let i = 0; i < pixelCount; i++) {
      const base = i * 4;
      rgb[i * 3] = pixels[base] ?? 0;
      rgb[i * 3 + 1] = pixels[base + 1] ?? 0;
      rgb[i * 3 + 2] = pixels[base + 2] ?? 0;
    }
  }

  return {
    samples: deflateSync(rgb),
    smask: alpha ? deflateSync(alpha) : null,
    width: w,
    height: h,
    bpc: 8,
  };
}

async function loadJpeg(data: Buffer): Promise<SignatureImageData> {
  const jpeg = await import("jpeg-js");
  const decoded = jpeg.decode(data, { useTArray: true });

  if (decoded.width * decoded.height > MAX_IMAGE_PIXELS) {
    throw new Error(
      `Image too large: ${decoded.width}x${decoded.height}. Maximum: ${MAX_IMAGE_PIXELS} pixels.`,
    );
  }

  let pixels: Uint8Array | Buffer = decoded.data;
  let w = decoded.width;
  let h = decoded.height;
  const maxDim = Math.max(w, h);
  if (maxDim > MAX_IMAGE_PX) {
    const scale = MAX_IMAGE_PX / maxDim;
    const newW = Math.max(1, Math.round(w * scale));
    const newH = Math.max(1, Math.round(h * scale));
    pixels = nearestNeighborResize(pixels, w, h, newW, newH, 4);
    w = newW;
    h = newH;
  }

  // JPEG has no alpha -- extract RGB only
  const pixelCount = w * h;
  const rgb = new Uint8Array(pixelCount * 3);
  for (let i = 0; i < pixelCount; i++) {
    const base = i * 4;
    rgb[i * 3] = pixels[base] ?? 0;
    rgb[i * 3 + 1] = pixels[base + 1] ?? 0;
    rgb[i * 3 + 2] = pixels[base + 2] ?? 0;
  }

  return {
    samples: deflateSync(rgb),
    smask: null,
    width: w,
    height: h,
    bpc: 8,
  };
}

/**
 * Nearest-neighbor resize for RGBA pixel data.
 */
function nearestNeighborResize(
  src: Uint8Array | Buffer,
  srcW: number,
  srcH: number,
  dstW: number,
  dstH: number,
  channels: number,
): Uint8Array {
  const dst = new Uint8Array(dstW * dstH * channels);
  for (let y = 0; y < dstH; y++) {
    const srcY = Math.floor((y * srcH) / dstH);
    for (let x = 0; x < dstW; x++) {
      const srcX = Math.floor((x * srcW) / dstW);
      const srcIdx = (srcY * srcW + srcX) * channels;
      const dstIdx = (y * dstW + x) * channels;
      for (let c = 0; c < channels; c++) {
        dst[dstIdx + c] = src[srcIdx + c] ?? 0;
      }
    }
  }
  return dst;
}
