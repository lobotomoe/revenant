// SPDX-License-Identifier: Apache-2.0
/**
 * Image dimensions read from file headers, without decoding pixel data.
 *
 * Decoders allocate width * height * channels bytes before returning, so a
 * pixel budget can only be enforced if the dimensions are known beforehand.
 * These readers parse just enough of the header to answer that question.
 */

/** PNG signature: the eight bytes every PNG file starts with. */
const PNG_SIGNATURE = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];

/** Offset of the IHDR chunk type; PNG mandates IHDR as the first chunk. */
const PNG_IHDR_TYPE_OFFSET = 12;

/** Offset of the IHDR width field (chunk type is followed by width, height). */
const PNG_IHDR_WIDTH_OFFSET = 16;

/** Bytes needed to reach the end of the IHDR height field. */
const PNG_HEADER_LENGTH = 24;

export interface ImageDimensions {
  width: number;
  height: number;
}

/**
 * Read the pixel dimensions of a PNG from its IHDR chunk.
 *
 * @throws If the signature or IHDR chunk is missing or truncated.
 */
export function readPngDimensions(data: Uint8Array): ImageDimensions {
  if (data.length < PNG_HEADER_LENGTH) {
    throw new Error("Malformed PNG: file is too short to contain a header");
  }
  for (let i = 0; i < PNG_SIGNATURE.length; i++) {
    if (data[i] !== PNG_SIGNATURE[i]) {
      throw new Error("Malformed PNG: bad file signature");
    }
  }
  const chunkType = String.fromCharCode(
    ...data.subarray(PNG_IHDR_TYPE_OFFSET, PNG_IHDR_TYPE_OFFSET + 4),
  );
  if (chunkType !== "IHDR") {
    throw new Error(`Malformed PNG: expected IHDR as the first chunk, found ${chunkType}`);
  }
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  return {
    width: view.getUint32(PNG_IHDR_WIDTH_OFFSET),
    height: view.getUint32(PNG_IHDR_WIDTH_OFFSET + 4),
  };
}

/** Markers in the 0xC0-0xCF range that are not start-of-frame. */
const JPEG_NON_SOF_MARKERS = [0xc4, 0xc8, 0xcc];

/** Markers that carry no payload segment and are simply skipped. */
const JPEG_STANDALONE_MARKERS = [0x01, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9];

/** Start of scan -- entropy-coded data follows, so header parsing must stop. */
const JPEG_SOS_MARKER = 0xda;

function isStartOfFrame(marker: number): boolean {
  const inRange = marker >= 0xc0 && marker <= 0xcf;
  return inRange && !JPEG_NON_SOF_MARKERS.some((m) => m === marker);
}

/**
 * Read the pixel dimensions of a JPEG from its start-of-frame segment.
 *
 * Walks the marker segments preceding the scan data; every JPEG variant,
 * baseline or progressive, declares a start-of-frame before its first scan.
 *
 * @throws If the file is truncated or carries no start-of-frame segment.
 */
export function readJpegDimensions(data: Uint8Array): ImageDimensions {
  if (data.length < 4 || data[0] !== 0xff || data[1] !== 0xd8) {
    throw new Error("Malformed JPEG: bad file signature");
  }
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);

  let offset = 2;
  while (offset < data.length) {
    if (data[offset] !== 0xff) {
      throw new Error("Malformed JPEG: expected a marker, found stray data");
    }
    // Any number of 0xFF fill bytes may precede the marker identifier.
    while (offset < data.length && data[offset] === 0xff) {
      offset++;
    }
    const marker = data[offset];
    if (marker === undefined) {
      throw new Error("Malformed JPEG: truncated before the frame header");
    }
    offset++;

    if (JPEG_STANDALONE_MARKERS.some((m) => m === marker)) {
      continue;
    }
    if (marker === JPEG_SOS_MARKER) {
      throw new Error("Malformed JPEG: scan data begins before any frame header");
    }
    if (offset + 2 > data.length) {
      throw new Error("Malformed JPEG: truncated segment length");
    }
    const segmentLength = view.getUint16(offset);
    if (segmentLength < 2) {
      throw new Error("Malformed JPEG: invalid segment length");
    }

    if (isStartOfFrame(marker)) {
      // Segment layout: length (2), sample precision (1), height (2), width (2).
      if (offset + 7 > data.length) {
        throw new Error("Malformed JPEG: truncated frame header");
      }
      return {
        height: view.getUint16(offset + 3),
        width: view.getUint16(offset + 5),
      };
    }
    offset += segmentLength;
  }

  throw new Error("Malformed JPEG: no frame header found");
}
