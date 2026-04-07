// SPDX-License-Identifier: Apache-2.0
/**
 * ASN.1/DER parsing utilities for CMS signature extraction.
 */

/** ASN.1 SEQUENCE tag -- first byte of any valid CMS/PKCS#7 blob. */
export const ASN1_SEQUENCE_TAG = 0x30;

/**
 * Maximum hex chars for a single CMS blob (16 MB DER = 32M hex chars).
 * Protects against malformed length fields claiming absurd sizes.
 */
const MAX_CMS_HEX_CHARS = 32 * 1024 * 1024;

/** Minimum plausible CMS blob size in bytes (header + basic content). */
export const MIN_CMS_SIZE = 100;

/** End-of-contents octets that terminate BER indefinite-length encoding. */
const EOC_BYTE_0 = 0x00;

/**
 * Extract exact CMS blob from zero-padded hex string.
 *
 * Handles both DER (definite length) and BER (indefinite length)
 * encodings.  The original EKENG cosign tool produces BER-encoded
 * CMS blobs with indefinite length (0x30 0x80 ... 0x00 0x00).
 *
 * For DER: parses the ASN.1 TLV header to determine exact length.
 * For BER indefinite: walks the TLV structure to find the EOC marker.
 */
export function extractDerFromPaddedHex(hexStr: string): Uint8Array {
  if (hexStr.length < 4) {
    throw new Error("Hex string too short for ASN.1 TLV header");
  }

  const tag = parseInt(hexStr.slice(0, 2), 16);
  if (tag !== ASN1_SEQUENCE_TAG) {
    throw new Error(`Expected ASN.1 SEQUENCE (0x30), got 0x${tag.toString(16).padStart(2, "0")}`);
  }

  const lengthByte = parseInt(hexStr.slice(2, 4), 16);
  let headerBytes = 2; // tag + initial length byte
  let contentLen: number;

  if (lengthByte === 0x80) {
    // BER indefinite length encoding (0x30 0x80 ... 0x00 0x00).
    // Walk the TLV structure to find the EOC marker.
    return extractBerIndefinite(hexStr);
  } else if (lengthByte < 0x80) {
    // Short form: lengthByte IS the length
    contentLen = lengthByte;
  } else {
    // Long form: lower 7 bits = number of length bytes
    const numLenBytes = lengthByte & 0x7f;
    if (numLenBytes > 4) {
      throw new Error(`ASN.1 length field too large: ${numLenBytes} bytes`);
    }
    headerBytes += numLenBytes;
    const neededHex = 4 + numLenBytes * 2;
    if (hexStr.length < neededHex) {
      throw new Error("Hex string too short for ASN.1 length field");
    }
    const lenHex = hexStr.slice(4, 4 + numLenBytes * 2);
    contentLen = parseInt(lenHex, 16);
  }

  const totalDerBytes = headerBytes + contentLen;
  const totalHexChars = totalDerBytes * 2;

  if (totalHexChars > MAX_CMS_HEX_CHARS) {
    throw new Error(
      `ASN.1 claims ${totalDerBytes} bytes, exceeds maximum ` + `(${MAX_CMS_HEX_CHARS / 2} bytes)`,
    );
  }

  if (totalHexChars > hexStr.length) {
    throw new Error(
      `ASN.1 length (${totalDerBytes} bytes) exceeds available hex data ` +
        `(${Math.floor(hexStr.length / 2)} bytes)`,
    );
  }

  const derHex = hexStr.slice(0, totalHexChars);
  return Buffer.from(derHex, "hex");
}

/**
 * Extract a BER indefinite-length blob from zero-padded hex.
 *
 * Decodes the full hex, then walks the TLV structure to find
 * where the top-level SEQUENCE's EOC marker (0x00 0x00) is.
 */
function extractBerIndefinite(hexStr: string): Uint8Array {
  const raw = Buffer.from(hexStr, "hex");
  // Start after the top-level tag (0x30) and length (0x80)
  let pos = 2;
  const end = raw.length;

  // Walk top-level children until we hit EOC (0x00 0x00)
  while (pos < end) {
    if (raw[pos] === EOC_BYTE_0 && raw[pos + 1] === EOC_BYTE_0) {
      // Found EOC for the top-level SEQUENCE
      return raw.subarray(0, pos + 2);
    }
    pos = skipTlv(raw, pos, end);
  }

  throw new Error("BER indefinite-length SEQUENCE: EOC marker not found");
}

/**
 * Skip a single TLV element and return the position after it.
 * Handles both definite and indefinite length children.
 */
function skipTlv(data: Uint8Array, pos: number, end: number): number {
  if (pos >= end) {
    throw new Error(`BER parse: unexpected end at offset ${pos}`);
  }

  // Skip tag byte(s)
  const tagByte = data[pos];
  if (tagByte === undefined) {
    throw new Error(`BER parse: unexpected end at offset ${pos}`);
  }
  pos += 1;
  if ((tagByte & 0x1f) === 0x1f) {
    // Multi-byte tag: keep reading until a byte < 0x80
    while (pos < end && ((data[pos] ?? 0) & 0x80) !== 0) {
      pos += 1;
    }
    pos += 1; // final tag byte
  }

  if (pos >= end) {
    throw new Error("BER parse: tag extends beyond data");
  }

  const lengthByte = data[pos];
  if (lengthByte === undefined) {
    throw new Error("BER parse: tag extends beyond data");
  }
  pos += 1;

  if (lengthByte === 0x80) {
    // Indefinite length child -- walk its children until EOC
    while (pos < end) {
      if (data[pos] === EOC_BYTE_0 && data[pos + 1] === EOC_BYTE_0) {
        return pos + 2;
      }
      pos = skipTlv(data, pos, end);
    }
    throw new Error("BER parse: nested indefinite-length without EOC");
  }

  let contentLen: number;
  if (lengthByte < 0x80) {
    contentLen = lengthByte;
  } else {
    const numLenBytes = lengthByte & 0x7f;
    if (pos + numLenBytes > end) {
      throw new Error("BER parse: length field extends beyond data");
    }
    contentLen = 0;
    for (let i = 0; i < numLenBytes; i++) {
      contentLen = (contentLen << 8) | (data[pos + i] ?? 0);
    }
    pos += numLenBytes;
  }

  return pos + contentLen;
}
