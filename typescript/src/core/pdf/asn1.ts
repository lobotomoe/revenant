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

/**
 * Extract exact DER blob from zero-padded hex string.
 *
 * Parses the ASN.1 TLV header to determine exact DER length, avoiding
 * the rstrip("0") approach which corrupts blobs ending in 0x00 bytes.
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

  if (lengthByte < 0x80) {
    // Short form: lengthByte IS the length
    contentLen = lengthByte;
  } else if (lengthByte === 0x80) {
    throw new Error("Indefinite length encoding is not valid in DER");
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
