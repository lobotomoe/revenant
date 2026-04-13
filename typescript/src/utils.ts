// SPDX-License-Identifier: Apache-2.0
/** Shared low-level utility functions. */

/** Convert a Uint8Array to a lowercase hex string. */
export function bytesToHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

/** Get a proper ArrayBuffer from a Uint8Array (avoids SharedArrayBuffer issues). */
export function toArrayBuffer(data: Uint8Array): ArrayBuffer {
  const buf = new ArrayBuffer(data.byteLength);
  new Uint8Array(buf).set(data);
  return buf;
}
