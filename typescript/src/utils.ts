// SPDX-License-Identifier: Apache-2.0
/** Shared low-level utility functions. */

/** Convert a Uint8Array to a lowercase hex string. */
export function bytesToHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}
