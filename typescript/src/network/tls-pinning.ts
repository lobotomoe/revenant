// SPDX-License-Identifier: Apache-2.0
/**
 * Server key pinning for connections that cannot use the public PKI.
 *
 * A pin is the SHA-256 digest of a certificate's SubjectPublicKeyInfo, written
 * as lowercase hex. Pinning the key rather than the whole certificate lets a
 * server be issued a fresh certificate for the same key without invalidating
 * the pin, and a profile may carry several pins so a key rotation can be
 * staged.
 *
 * This is how the legacy TLS transport authenticates its peer. Appliances that
 * require TLS 1.0 with RC4 typically present a self-signed factory certificate
 * whose subject does not name the host it serves, so no certificate authority
 * vouches for it and no hostname check can succeed -- a pinned key is the only
 * thing that can distinguish the real appliance from anyone speaking for it.
 */

import { createHash } from "node:crypto";

import { TLSError } from "../errors.js";

/** SHA-256 of a DER-encoded SubjectPublicKeyInfo, as lowercase hex. */
export function spkiFingerprint(spkiDer: Uint8Array): string {
  return createHash("sha256").update(spkiDer).digest("hex");
}

/** Strip the formatting operators write pins with, so comparison is on content. */
function normalisePin(pin: string): string {
  return pin.trim().toLowerCase().replaceAll(":", "");
}

/**
 * Verify that a server's key matches one of the configured pins.
 *
 * @param spkiDer The SubjectPublicKeyInfo from the certificate the server sent.
 * @param pins Accepted pins. Empty means the server has no declared identity,
 *   which is refused rather than assumed benign.
 * @param host Server hostname, for the error message.
 * @param port Server port, for the error message.
 * @throws TLSError If no pin is configured, or none of them matches.
 */
export function checkServerPin(
  spkiDer: Uint8Array,
  pins: readonly string[],
  host: string,
  port: number,
): void {
  const actual = spkiFingerprint(spkiDer);

  if (pins.length === 0) {
    throw new TLSError(
      `No pinned key configured for ${host}:${port}. Legacy TLS does not ` +
        "authenticate the server on its own, so a pinned key is required " +
        "before anything is sent.\n" +
        `The server currently presents: ${actual}\n` +
        "If that is your appliance, record it as the profile's tlsPins.",
    );
  }

  const normalised = pins.map(normalisePin);
  if (normalised.includes(actual)) {
    return;
  }

  throw new TLSError(
    `The key presented by ${host}:${port} is not one of its pinned keys. ` +
      "Refusing to continue.\n" +
      `  presented: ${actual}\n` +
      `  pinned:    ${normalised.join(", ")}\n` +
      "Either the server's key changed, or this is not the server it claims to be.",
  );
}
