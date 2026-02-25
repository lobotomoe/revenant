// SPDX-License-Identifier: Apache-2.0
/**
 * Transport protocol abstraction for remote signing services.
 *
 * Defines the interface that signing transports must implement. The core
 * signing logic depends on this protocol, not on concrete implementations.
 */

export interface SigningTransport {
  /** SOAP endpoint URL. Used for enum-certificates discovery. */
  readonly url?: string;

  signData(
    data: Uint8Array,
    username: string,
    password: string,
    timeout: number,
  ): Promise<Uint8Array>;

  signHash(
    hashBytes: Uint8Array,
    username: string,
    password: string,
    timeout: number,
  ): Promise<Uint8Array>;

  signPdfDetached(
    pdfBytes: Uint8Array,
    username: string,
    password: string,
    timeout: number,
  ): Promise<Uint8Array>;
}
