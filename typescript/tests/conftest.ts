/**
 * Shared test fixtures for Revenant test suite.
 */

import { PDFDocument } from "pdf-lib";

import type { SigningTransport } from "../src/network/protocol.js";

/**
 * Fake CMS blob that satisfies length checks (~1792 bytes).
 * Starts with ASN.1 SEQUENCE tag (0x30).
 */
export const FAKE_CMS = new Uint8Array([0x30, 0x82, 0x07, 0x00, ...new Array(1788).fill(0xab)]);

/**
 * Create a mock signing transport with a default URL.
 */
export function createMockTransport(): SigningTransport & { url: string } {
  return {
    url: "https://example.com",
    signHash: vi.fn().mockResolvedValue(FAKE_CMS),
    signData: vi.fn().mockResolvedValue(FAKE_CMS),
    signPdfDetached: vi.fn().mockResolvedValue(FAKE_CMS),
  };
}

/**
 * Create a minimal valid PDF using pdf-lib.
 */
export async function createValidPdf(): Promise<Uint8Array> {
  const pdfDoc = await PDFDocument.create();
  pdfDoc.addPage([612, 792]);
  const bytes = await pdfDoc.save();
  return new Uint8Array(bytes);
}
