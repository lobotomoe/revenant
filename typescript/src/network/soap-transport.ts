// SPDX-License-Identifier: Apache-2.0
/**
 * SOAP-based signing transport implementation.
 *
 * Implements SigningTransport interface for CoSign SOAP services.
 */

import { logger } from "../logger.js";
import type { SigningTransport } from "./protocol.js";
import {
  buildEnumCertificatesEnvelope,
  buildSignEnvelope,
  buildSignHashEnvelope,
  buildVerifyEnvelope,
  parseEnumCertificatesResponse,
  parseSignResponse,
  parseVerifyResponse,
  type ServerVerifyResult,
  SIGNATURE_TYPE_CMS,
  sendSoap,
} from "./soap.js";

function toBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

export class SoapSigningTransport implements SigningTransport {
  readonly url: string;

  constructor(url: string) {
    this.url = url;
  }

  private async sendAndParse(envelope: string, timeout: number): Promise<Uint8Array> {
    const response = await sendSoap(this.url, envelope, "DssSign", timeout);
    return parseSignResponse(response);
  }

  async signData(
    data: Uint8Array,
    username: string,
    password: string,
    timeout: number,
  ): Promise<Uint8Array> {
    const dataB64 = toBase64(data);
    const envelope = buildSignEnvelope(username, password, SIGNATURE_TYPE_CMS, dataB64);
    return this.sendAndParse(envelope, timeout);
  }

  async signHash(
    hashBytes: Uint8Array,
    username: string,
    password: string,
    timeout: number,
  ): Promise<Uint8Array> {
    const hashB64 = toBase64(hashBytes);
    const envelope = buildSignHashEnvelope(username, password, SIGNATURE_TYPE_CMS, hashB64);
    return this.sendAndParse(envelope, timeout);
  }

  async signPdfDetached(
    pdfBytes: Uint8Array,
    username: string,
    password: string,
    timeout: number,
  ): Promise<Uint8Array> {
    const pdfB64 = toBase64(pdfBytes);
    const envelope = buildSignEnvelope(username, password, SIGNATURE_TYPE_CMS, pdfB64);
    return this.sendAndParse(envelope, timeout);
  }
}

export async function verifyPdfServer(
  url: string,
  pdfBytes: Uint8Array,
  timeout: number,
): Promise<ServerVerifyResult> {
  try {
    const pdfB64 = toBase64(pdfBytes);
    const envelope = buildVerifyEnvelope(pdfB64);
    const response = await sendSoap(url, envelope, "DssVerify", timeout);
    return parseVerifyResponse(response);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    logger.warn(`Server verify failed: ${msg}`);
    return {
      valid: false,
      signerName: null,
      signTime: null,
      certificateStatus: null,
      error: msg,
    };
  }
}

export async function enumCertificates(
  url: string,
  username: string,
  password: string,
  timeout: number,
): Promise<Uint8Array[]> {
  const envelope = buildEnumCertificatesEnvelope(username, password);
  const response = await sendSoap(url, envelope, "DssSign", timeout);
  return parseEnumCertificatesResponse(response);
}
