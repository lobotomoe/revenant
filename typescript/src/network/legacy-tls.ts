// SPDX-License-Identifier: Apache-2.0
/**
 * Legacy TLS transport using node-forge.
 *
 * Some CoSign appliances (notably EKENG's ca.gov.am) require TLSv1.0 with
 * RC4-MD5 -- a cipher suite removed from OpenSSL 3.x. This module provides
 * a raw HTTP-over-TLS implementation using node-forge's pure-JS TLS stack.
 */

import * as net from "node:net";
import * as forgeNamespace from "node-forge";
import "./rc4-cipher-suite.js"; // Register RC4 cipher suites with node-forge TLS

// node-forge is CJS. When loaded via dynamic import() chain, named exports
// may be undefined — only the default export works. Handle both cases.
const forge =
  (forgeNamespace as Record<string, unknown>).tls !== undefined
    ? forgeNamespace
    : ((forgeNamespace as Record<string, unknown>).default as typeof forgeNamespace);

import { BYTES_PER_MB, DEFAULT_TIMEOUT_LEGACY_TLS, MAX_RESPONSE_SIZE } from "../constants.js";
import { isNodeError, RevenantError, TLSError } from "../errors.js";
import { logger } from "../logger.js";
import { checkServerPin } from "./tls-pinning.js";

const STANDARD_PORTS = new Set([80, 443]);

function parseStatusCode(statusLine: string): number {
  const parts = statusLine.split(/\s+/, 3);
  if (parts.length >= 2) {
    const statusPart = parts[1];
    if (statusPart !== undefined) {
      const code = parseInt(statusPart, 10);
      if (!Number.isNaN(code)) return code;
    }
  }
  throw new TLSError(`Cannot parse HTTP status line: ${JSON.stringify(statusLine)}`);
}

/**
 * Re-encode a certificate's public key as a DER SubjectPublicKeyInfo.
 *
 * node-forge exposes the parsed key rather than the original bytes, so this
 * writes the structure back out. SubjectPublicKeyInfo has one valid DER
 * encoding, which is why the digest still matches one taken from the wire.
 */
function subjectPublicKeyInfoDer(cert: forgeNamespace.pki.Certificate): Uint8Array {
  const spki = forge.pki.publicKeyToAsn1(cert.publicKey);
  const der = forge.asn1.toDer(spki).getBytes();
  return Uint8Array.from(der, (ch) => ch.charCodeAt(0));
}

function validateHeaderValue(name: string, value: string): string {
  if (value.includes("\r") || value.includes("\n")) {
    throw new TLSError(`HTTP header '${name}' contains invalid CR/LF characters`);
  }
  return value;
}

export async function legacyRequest(
  method: "GET" | "POST",
  url: string,
  options: {
    body?: Uint8Array;
    headers?: Record<string, string>;
    timeout?: number;
    /**
     * Accepted server keys. Checked as soon as the certificate arrives and
     * before anything is sent; an empty list is refused rather than treated
     * as "any key".
     */
    pins: readonly string[];
  },
): Promise<Uint8Array> {
  const parsed = new URL(url);
  const host = parsed.hostname;
  const port = parsed.port ? parseInt(parsed.port, 10) : 443;
  let path = parsed.pathname || "/";
  if (parsed.search) {
    path = `${path}${parsed.search}`;
  }

  if (!host) {
    throw new TLSError(`Invalid URL: ${url}`);
  }

  const timeout = options.timeout ?? DEFAULT_TIMEOUT_LEGACY_TLS;
  const body = options.body;
  const extraHeaders = options.headers;
  const pins = options.pins;

  return new Promise<Uint8Array>((resolve, reject) => {
    // The pin check runs inside node-forge's verify callback, which can only
    // answer yes or no. The reason is kept here so the rejection says why.
    let pinFailure: Error | null = null;

    const timer = setTimeout(() => {
      socket.destroy();
      reject(
        new TLSError(`Connection timed out after ${timeout}s. Is the server reachable?`, {
          retryable: true,
        }),
      );
    }, timeout * 1000);

    const socket = net.createConnection({ host, port }, () => {
      // Socket connected, start TLS handshake
      const tls = forge.tls.createConnection({
        server: false,
        verify: (_connection, _verified, depth, certs) => {
          // The chain cannot be validated -- these appliances present a
          // self-signed certificate no authority vouches for -- so the
          // pinned key stands in for the whole of PKI. certs[0] is the
          // end-entity certificate at every depth; check it once.
          if (depth !== 0) {
            return true;
          }
          const leaf = certs[0];
          if (leaf === undefined) {
            pinFailure = new TLSError(
              `${host}:${port} completed a handshake without presenting a certificate`,
            );
            return { message: pinFailure.message };
          }
          try {
            checkServerPin(subjectPublicKeyInfoDer(leaf), pins, host, port);
          } catch (err) {
            pinFailure = err instanceof Error ? err : new TLSError(String(err));
            return { message: pinFailure.message };
          }
          return true;
        },
        connected: (connection) => {
          // TLS handshake complete, send HTTP request
          logger.info(
            `Legacy TLS (TLS 1.0 + RC4) established with ${host}:${port} against a pinned key`,
          );

          const hostHeader = STANDARD_PORTS.has(port) ? host : `${host}:${port}`;
          const allHeaders: Record<string, string> = {
            Host: hostHeader,
            Connection: "close",
          };
          if (body) {
            allHeaders["Content-Length"] = String(body.length);
          }
          if (extraHeaders) {
            Object.assign(allHeaders, extraHeaders);
          }

          const headerLines = Object.entries(allHeaders)
            .map(([k, v]) => `${k}: ${validateHeaderValue(k, v)}`)
            .join("\r\n");
          const requestStr = `${method} ${path} HTTP/1.0\r\n${headerLines}\r\n\r\n`;
          connection.prepare(requestStr);
          if (body) {
            // Convert Uint8Array to binary string without spread operator
            // (spread causes RangeError for large arrays)
            let binaryStr = "";
            for (let i = 0; i < body.length; i++) {
              binaryStr += String.fromCharCode(body[i] ?? 0);
            }
            const bodyBuf = forge.util.createBuffer(binaryStr);
            connection.prepare(bodyBuf.getBytes());
          }
        },
        tlsDataReady: (connection) => {
          const data = connection.tlsData.getBytes();
          socket.write(data, "binary");
        },
        dataReady: (connection) => {
          responseBuffer += connection.data.getBytes();
          const totalSize = responseBuffer.length;
          if (totalSize > MAX_RESPONSE_SIZE) {
            clearTimeout(timer);
            socket.destroy();
            reject(
              new TLSError(
                `Response from ${host}:${port} exceeds ${MAX_RESPONSE_SIZE / BYTES_PER_MB} MB limit`,
              ),
            );
          }
        },
        closed: () => {
          clearTimeout(timer);
          try {
            const result = parseResponse(responseBuffer, host, port);
            resolve(result);
          } catch (err) {
            reject(err);
          }
        },
        error: (_connection, error) => {
          clearTimeout(timer);
          socket.destroy();
          // A rejected pin surfaces here as a generic bad-certificate alert;
          // report what actually went wrong instead.
          reject(pinFailure ?? new TLSError(`TLS error with ${host}:${port}: ${error.message}`));
        },
      });

      let responseBuffer = "";

      socket.on("data", (data) => {
        tls.process(data.toString("binary"));
      });

      socket.on("end", () => {
        tls.close();
      });

      // Initiate TLS ClientHello -- must be called after creating the
      // connection and registering the data handler.
      tls.handshake();
    });

    socket.on("error", (err) => {
      clearTimeout(timer);
      if (isNodeError(err, "ETIMEDOUT")) {
        reject(
          new TLSError(`Connection timed out after ${timeout}s. Is the server reachable?`, {
            retryable: true,
          }),
        );
      } else {
        reject(
          new TLSError(`Cannot connect to ${host}:${port}: ${err.message}`, {
            retryable: true,
          }),
        );
      }
    });

    socket.setTimeout(timeout * 1000, () => {
      socket.destroy();
      reject(
        new TLSError(`Connection timed out after ${timeout}s. Is the server reachable?`, {
          retryable: true,
        }),
      );
    });
  });
}

function parseResponse(raw: string, host: string, port: number): Uint8Array {
  const headerEnd = raw.indexOf("\r\n\r\n");
  if (headerEnd === -1) {
    throw new TLSError(`Invalid HTTP response from ${host}:${port}`);
  }

  const responseBody = raw.slice(headerEnd + 4);
  const statusLine = raw.slice(0, raw.indexOf("\r\n"));

  const statusCode = parseStatusCode(statusLine);
  if (statusCode < 200 || statusCode >= 300) {
    throw new RevenantError(`HTTP ${statusCode} from ${host}:${port}: ${statusLine}`);
  }

  // Convert binary string to Uint8Array
  const bytes = new Uint8Array(responseBody.length);
  for (let i = 0; i < responseBody.length; i++) {
    bytes[i] = responseBody.charCodeAt(i);
  }
  return bytes;
}
