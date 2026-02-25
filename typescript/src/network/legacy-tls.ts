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

function validateHeaderValue(name: string, value: string): string {
  if (value.includes("\r") || value.includes("\n")) {
    throw new TLSError(`HTTP header '${name}' contains invalid CR/LF characters`);
  }
  return value;
}

export async function legacyRequest(
  method: "GET" | "POST",
  url: string,
  options?: {
    body?: Uint8Array;
    headers?: Record<string, string>;
    timeout?: number;
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

  const timeout = options?.timeout ?? DEFAULT_TIMEOUT_LEGACY_TLS;
  const body = options?.body;
  const extraHeaders = options?.headers;

  return new Promise<Uint8Array>((resolve, reject) => {
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
        verify: () => true, // Accept all certificates (legacy compat)
        connected: (connection) => {
          // TLS handshake complete, send HTTP request
          logger.warn(
            `Using legacy TLS (TLS 1.0 + RC4) for ${host}:${port}. ` +
              "This cipher suite is deprecated and only used for backward compatibility.",
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
          reject(new TLSError(`TLS error with ${host}:${port}: ${error.message}`));
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
