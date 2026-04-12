// SPDX-License-Identifier: Apache-2.0
/**
 * Certificate information and expiration CLI command.
 */

import { existsSync, readFileSync } from "node:fs";

import { formatExpirySummary, formatValidityPeriod } from "../core/cert-expiry.js";
import type { CertInfo } from "../core/cert-info.js";
import { AuthError, getErrorMessage, RevenantError, TLSError } from "../errors.js";

function printCertInfo(info: CertInfo, indent: string = "  "): void {
  if (info.name) console.log(`${indent}Subject:      ${info.name}`);
  if (info.organization) console.log(`${indent}Organization: ${info.organization}`);
  if (info.email) console.log(`${indent}Email:        ${info.email}`);
  if (info.dn) console.log(`${indent}DN:           ${info.dn}`);

  const validity = formatValidityPeriod(info.notBefore, info.notAfter);
  console.log(`${indent}Valid:        ${validity}`);

  const summary = formatExpirySummary(info.notAfter);
  console.log(`${indent}Status:       ${summary}`);
}

async function certFromServer(): Promise<void> {
  const { getServerConfig, registerActiveProfileTls, resolveCredentials } = await import(
    "../config/index.js"
  );
  const { discoverIdentityFromServer } = await import("../core/cert-info.js");
  const { SoapSigningTransport } = await import("../network/soap-transport.js");

  const { url, timeout } = getServerConfig();
  if (!url || !timeout) {
    process.stderr.write("Error: no server configured. Run 'revenant setup' first.\n");
    process.exit(1);
  }

  const creds = resolveCredentials();
  let username = creds.username;
  let password = creds.password;
  if (!username || !password) {
    const { promptCredentials } = await import("./helpers.js");
    const prompted = await promptCredentials();
    username = prompted.username;
    password = prompted.password;
  }

  await registerActiveProfileTls();
  const transport = new SoapSigningTransport(url);

  console.log(`Fetching certificate from ${url}...`);
  try {
    const info = await discoverIdentityFromServer(transport, username, password, timeout);
    console.log("\nCertificate:");
    printCertInfo(info);
  } catch (e) {
    if (e instanceof AuthError) {
      process.stderr.write(`Error: authentication failed: ${e.message}\n`);
      process.exit(1);
    }
    if (e instanceof TLSError) {
      process.stderr.write(`Error: connection failed: ${e.message}\n`);
      process.exit(1);
    }
    if (e instanceof RevenantError) {
      process.stderr.write(`Error: ${e.message}\n`);
      process.exit(1);
    }
    throw e;
  }
}

async function certFromPdf(pdfPath: string): Promise<void> {
  const { formatSizeKb } = await import("./helpers.js");
  const { extractAllCertInfoFromPdf } = await import("../core/cert-info.js");

  if (!existsSync(pdfPath)) {
    process.stderr.write(`Error: ${pdfPath} not found\n`);
    process.exit(1);
  }

  let pdfBytes: Uint8Array;
  try {
    pdfBytes = new Uint8Array(readFileSync(pdfPath));
  } catch (e) {
    process.stderr.write(`Error: cannot read ${pdfPath}: ${getErrorMessage(e)}\n`);
    process.exit(1);
  }

  console.log(`Reading ${pdfPath} (${formatSizeKb(pdfBytes.byteLength)})...`);

  try {
    const certs = extractAllCertInfoFromPdf(pdfBytes);
    for (let i = 0; i < certs.length; i++) {
      const cert = certs[i];
      if (cert === undefined) continue;
      if (certs.length > 1) {
        console.log(`\nCertificate [${i + 1}/${certs.length}]:`);
      } else {
        console.log("\nCertificate:");
      }
      printCertInfo(cert);
    }
  } catch (e) {
    if (e instanceof RevenantError) {
      process.stderr.write(`Error: ${e.message}\n`);
      process.exit(1);
    }
    throw e;
  }
}

export async function cmdCert(options: { pdf?: string | null }): Promise<void> {
  if (options.pdf) {
    certFromPdf(options.pdf);
  } else {
    await certFromServer();
  }
}
