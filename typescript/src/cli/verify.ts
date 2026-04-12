// SPDX-License-Identifier: Apache-2.0
/**
 * Signature verification and inspection commands.
 *
 * cmdVerify uses openssl CLI (graceful degradation if not installed).
 * cmdInfo uses pkijs (cross-platform, no external tools).
 */

import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, statSync } from "node:fs";

import { formatExpirySummary } from "../core/cert-expiry.js";
import { extractCertInfoFromCms } from "../core/cert-info.js";
import { getErrorMessage, isNodeError } from "../errors.js";

// -- Detached verify (openssl) ------------------------------------------------

export interface VerifyCommandArgs {
  pdf: string;
  signature?: string | null;
}

export function cmdVerify(args: VerifyCommandArgs): void {
  const pdfPath = args.pdf;
  const sigPath = args.signature ?? `${pdfPath}.p7s`;

  if (!existsSync(pdfPath)) {
    process.stderr.write(`Error: ${pdfPath} not found\n`);
    process.exit(1);
  }
  if (!existsSync(sigPath)) {
    process.stderr.write(`Error: ${sigPath} not found\n`);
    process.exit(1);
  }

  console.log(`Verifying ${pdfPath} against ${sigPath}...`);

  const opensslBin = "openssl";
  const opensslArgs = [
    "cms",
    "-verify",
    "-inform",
    "DER",
    "-in",
    sigPath,
    "-content",
    pdfPath,
    "-binary",
    "-purpose",
    "any",
  ];

  console.log("  Using system trust store for chain verification");

  try {
    const result = execFileSync(opensslBin, opensslArgs, {
      timeout: 15_000,
      stdio: ["pipe", "pipe", "pipe"],
    });
    const stdout = result.toString("utf-8").trim();
    console.log("  VALID: Signature verification succeeded.");
    if (stdout.includes("Verification successful")) {
      console.log(`  ${stdout}`);
    }
  } catch (e: unknown) {
    if (isNodeError(e, "ENOENT")) {
      process.stderr.write("Error: openssl not found. Install OpenSSL to verify signatures.\n");
      process.exit(1);
    }
    // execFileSync attaches stderr buffer on non-zero exit
    if (e instanceof Error && "stderr" in e) {
      const { stderr } = e;
      if (Buffer.isBuffer(stderr)) {
        const stderrText = stderr.toString("utf-8").trim();
        console.log(`  INVALID: ${stderrText}`);
        process.exit(1);
      }
    }
    throw e;
  }
}

// -- CMS info (pkijs) ---------------------------------------------------------

export interface InfoCommandArgs {
  signature: string;
}

export async function cmdInfo(args: InfoCommandArgs): Promise<void> {
  const sigPath = args.signature;
  if (!existsSync(sigPath)) {
    process.stderr.write(`Error: ${sigPath} not found\n`);
    process.exit(1);
  }

  let fileSize: number;
  try {
    fileSize = statSync(sigPath).size;
  } catch (e) {
    process.stderr.write(`Error: cannot access ${sigPath}: ${getErrorMessage(e)}\n`);
    process.exit(1);
  }
  console.log(`Signature: ${sigPath} (${fileSize} bytes)`);

  let sigBytes: Uint8Array;
  try {
    sigBytes = new Uint8Array(readFileSync(sigPath));
  } catch (e) {
    process.stderr.write(`Error reading ${sigPath}: ${getErrorMessage(e)}\n`);
    process.exit(1);
  }

  try {
    const info = extractCertInfoFromCms(sigBytes);
    console.log("\nCertificate info:");
    if (info.name) console.log(`  Subject: ${info.name}`);
    if (info.organization) console.log(`  Organization: ${info.organization}`);
    if (info.email) console.log(`  Email: ${info.email}`);
    if (info.dn) console.log(`  DN: ${info.dn}`);
    if (info.notAfter) {
      console.log(`  Status: ${formatExpirySummary(info.notAfter)}`);
    }
  } catch (e) {
    process.stderr.write(`  Error parsing signature: ${getErrorMessage(e)}\n`);
  }
}
