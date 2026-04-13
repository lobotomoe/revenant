// SPDX-License-Identifier: Apache-2.0
/**
 * Command-line interface for Revenant.
 *
 * Argument parsing, dispatch, and non-signing subcommands.
 * Signing logic lives in sign.ts.
 */

import { Command } from "commander";

import { BUILTIN_PROFILES, getServerConfig } from "../config/index.js";
import { VERSION } from "../constants.js";
import type { VerificationResult } from "../core/pdf/index.js";
import { getErrorMessage, RevenantError } from "../errors.js";

async function cmdLogout(): Promise<void> {
  const { logout } = await import("../config/index.js");
  await logout();
  console.log("Logged out. Server configuration preserved.");
  console.log("Run 'revenant setup' to log in again.");
}

async function cmdReset(): Promise<void> {
  const { resetAll } = await import("../config/index.js");
  await resetAll();
  console.log("All configuration cleared.");
  console.log("Run 'revenant setup' to reconfigure.");
}

async function cmdCheck(pdfPath: string, options: { server?: boolean }): Promise<void> {
  const { readFileSync, existsSync } = await import("node:fs");
  const { formatSizeKb, formatServerVerifyResult } = await import("./helpers.js");
  const { formatVerifyResults } = await import("./workflows.js");
  const { verifyAllEmbeddedSignatures } = await import("../core/pdf/index.js");

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

  console.log(`Checking ${pdfPath} (${formatSizeKb(pdfBytes.length)})...`);

  let results: VerificationResult[];
  try {
    const { getActiveProfile } = await import("../config/index.js");
    const profile = getActiveProfile();
    const tslUrl = profile?.tslUrl ?? null;
    results = await verifyAllEmbeddedSignatures(pdfBytes, tslUrl);
  } catch (e) {
    if (e instanceof RevenantError) {
      process.stderr.write(`  ERROR: ${e.message}\n`);
      process.exit(1);
    }
    throw e;
  }

  const vr = formatVerifyResults(results);

  for (const entry of vr.entries) {
    if (vr.totalCount > 1) {
      console.log(`\n  Signature ${entry.index + 1}/${entry.total} (${entry.signerName}):`);
    }
    const indent = vr.totalCount > 1 ? "    " : "  ";
    for (const line of entry.detailLines) {
      console.log(`${indent}${line}`);
    }
  }

  // Server-side verification (optional)
  if (options.server) {
    const config = getServerConfig();
    if (config.url && config.timeout) {
      console.log("\n  Server verification...");
      const { registerActiveProfileTls } = await import("../config/index.js");
      const { verifyPdfServer } = await import("../network/soap-transport.js");
      await registerActiveProfileTls();
      const serverResult = await verifyPdfServer(config.url, pdfBytes, config.timeout);
      formatServerVerifyResult(serverResult);
    } else {
      console.log("\n  Server verification skipped: no server configured.");
    }
  }

  console.log();
  if (vr.allValid) {
    const sigWord = vr.totalCount === 1 ? "Signature" : `All ${vr.totalCount} signatures`;
    console.log(`  RESULT: ${sigWord} VALID`);
  } else {
    console.log(`  RESULT: ${vr.failedCount} of ${vr.totalCount} signature(s) FAILED`);
    process.exit(1);
  }
}

export function main(): void {
  const config = getServerConfig();
  const urlHint = config.url ? ` (current: ${config.url})` : " (run `revenant setup` first)";

  const program = new Command();
  program
    .name("revenant")
    .description("Cross-platform CLI for ARX CoSign electronic signatures.")
    .version(`revenant ${VERSION}`, "-V, --version")
    .addHelpText(
      "after",
      `\nEnvironment variables:
  REVENANT_USER     Revenant username
  REVENANT_PASS     Revenant password
  REVENANT_URL      SOAP endpoint${urlHint}
  REVENANT_TIMEOUT  Timeout in seconds (default: 120)
  REVENANT_NAME     Signer display name (overrides config from setup)

Project:
  https://github.com/lobotomoe/revenant
  Bug reports: https://github.com/lobotomoe/revenant/issues`,
    );

  // sign
  const signCmd = program.command("sign");
  signCmd
    .description("Sign PDF document(s)")
    .argument("<files...>", "PDF file(s) to sign")
    .option("-o, --output <path>", "Output file path (single file only)")
    .option("-d, --detached", "Save detached .p7s signature instead of embedded PDF", false)
    .option(
      "-p, --position <preset>",
      "Signature position preset (default: bottom-right)",
      "bottom-right",
    )
    .option("--page <page>", "Page for the signature field (default: last)", "last")
    .option("--image <path>", "Signature image file (PNG or JPEG)")
    .option("--invisible", "Create an invisible signature (no visual appearance)", false)
    .option(
      "--font <name>",
      "Font for signature appearance (noto-sans, ghea-mariam, ghea-grapalat)",
    )
    .option("--reason <text>", "Signature reason string")
    .option("--dry-run", "Show what would be done without actually signing", false)
    .action(async (files: string[], opts) => {
      const { cmdSign } = await import("./sign.js");
      await cmdSign({
        files,
        output: opts.output ?? null,
        detached: opts.detached,
        position: opts.position,
        page: opts.page,
        image: opts.image ?? null,
        invisible: opts.invisible,
        font: opts.font ?? null,
        reason: opts.reason ?? null,
        dryRun: opts.dryRun,
      });
    });

  // verify
  program
    .command("verify")
    .description("Verify a detached CMS signature")
    .argument("<pdf>", "PDF file")
    .option("-s, --signature <path>", "Signature file (default: <pdf>.p7s)")
    .action(async (pdf: string, opts) => {
      const { cmdVerify } = await import("./verify.js");
      cmdVerify({ pdf, signature: opts.signature ?? null });
    });

  // check
  program
    .command("check")
    .description("Check an embedded PDF signature")
    .argument("<pdf>", "Signed PDF file")
    .option("--server", "Also run server-side verification if configured", false)
    .action(async (pdf: string, opts) => {
      await cmdCheck(pdf, { server: opts.server });
    });

  // info
  program
    .command("info")
    .description("Show signature file details")
    .argument("<signature>", "CMS signature file (.p7s)")
    .action(async (signature: string) => {
      const { cmdInfo } = await import("./verify.js");
      await cmdInfo({ signature });
    });

  // cert
  program
    .command("cert")
    .description("Show certificate details and expiration")
    .option("--pdf <path>", "Extract certificate info from a signed PDF (offline)")
    .action(async (opts) => {
      const { cmdCert } = await import("./cert.js");
      await cmdCert({ pdf: opts.pdf ?? null });
    });

  // setup
  program
    .command("setup")
    .description("Configure server, credentials, and signer identity")
    .option(
      "--profile <name>",
      `Use a built-in server profile (${[...BUILTIN_PROFILES.keys()].sort().join(", ")})`,
    )
    .action(async (opts) => {
      const { cmdSetup } = await import("./setup.js");
      await cmdSetup(opts.profile ?? null);
    });

  // logout
  program
    .command("logout")
    .description("Log out (clear credentials and identity, keep server)")
    .action(async () => {
      await cmdLogout();
    });

  // reset
  program
    .command("reset")
    .description("Clear all configuration")
    .action(async () => {
      await cmdReset();
    });

  program.parseAsync().catch((err) => {
    const msg = err instanceof RevenantError ? err.message : getErrorMessage(err);
    process.stderr.write(`Error: ${msg}\n`);
    process.exit(1);
  });
}
