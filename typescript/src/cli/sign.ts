// SPDX-License-Identifier: Apache-2.0
/**
 * Signing command handlers for Revenant CLI.
 */

import {
  getActiveProfile,
  getCredentials,
  getServerConfig,
  getSignerName,
  resolveCredentials,
} from "../config/index.js";
import {
  BYTES_PER_MB,
  DEFAULT_POSITION,
  DEFAULT_TIMEOUT_SOAP,
  ENV_NAME,
  ENV_PASS,
  ENV_USER,
  PDF_WARN_SIZE,
  VERSION,
} from "../constants.js";
import { AuthError, getErrorMessage } from "../errors.js";
import {
  defaultDetachedOutputPath,
  defaultOutputPath,
  formatSizeKb,
  offerSaveCredentials,
  printAuthFailure,
  promptCredentials,
  safeReadFile,
} from "./helpers.js";
import { cmdSetup } from "./setup.js";
import {
  resolveSigFields,
  type SigningResult,
  signOneDetached,
  signOneEmbedded,
} from "./workflows.js";

// Credential source tracking
const CRED_SOURCE_ENV = "env";
const CRED_SOURCE_CONFIG = "config";
const CRED_SOURCE_PROMPT = "prompt";

function resolveCredSource(): string {
  const envUser = (process.env[ENV_USER] ?? "").trim();
  const envPass = (process.env[ENV_PASS] ?? "").trim();
  if (envUser && envPass) return CRED_SOURCE_ENV;

  const { username, password } = resolveCredentials();
  if (username && password) return CRED_SOURCE_CONFIG;

  return CRED_SOURCE_PROMPT;
}

async function getSignCredentials(): Promise<{
  username: string;
  password: string;
}> {
  // 1. Environment variables
  const envUser = (process.env[ENV_USER] ?? "").trim();
  const envPass = (process.env[ENV_PASS] ?? "").trim();
  if (envUser && envPass) return { username: envUser, password: envPass };

  // 2. Saved credentials
  const saved = await getCredentials();
  if (saved.username && saved.password) {
    return { username: saved.username, password: saved.password };
  }

  // 3. Interactive prompt (pre-fill from partial env/config)
  const partial = resolveCredentials();
  return promptCredentials(partial.username || null, partial.password || null);
}

function signOneEmbeddedCli(
  pdfPath: string,
  outputPath: string | null,
  username: string,
  password: string,
  url: string,
  timeout: number,
  options: {
    name?: string | null;
    position?: string;
    page?: number | string;
    imagePath?: string | null;
    dryRun?: boolean;
    visible?: boolean;
    font?: string | null;
    reason?: string;
  } = {},
): Promise<SigningResult> {
  const pdfBytes = safeReadFile(pdfPath, "PDF");
  if (pdfBytes === null) {
    return Promise.resolve({
      ok: false,
      authFailed: false,
      tlsError: false,
      errorMessage: "File not found or unreadable",
      outputPath: null,
      outputSize: 0,
    });
  }

  if (pdfBytes.length > PDF_WARN_SIZE) {
    const sizeMb = pdfBytes.length / BYTES_PER_MB;
    const warnMb = PDF_WARN_SIZE / BYTES_PER_MB;
    process.stderr.write(
      `  Warning: ${pdfPath} is ${sizeMb.toFixed(0)} MB. ` +
        `Files over ${warnMb} MB may be slow or fail.\n`,
    );
  }

  const out = outputPath ?? defaultOutputPath(pdfPath);

  if (options.dryRun) {
    const pageDisplay = typeof options.page === "string" ? options.page : (options.page ?? 0) + 1;
    console.log(`  Would sign: ${pdfPath} (${formatSizeKb(pdfBytes.length)})`);
    console.log(`    -> Output: ${out}`);
    console.log(`    -> Position: ${options.position ?? DEFAULT_POSITION}, Page: ${pageDisplay}`);
    if (options.imagePath) {
      console.log(`    -> Image: ${options.imagePath}`);
    }
    return Promise.resolve({
      ok: true,
      authFailed: false,
      tlsError: false,
      errorMessage: null,
      outputPath: null,
      outputSize: 0,
    });
  }

  const fields = resolveSigFields();
  process.stdout.write(`  Signing ${pdfPath} (${formatSizeKb(pdfBytes.length)})... `);

  return signOneEmbedded(pdfBytes, out, url, username, password, timeout, {
    name: options.name,
    position: options.position,
    page: options.page,
    imagePath: options.imagePath,
    visible: options.visible,
    font: options.font,
    reason: options.reason,
    fields,
  }).then((result) => {
    if (result.ok) {
      console.log(`OK -> ${out} (${formatSizeKb(result.outputSize)})`);
    } else if (result.authFailed) {
      printAuthFailure(new AuthError(result.errorMessage ?? ""), getActiveProfile());
    } else if (result.tlsError) {
      process.stderr.write("TLS ERROR\n");
      process.stderr.write(`  ${result.errorMessage}\n`);
    } else {
      process.stderr.write("FAILED\n");
      process.stderr.write(`  ${result.errorMessage}\n`);
    }
    return result;
  });
}

function signOneDetachedCli(
  pdfPath: string,
  outputPath: string | null,
  username: string,
  password: string,
  url: string,
  timeout: number,
): Promise<SigningResult> {
  const pdfBytes = safeReadFile(pdfPath, "PDF");
  if (pdfBytes === null) {
    return Promise.resolve({
      ok: false,
      authFailed: false,
      tlsError: false,
      errorMessage: "File not found or unreadable",
      outputPath: null,
      outputSize: 0,
    });
  }

  if (pdfBytes.length > PDF_WARN_SIZE) {
    const sizeMb = pdfBytes.length / BYTES_PER_MB;
    const warnMb = PDF_WARN_SIZE / BYTES_PER_MB;
    process.stderr.write(
      `  Warning: ${pdfPath} is ${sizeMb.toFixed(0)} MB. ` +
        `Files over ${warnMb} MB may be slow or fail.\n`,
    );
  }

  const sigPath = outputPath ?? defaultDetachedOutputPath(pdfPath);
  process.stdout.write(`  Signing ${pdfPath} (${formatSizeKb(pdfBytes.length)})... `);

  return signOneDetached(pdfBytes, sigPath, url, username, password, timeout).then((result) => {
    if (result.ok) {
      console.log(`OK -> ${sigPath} (${result.outputSize} bytes)`);
    } else if (result.authFailed) {
      printAuthFailure(new AuthError(result.errorMessage ?? ""), getActiveProfile());
    } else if (result.tlsError) {
      process.stderr.write("TLS ERROR\n");
      process.stderr.write(`  ${result.errorMessage}\n`);
    } else {
      process.stderr.write("FAILED\n");
      process.stderr.write(`  ${result.errorMessage}\n`);
    }
    return result;
  });
}

async function requireServerConfig(): Promise<{
  url: string;
  timeout: number;
  profileName: string | null;
}> {
  const config = getServerConfig();
  if (config.url) {
    return {
      url: config.url,
      timeout: config.timeout ?? DEFAULT_TIMEOUT_SOAP,
      profileName: config.profileName,
    };
  }

  // No config -- offer interactive setup
  console.log("No saved configuration found.");
  const { createInterface } = await import("node:readline");
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  const answer = await new Promise<string>((resolve) => {
    rl.question("Run setup wizard? [Y/n] ", (a) => {
      rl.close();
      resolve(a.trim().toLowerCase());
    });
  });

  if (answer === "" || answer === "y" || answer === "yes") {
    await cmdSetup(null);
    const reloaded = getServerConfig();
    if (reloaded.url) {
      console.log();
      return {
        url: reloaded.url,
        timeout: reloaded.timeout ?? DEFAULT_TIMEOUT_SOAP,
        profileName: reloaded.profileName,
      };
    }
  }

  process.stderr.write("No server configured.\n");
  process.stderr.write("Set REVENANT_URL env var or run `revenant setup`.\n");
  process.exit(1);
}

export interface SignCommandArgs {
  files: string[];
  output?: string | null;
  detached?: boolean;
  position?: string;
  page?: string;
  image?: string | null;
  invisible?: boolean;
  font?: string | null;
  reason?: string | null;
  dryRun?: boolean;
}

export async function cmdSign(args: SignCommandArgs): Promise<void> {
  const { parsePageSpec } = await import("../core/pdf/index.js");

  const files = args.files;
  if (files.length === 0) {
    process.stderr.write("Error: no input files specified.\n");
    process.exit(1);
  }

  const detached = args.detached ?? false;
  const output = args.output ?? null;
  const dryRun = args.dryRun ?? false;

  if (output && files.length > 1) {
    process.stderr.write("Error: -o/--output can only be used with a single input file.\n");
    process.exit(1);
  }

  let username: string;
  let password: string;
  let credSource: string;
  let url: string;
  let timeout: number;

  if (dryRun) {
    username = "";
    password = "";
    credSource = "dry_run";
    const config = getServerConfig();
    url = config.url ?? "(not configured)";
    timeout = config.timeout ?? DEFAULT_TIMEOUT_SOAP;
  } else {
    credSource = resolveCredSource();
    const creds = await getSignCredentials();
    username = creds.username;
    password = creds.password;
    const server = await requireServerConfig();
    url = server.url;
    timeout = server.timeout;
  }

  // Resolve signer name
  let name: string | null = null;
  if (!detached) {
    name = (process.env[ENV_NAME] ?? "").trim() || null;
  }
  if (!name && !detached) {
    name = getSignerName();
    if (name) {
      console.log(`Using signer name from config: ${name}`);
      console.log("  (override with REVENANT_NAME env, reconfigure with: revenant setup)");
    }
  }

  // Position, page, image
  const position = args.position ?? DEFAULT_POSITION;
  const pageRaw = args.page ?? "last";
  let page: number | string;
  try {
    page = parsePageSpec(pageRaw);
  } catch (e) {
    process.stderr.write(`Error: ${getErrorMessage(e)}\n`);
    process.exit(1);
  }
  const imagePath = args.image ?? null;
  const visible = !(args.invisible ?? false);
  const reason = args.reason ?? "";

  // Font: CLI --font overrides profile default
  let font = args.font ?? null;
  if (font === null) {
    const profile = getActiveProfile();
    if (profile) font = profile.font;
  }

  const modeLabel = detached ? "detached .p7s" : "embedded PDF";
  const credLabel: Record<string, string> = {
    [CRED_SOURCE_ENV]: "environment",
    [CRED_SOURCE_CONFIG]: "saved config",
    [CRED_SOURCE_PROMPT]: "interactive",
  };
  console.log(`Revenant CLI v${VERSION}`);
  console.log(`Endpoint: ${url}`);
  if (dryRun) {
    console.log("Mode: DRY RUN (no actual signing)");
  } else {
    console.log(`Credentials: ${credLabel[credSource] ?? credSource}`);
    console.log(`Mode: ${modeLabel}`);
  }
  if (!detached) {
    console.log(`Position: ${position}, Page: ${pageRaw}`);
  }
  console.log();

  let success = 0;
  let failed = 0;

  for (const pdfFile of files) {
    let result: SigningResult;
    if (detached) {
      if (dryRun) {
        console.log(`  Would sign: ${pdfFile} (detached .p7s)`);
        result = {
          ok: true,
          authFailed: false,
          tlsError: false,
          errorMessage: null,
          outputPath: null,
          outputSize: 0,
        };
      } else {
        result = await signOneDetachedCli(pdfFile, output, username, password, url, timeout);
      }
    } else {
      result = await signOneEmbeddedCli(pdfFile, output, username, password, url, timeout, {
        name,
        position,
        page,
        imagePath,
        dryRun,
        visible,
        font,
        reason,
      });
    }

    if (result.ok) {
      success++;
    } else {
      failed++;
      // Stop batch on auth failure to prevent account lockout
      if (result.authFailed) {
        const remaining = files.length - success - failed;
        if (remaining > 0) {
          process.stderr.write(
            `\n  Stopping: ${remaining} file(s) skipped to prevent account lockout.\n`,
          );
        }
        break;
      }
    }
  }

  console.log();
  if (dryRun) {
    console.log(`Dry run complete: ${success} file(s) would be signed.`);
  } else if (failed) {
    console.log(`Done: ${success} signed, ${failed} failed.`);
    process.exit(1);
  } else {
    console.log(`Done: ${success} signed.`);
  }

  // Offer to save credentials if they came from interactive prompt
  if (success > 0 && credSource === CRED_SOURCE_PROMPT) {
    await offerSaveCredentials(username, password);
  }
}
