// SPDX-License-Identifier: Apache-2.0
/**
 * Common CLI helper functions for Revenant.
 *
 * Extracted patterns from setup and sign commands to eliminate duplication.
 */

import {
  existsSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  rmdirSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { dirname, join } from "node:path";
import { createInterface } from "node:readline";

import type { ServerProfile } from "../config/index.js";
import type { AuthError } from "../errors.js";

const BYTES_PER_KB = 1024;

export function formatSizeKb(sizeBytes: number): string {
  return `${(sizeBytes / BYTES_PER_KB).toFixed(1)} KB`;
}

export function defaultOutputPath(pdfPath: string): string {
  const dotIdx = pdfPath.lastIndexOf(".");
  if (dotIdx === -1) return `${pdfPath}_signed.pdf`;
  return `${pdfPath.slice(0, dotIdx)}_signed.pdf`;
}

export function defaultDetachedOutputPath(pdfPath: string): string {
  return `${pdfPath}.p7s`;
}

/**
 * Prompt user for input, returning null on EOF/KeyboardInterrupt.
 */
export async function safeInput(prompt: string): Promise<string | null> {
  const rl = createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  return new Promise((resolve) => {
    rl.question(prompt, (answer) => {
      rl.close();
      resolve(answer.trim());
    });
    rl.on("close", () => resolve(null));
  });
}

/**
 * Prompt user for yes/no confirmation.
 */
export async function confirmChoice(message: string, defaultYes: boolean = true): Promise<boolean> {
  const suffix = defaultYes ? "[Y/n]" : "[y/N]";
  const answer = await safeInput(`${message} ${suffix} `);
  if (answer === null) return false;

  const lower = answer.toLowerCase();
  if (defaultYes) {
    return lower === "" || lower === "y" || lower === "yes";
  }
  return lower === "y" || lower === "yes";
}

/**
 * Read a file with uniform error handling.
 */
export function safeReadFile(path: string, kind: string = "file"): Uint8Array | null {
  if (!existsSync(path)) {
    process.stderr.write(`Error: ${kind} not found: ${path}\n`);
    return null;
  }

  try {
    return new Uint8Array(readFileSync(path));
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    process.stderr.write(`Error reading ${kind}: ${msg}\n`);
    return null;
  }
}

/**
 * Print authentication failure message with account lockout warning.
 */
export function printAuthFailure(error: AuthError, profile?: ServerProfile | null): void {
  process.stderr.write("AUTH FAILED\n");
  process.stderr.write(`  ${error.message}\n`);
  if (profile?.maxAuthAttempts) {
    process.stderr.write(
      `  WARNING: account locks after ${profile.maxAuthAttempts} failed attempts!\n`,
    );
  }
}

/**
 * Prompt for username and/or password interactively.
 */
export async function promptCredentials(
  username?: string | null,
  password?: string | null,
): Promise<{ username: string; password: string }> {
  if (!username) {
    const answer = await safeInput("Revenant username: ");
    if (answer === null) process.exit(1);
    username = answer;
  }

  if (!password) {
    // Use readline with silent output for password
    const rl = createInterface({
      input: process.stdin,
      output: process.stdout,
    });
    password = await new Promise<string>((resolve) => {
      // Disable echoing by writing to stdout directly
      process.stdout.write("Revenant password: ");
      const stdin = process.stdin;
      const wasRaw = stdin.isRaw;
      if (stdin.isTTY) stdin.setRawMode(true);

      let buf = "";
      const onData = (ch: Buffer): void => {
        const c = ch.toString("utf-8");
        if (c === "\n" || c === "\r") {
          if (stdin.isTTY) stdin.setRawMode(wasRaw ?? false);
          stdin.removeListener("data", onData);
          process.stdout.write("\n");
          rl.close();
          resolve(buf.trim());
        } else if (c === "\u0003") {
          // Ctrl-C
          if (stdin.isTTY) stdin.setRawMode(wasRaw ?? false);
          stdin.removeListener("data", onData);
          rl.close();
          process.stdout.write("\n");
          process.exit(1);
        } else if (c === "\u007f" || c === "\b") {
          buf = buf.slice(0, -1);
        } else {
          buf += c;
        }
      };
      stdin.on("data", onData);
    });
  }

  if (!username || !password) {
    process.stderr.write("Error: username and password are required.\n");
    process.exit(1);
  }

  return { username, password };
}

/**
 * Ask the user if they want to save credentials for future use.
 */
export async function offerSaveCredentials(username: string, password: string): Promise<void> {
  const { getCredentialStorageInfo, isKeyringAvailable, saveCredentials } = await import(
    "../config/index.js"
  );

  const shouldSave = await confirmChoice("\nSave credentials for future use?");
  if (shouldSave) {
    await saveCredentials(username, password);
    const storage = await getCredentialStorageInfo();
    console.log(`Credentials saved to: ${storage}`);
    const keyring = await isKeyringAvailable();
    if (!keyring) {
      console.log("  For secure storage, install: npm install keytar");
    }
    console.log("  (env vars REVENANT_USER/REVENANT_PASS always take priority)");
  } else {
    console.log("Credentials not saved.");
  }
}

/**
 * Write data to a file atomically using temp file + rename.
 */
export function atomicWrite(filePath: string, data: Uint8Array): void {
  const dir = dirname(filePath);
  const tmpDir = mkdtempSync(join(dir, ".revenant-tmp-"));
  const tmpPath = join(tmpDir, "output.tmp");

  try {
    writeFileSync(tmpPath, data);
    renameSync(tmpPath, filePath);
  } catch (err) {
    try {
      unlinkSync(tmpPath);
    } catch {
      // cleanup best-effort
    }
    throw err;
  } finally {
    try {
      rmdirSync(tmpDir);
    } catch {
      // cleanup best-effort
    }
  }
}

/**
 * Print server-side verification result to stdout.
 */
export function formatServerVerifyResult(result: {
  valid: boolean;
  signerName: string | null;
  signTime: string | null;
  certificateStatus: string | null;
  error: string | null;
}): void {
  if (result.error) {
    console.log(`  Server: unavailable (${result.error})`);
    return;
  }
  if (result.signerName) {
    console.log(`  Server signer: ${result.signerName}`);
  }
  if (result.signTime) {
    console.log(`  Server sign time: ${result.signTime}`);
  }
  if (result.certificateStatus) {
    console.log(`  Server certificate: ${result.certificateStatus}`);
  }
  if (result.valid) {
    console.log("  Server: VALID");
  } else {
    console.log("  Server: FAILED");
  }
}
