// SPDX-License-Identifier: Apache-2.0
/**
 * Interactive setup wizard for Revenant CLI.
 *
 * Configures server profile, credentials, and signer identity.
 */

import {
  BUILTIN_PROFILES,
  CONFIG_FILE,
  getActiveProfile,
  getProfile,
  getSavedUsername,
  getSignerInfo,
  makeCustomProfile,
  registerProfileTlsMode,
  type ServerProfile,
  saveServerConfig,
  saveSignerInfo,
} from "../config/index.js";
import { DEFAULT_TIMEOUT_HTTP_GET, ENV_NAME, ENV_URL } from "../constants.js";
import type { CertInfo } from "../core/cert-info.js";
import { discoverIdentityFromServer } from "../core/cert-info.js";
import { AuthError, RevenantError, TLSError } from "../errors.js";
import { pingServer } from "../network/discovery.js";
import { getHostTlsInfo } from "../network/transport.js";
import {
  confirmChoice,
  offerSaveCredentials,
  printAuthFailure,
  promptCredentials,
  safeInput,
} from "./helpers.js";

// -- Setup steps --------------------------------------------------------------

async function chooseProfile(presetProfile: string | null): Promise<ServerProfile> {
  if (presetProfile) {
    let profile: ServerProfile;
    try {
      profile = getProfile(presetProfile);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      process.stderr.write(`Error: ${msg}\n`);
      process.exit(1);
    }
    console.log(`Using profile: ${profile.displayName}`);
    console.log(`  URL: ${profile.url}`);
    return profile;
  }

  console.log("Choose a CoSign server:\n");

  const profilesList = [...BUILTIN_PROFILES.values()].sort((a, b) => a.name.localeCompare(b.name));
  for (const [i, p] of profilesList.entries()) {
    console.log(`  ${i + 1}. ${p.displayName}`);
  }
  console.log(`  ${profilesList.length + 1}. Custom server (enter URL)`);
  console.log();

  const choice = await safeInput(`Your choice [1-${profilesList.length + 1}]: `);
  if (choice === null) process.exit(1);

  const idx = parseInt(choice, 10) - 1;
  if (Number.isNaN(idx) || idx < 0 || idx > profilesList.length) {
    process.stderr.write("Invalid choice.\n");
    process.exit(1);
  }

  if (idx < profilesList.length) {
    const profile = profilesList[idx];
    if (profile === undefined) {
      process.stderr.write("Invalid choice.\n");
      process.exit(1);
    }
    console.log(`\nSelected: ${profile.displayName}`);
    console.log(`  URL: ${profile.url}`);
    return profile;
  }

  // Custom server
  const url = await safeInput("\nServer SOAP URL (e.g. https://host:port/SAPIWS/DSS.asmx): ");
  if (!url) {
    process.stderr.write("Error: URL is required.\n");
    process.exit(1);
  }

  return makeCustomProfile(url);
}

async function ping(profile: ServerProfile): Promise<void> {
  process.stdout.write(`\nContacting ${profile.url}... `);
  const result = await pingServer(profile.url, DEFAULT_TIMEOUT_HTTP_GET);

  if (result.ok) {
    console.log(`OK (${result.info})`);
    const host = new URL(profile.url).hostname;
    const tlsInfo = getHostTlsInfo(host);
    if (tlsInfo) {
      console.log(`  TLS: ${tlsInfo}`);
    }
  } else {
    console.log("FAILED");
    process.stderr.write(`  ${result.info}\n`);
    process.stderr.write("\nCheck the URL and try again.\n");
    process.exit(1);
  }
}

async function getSetupCredentials(
  profile: ServerProfile,
): Promise<{ username: string; password: string }> {
  console.log();
  if (profile.maxAuthAttempts) {
    console.log(`WARNING: account locks after ${profile.maxAuthAttempts} failed attempts!`);
    console.log();
  }
  return promptCredentials();
}

async function discoverIdentity(
  profile: ServerProfile,
  url: string,
  username: string,
  password: string,
  timeout: number,
): Promise<CertInfo | null> {
  for (const method of profile.identityMethods) {
    if (method === "server") {
      const info = await tryIdentityFromServer(url, username, password, timeout);
      if (info) return info;
    } else if (method === "manual") {
      const info = await tryIdentityManual();
      if (info) return info;
    }
  }
  return null;
}

// -- Identity discovery helpers -----------------------------------------------

async function tryIdentityFromServer(
  url: string,
  username: string,
  password: string,
  timeout: number,
): Promise<CertInfo | null> {
  const { SoapSigningTransport } = await import("../network/soap-transport.js");

  process.stdout.write("\nDiscovering signer identity from server... ");

  let info: CertInfo;
  try {
    const transport = new SoapSigningTransport(url);
    info = await discoverIdentityFromServer(transport, username, password, timeout);
  } catch (e) {
    if (e instanceof AuthError) {
      console.log("FAILED");
      printAuthFailure(e);
      return null;
    }
    if (e instanceof RevenantError || e instanceof TLSError) {
      console.log("FAILED");
      process.stderr.write(`  ${e.message}\n`);
      console.log("  (will try other methods)");
      return null;
    }
    throw e;
  }

  if (!info.name) {
    console.log("no signer name found");
    return null;
  }

  console.log("OK");
  printSignerInfo(info);

  const confirmed = await confirmChoice("\nIs this you?");
  if (confirmed) return info;

  return null;
}

async function tryIdentityManual(): Promise<CertInfo | null> {
  console.log("\nEnter signer identity manually:");

  const name = await safeInput("  Name (CN): ");
  if (!name) {
    process.stderr.write("  Name is required.\n");
    return null;
  }

  const email = await safeInput("  Email (optional): ");
  if (email === null) return null;

  const org = await safeInput("  Organization (optional): ");
  if (org === null) return null;

  return {
    name,
    email: email || null,
    organization: org || null,
    dn: null,
    notBefore: null,
    notAfter: null,
  };
}

// -- UI helpers ---------------------------------------------------------------

function printSignerInfo(info: CertInfo): void {
  console.log(`\n  Name (CN):    ${info.name}`);
  if (info.email) {
    console.log(`  Email:        ${info.email}`);
  }
  if (info.organization) {
    console.log(`  Organization: ${info.organization}`);
  }
  if (info.dn) {
    console.log(`  Full DN:      ${info.dn}`);
  }
}

// -- Main setup command -------------------------------------------------------

export async function cmdSetup(presetProfile: string | null = null): Promise<void> {
  console.log("Revenant Setup Wizard");
  console.log("=".repeat(40));
  console.log();

  // Show current config if exists
  const current = getSignerInfo();
  const savedUser = getSavedUsername();
  const currentProfile = getActiveProfile();
  if (currentProfile && (current.name || savedUser)) {
    console.log("Current configuration:");
    console.log(`  Profile:      ${currentProfile.displayName}`);
    console.log(`  URL:          ${currentProfile.url}`);
    if (current.name) {
      console.log(`  Name:         ${current.name}`);
    }
    if (current.email) {
      console.log(`  Email:        ${current.email}`);
    }
    if (current.organization) {
      console.log(`  Organization: ${current.organization}`);
    }
    if (savedUser) {
      console.log(`  Credentials:  saved (user: ${savedUser})`);
    }
    console.log(`  Config file:  ${CONFIG_FILE}`);
    console.log();
  }

  // Step 1: Choose server profile
  const profile = await chooseProfile(presetProfile);

  // Pre-register TLS mode
  await registerProfileTlsMode(profile);

  // Step 2: Ping server
  await ping(profile);

  // Step 3: Credentials
  const { username, password } = await getSetupCredentials(profile);

  // Step 4: Discover signer identity
  const info = await discoverIdentity(profile, profile.url, username, password, profile.timeout);

  if (!info) {
    console.log("\nSetup cancelled (no signer identity configured).");
    process.exit(1);
  }

  // Step 5: Save everything
  saveServerConfig(profile);
  saveSignerInfo(
    info.name ?? "",
    info.email,
    info.organization,
    info.dn,
    info.notBefore,
    info.notAfter,
  );

  console.log(`\nSaved to ${CONFIG_FILE}`);
  console.log(`  Server:  ${profile.displayName}`);
  console.log(`  Signer:  ${info.name}`);
  console.log(`Override anytime with ${ENV_URL} / ${ENV_NAME} env variables.`);

  // Offer to save credentials
  await offerSaveCredentials(username, password);
}
