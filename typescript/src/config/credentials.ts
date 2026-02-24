// SPDX-License-Identifier: Apache-2.0
/**
 * Credential management for Revenant.
 *
 * Credentials are stored securely via the system keychain (keytar)
 * when available, falling back to config file storage otherwise.
 */

import type keytar from "keytar";

import { ENV_PASS, ENV_USER } from "../constants.js";
import { logger } from "../logger.js";
import { CONFIG_FILE, loadConfig, loadRawConfig, saveConfig } from "./storage.js";

const KEYRING_SERVICE = "revenant";

type KeytarModule = typeof keytar;

let keytarMod: KeytarModule | null = null;
let keytarLoaded = false;

async function loadKeytar(): Promise<KeytarModule | null> {
  if (keytarLoaded) return keytarMod;
  keytarLoaded = true;
  try {
    const mod = await import("keytar");
    keytarMod = mod.default ?? mod;
    return keytarMod;
  } catch {
    return null;
  }
}

// Session-level credential cache (not persisted to disk)
let sessionUsername: string | null = null;
let sessionPassword: string | null = null;

export function setSessionCredentials(username: string, password: string): void {
  sessionUsername = username;
  sessionPassword = password;
}

export function clearSessionCredentials(): void {
  sessionUsername = null;
  sessionPassword = null;
}

export async function isKeyringAvailable(): Promise<boolean> {
  const kt = await loadKeytar();
  return kt !== null;
}

export async function getCredentialStorageInfo(): Promise<string> {
  const kt = await loadKeytar();
  if (kt) {
    if (process.platform === "darwin") return "macOS Keychain";
    if (process.platform === "win32") return "Windows Credential Manager";
    return "Linux Secret Service";
  }
  return `${CONFIG_FILE} (plaintext)`;
}

export function resolveCredentials(): { username: string; password: string } {
  let user = (process.env[ENV_USER] ?? "").trim();
  let pwd = (process.env[ENV_PASS] ?? "").trim();

  if (!user && sessionUsername) user = sessionUsername;
  if (!pwd && sessionPassword) pwd = sessionPassword;

  if (!user || !pwd) {
    const saved = getCredentialsSync();
    if (saved.username && !user) user = saved.username;
    if (saved.password && !pwd) pwd = saved.password;
  }

  return { username: user, password: pwd };
}

function getCredentialsSync(): {
  username: string | null;
  password: string | null;
} {
  const config = loadConfig();
  const username = config.username ?? null;
  if (!username) return { username: null, password: null };

  // Keyring is async-only; for sync resolution, use config file only
  const password = config.password ?? null;
  return { username, password };
}

export async function getCredentials(): Promise<{
  username: string | null;
  password: string | null;
}> {
  const kt = await loadKeytar();
  await migratePlaintextPassword(kt);
  const config = loadConfig();
  const username = config.username ?? null;
  if (!username) return { username: null, password: null };

  if (kt) {
    try {
      const password = await kt.getPassword(KEYRING_SERVICE, username);
      if (password) return { username, password };
    } catch {
      // Keyring read failed, try config file
    }
  }

  const password = config.password ?? null;
  return { username, password };
}

export async function saveCredentials(username: string, password: string): Promise<boolean> {
  const kt = await loadKeytar();
  const config = loadRawConfig();
  const oldUsername = config.username;

  if (kt && typeof oldUsername === "string" && oldUsername !== username) {
    try {
      await kt.deletePassword(KEYRING_SERVICE, oldUsername);
    } catch {
      // Ignore
    }
  }

  config.username = username;

  if (kt) {
    try {
      await kt.setPassword(KEYRING_SERVICE, username, password);
      delete config.password;
      saveConfig(config);
      return true;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      logger.warn(`Keyring save failed, using config file: ${msg}`);
    }
  }

  if (!kt) {
    logger.warn(
      `Keyring unavailable. Password will be saved in plaintext (${CONFIG_FILE}). ` +
        "Install keytar for secure storage.",
    );
  }
  config.password = password;
  saveConfig(config);
  return false;
}

/**
 * Return the saved username without touching secrets.
 * Safe to use in display/logging contexts.
 */
export function getSavedUsername(): string | null {
  const config = loadConfig();
  return config.username ?? null;
}

export async function clearCredentials(): Promise<void> {
  const kt = await loadKeytar();
  const config = loadRawConfig();
  const username = config.username;

  if (kt && typeof username === "string") {
    try {
      await kt.deletePassword(KEYRING_SERVICE, username);
    } catch {
      // Ignore
    }
  }

  delete config.username;
  delete config.password;
  saveConfig(config);
}

async function migratePlaintextPassword(kt: KeytarModule | null): Promise<void> {
  if (!kt) return;
  const config = loadConfig();
  const username = config.username;
  if (!username || !config.password) return;

  try {
    const keyringPassword = await kt.getPassword(KEYRING_SERVICE, username);
    if (keyringPassword) {
      const raw = loadRawConfig();
      if ("password" in raw) {
        delete raw.password;
        saveConfig(raw);
      }
    }
  } catch {
    // Can't verify keyring has it -- don't remove plaintext
  }
}
