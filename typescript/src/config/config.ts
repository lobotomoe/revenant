// SPDX-License-Identifier: Apache-2.0
/**
 * Configuration management for Revenant.
 *
 * Stores signer identity, server profile, and preferences in
 * ~/.revenant/config.json.
 */

import {
  DEFAULT_TIMEOUT_SOAP,
  ENV_TIMEOUT,
  ENV_URL,
  MAX_TIMEOUT,
  MIN_TIMEOUT,
} from "../constants.js";
import { logger } from "../logger.js";
import { clearCredentials, clearSessionCredentials } from "./credentials.js";
import { BUILTIN_PROFILES, makeCustomProfile, type ServerProfile } from "./profiles.js";
import { loadConfig, loadRawConfig, saveConfig } from "./storage.js";

// -- Server config -----------------------------------------------------------

export function getServerConfig(): {
  url: string | null;
  timeout: number | null;
  profileName: string | null;
} {
  const config = loadConfig();

  let url = (process.env[ENV_URL] ?? "").trim();
  const timeoutStr = (process.env[ENV_TIMEOUT] ?? "").trim();
  const profileName = config.profile ?? null;

  if (!url) {
    url = config.url ?? "";
  }

  if (!url && profileName) {
    const profile = BUILTIN_PROFILES.get(profileName);
    if (profile) {
      url = profile.url;
    }
  }

  if (!url) {
    return { url: null, timeout: null, profileName: null };
  }

  let timeout: number;
  if (timeoutStr) {
    const parsed = parseInt(timeoutStr, 10);
    if (Number.isNaN(parsed) || parsed < MIN_TIMEOUT || parsed > MAX_TIMEOUT) {
      logger.warn(`${ENV_TIMEOUT}=${timeoutStr} invalid or out of range, using default`);
      timeout = DEFAULT_TIMEOUT_SOAP;
    } else {
      timeout = parsed;
    }
  } else if (config.timeout !== undefined) {
    timeout = config.timeout;
  } else if (profileName && BUILTIN_PROFILES.has(profileName)) {
    timeout = BUILTIN_PROFILES.get(profileName)?.timeout ?? DEFAULT_TIMEOUT_SOAP;
  } else {
    timeout = DEFAULT_TIMEOUT_SOAP;
  }

  return { url, timeout, profileName };
}

export function getActiveProfile(): ServerProfile | null {
  const config = loadConfig();
  const profileName = config.profile;

  if (profileName) {
    const profile = BUILTIN_PROFILES.get(profileName);
    if (profile) return profile;
  }

  const url = config.url ?? "";
  const timeout = config.timeout ?? DEFAULT_TIMEOUT_SOAP;

  if (url) {
    return makeCustomProfile(url, timeout);
  }

  return null;
}

export function saveServerConfig(profile: ServerProfile): void {
  const config = loadRawConfig();
  config.profile = profile.name;
  config.url = profile.url;
  config.timeout = profile.timeout;
  saveConfig(config);
}

// -- Signer identity ---------------------------------------------------------

export function getSignerName(): string | null {
  const config = loadConfig();
  return config.name ?? null;
}

export interface SignerInfo {
  name: string | null;
  email: string | null;
  organization: string | null;
  dn: string | null;
}

export function getSignerInfo(): SignerInfo {
  const config = loadConfig();
  return {
    name: config.name ?? null,
    email: config.email ?? null,
    organization: config.organization ?? null,
    dn: config.dn ?? null,
  };
}

export function saveSignerInfo(
  name: string,
  email?: string | null,
  organization?: string | null,
  dn?: string | null,
): void {
  const config = loadRawConfig();
  config.name = name;

  const optionalFields = [
    ["email", email],
    ["organization", organization],
    ["dn", dn],
  ] as const;

  for (const [key, value] of optionalFields) {
    if (value) {
      config[key] = value;
    } else {
      delete config[key];
    }
  }

  saveConfig(config);
}

export async function resetAll(): Promise<void> {
  await clearCredentials();
  clearSessionCredentials();
  saveConfig({});
}

const IDENTITY_KEYS = ["name", "email", "organization", "dn"] as const;

export async function logout(): Promise<void> {
  await clearCredentials();
  clearSessionCredentials();

  const config = loadRawConfig();
  let changed = false;
  for (const key of IDENTITY_KEYS) {
    if (key in config) {
      delete config[key];
      changed = true;
    }
  }
  if (changed) {
    saveConfig(config);
  }
}

// -- Layer detection ---------------------------------------------------------

export function getConfigLayer(): number {
  const { url } = getServerConfig();
  if (!url) return 0;
  if (!getSignerName()) return 1;
  return 2;
}
