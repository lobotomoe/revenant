// SPDX-License-Identifier: Apache-2.0
/** Configuration management for Revenant. */

export {
  getActiveProfile,
  getConfigLayer,
  getServerConfig,
  getSignerInfo,
  getSignerName,
  logout,
  resetAll,
  type SignerInfo,
  saveServerConfig,
  saveSignerInfo,
} from "./config.js";
export {
  clearCredentials,
  clearSessionCredentials,
  getCredentialStorageInfo,
  getCredentials,
  getSavedUsername,
  isKeyringAvailable,
  resolveCredentials,
  saveCredentials,
  setSessionCredentials,
} from "./credentials.js";
export {
  BUILTIN_PROFILES,
  type CertField,
  getProfile,
  hasIdentityMethod,
  makeCustomProfile,
  type ServerProfile,
  type SigField,
} from "./profiles.js";
export { CONFIG_DIR, CONFIG_FILE } from "./storage.js";

// -- TLS mode bridge ---------------------------------------------------------

import type { ServerProfile } from "./profiles.js";

/**
 * Register the TLS mode for a profile's host.
 * Called from the config layer to bridge profiles to the transport layer.
 */
export async function registerProfileTlsMode(profile: ServerProfile): Promise<void> {
  const { registerHostTls } = await import("../network/transport.js");
  const host = new URL(profile.url).hostname;
  registerHostTls(host, profile.legacyTls);
}

/**
 * Register TLS mode for the active (saved) profile.
 * Convenience wrapper used by CLI workflows before signing.
 */
export async function registerActiveProfileTls(): Promise<void> {
  const { getActiveProfile: getActive } = await import("./config.js");
  const profile = getActive();
  if (profile) {
    await registerProfileTlsMode(profile);
  }
}
