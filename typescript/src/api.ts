// SPDX-License-Identifier: Apache-2.0
/**
 * High-level convenience API.
 *
 * All exports here handle profile resolution, transport creation,
 * TLS registration, and appearance defaults automatically — callers
 * pass credentials and (optionally) a server profile name. For
 * lower-level control with an explicit transport, see the
 * `*WithTransport` exports in `./core/signing.js`.
 */

import {
  getActiveProfile,
  getProfile,
  getServerConfig,
  getSignerInfo,
  getSignerName,
  makeCustomProfile,
  registerProfileTlsMode,
  type ServerProfile,
} from "./config/index.js";
import { DEFAULT_TIMEOUT_SOAP } from "./constants.js";
import { extractCertFields, extractDisplayFields } from "./core/appearance/index.js";
import { type CertInfo, discoverIdentityFromServer } from "./core/cert-info.js";
import type { PrepareOptions } from "./core/pdf/index.js";
import {
  signDataWithTransport,
  signHashWithTransport,
  signPdfDetachedWithTransport,
  signPdfEmbeddedWithTransport,
} from "./core/signing.js";
import { ConfigError } from "./errors.js";
import { SoapSigningTransport } from "./network/soap-transport.js";

// -- Types --------------------------------------------------------------------

export interface SignOptions {
  /** Built-in profile name (e.g. "ekeng"). Mutually exclusive with url. */
  profile?: string | null;
  /** SOAP endpoint URL. Mutually exclusive with profile. */
  url?: string | null;
  /** Request timeout in seconds. Auto-resolved if not set. */
  timeout?: number | null;
  /** Target page -- 0-based int, "first", or "last". */
  page?: number | string;
  /** Position preset ("bottom-right", "top-left", etc.). */
  position?: string;
  /** Manual x-coordinate in PDF points (overrides position). */
  x?: number | null;
  /** Manual y-coordinate in PDF points (overrides position). */
  y?: number | null;
  /** Signature field width in PDF points. */
  width?: number | null;
  /** Signature field height in PDF points. */
  height?: number | null;
  /** Signature reason string. */
  reason?: string;
  /** Signer display name. Auto-resolved from config if not set. */
  name?: string | null;
  /** Path to a PNG/JPEG signature image. */
  imagePath?: string | null;
  /** Display strings for the signature appearance. */
  fields?: string[] | null;
  /** Set to false for an invisible signature. */
  visible?: boolean;
  /** Font key ("noto-sans", "ghea-grapalat", etc.). */
  font?: string | null;
}

export interface DetachedSignOptions {
  /** Built-in profile name. Mutually exclusive with url. */
  profile?: string | null;
  /** SOAP endpoint URL. Mutually exclusive with profile. */
  url?: string | null;
  /** Request timeout in seconds. */
  timeout?: number | null;
}

// -- Private resolution helpers -----------------------------------------------

function resolveProfile(
  profile: string | null | undefined,
  url: string | null | undefined,
): ServerProfile | null {
  if (profile != null && url != null) {
    throw new ConfigError("Cannot specify both 'profile' and 'url'. Use one or the other.");
  }
  if (profile != null) {
    return getProfile(profile);
  }
  if (url != null) {
    return makeCustomProfile(url);
  }
  return getActiveProfile();
}

function resolveUrlAndTimeout(
  profileObj: ServerProfile | null,
  explicitUrl: string | null | undefined,
  explicitTimeout: number | null | undefined,
): { url: string; timeout: number } {
  let url: string | null = explicitUrl ?? null;
  if (url === null && profileObj !== null) {
    url = profileObj.url;
  }

  let timeout: number | null = explicitTimeout ?? null;
  if (timeout === null && profileObj !== null) {
    timeout = profileObj.timeout;
  }

  if (!url) {
    const config = getServerConfig();
    if (config.url) {
      url = config.url;
      if (timeout === null) {
        timeout = config.timeout;
      }
    } else {
      throw new ConfigError(
        "No server URL configured. " +
          "Pass url='https://...' or profile='ekeng', " +
          "or run `revenant setup` to save a profile.",
      );
    }
  }

  return { url, timeout: timeout ?? DEFAULT_TIMEOUT_SOAP };
}

function resolveSigFields(profileObj: ServerProfile | null): string[] | null {
  if (profileObj === null || profileObj.sigFields.length === 0) {
    return null;
  }
  const signerInfo = getSignerInfo();
  const certValues = extractCertFields(profileObj.certFields, { ...signerInfo });
  return extractDisplayFields(profileObj.sigFields, certValues);
}

async function setupTransport(
  url: string,
  profileObj: ServerProfile | null,
): Promise<SoapSigningTransport> {
  if (profileObj !== null) {
    await registerProfileTlsMode(profileObj);
  }
  return new SoapSigningTransport(url);
}

// -- Public API ---------------------------------------------------------------

/**
 * Sign a PDF with an embedded signature.
 *
 * High-level convenience function that handles profile resolution,
 * transport creation, TLS registration, and appearance defaults.
 *
 * Server resolution (first match wins):
 *   1. profile="ekeng" -- look up a built-in server profile.
 *   2. url="https://..." -- use a custom SOAP endpoint.
 *   3. Saved configuration from `revenant setup`.
 *
 * When name, font, or fields are not provided explicitly they are
 * auto-resolved from the server profile and saved signer identity.
 */
export async function sign(
  pdfBytes: Uint8Array,
  username: string,
  password: string,
  options: SignOptions = {},
): Promise<Uint8Array> {
  const profileObj = resolveProfile(options.profile, options.url);
  const { url: resolvedUrl, timeout: resolvedTimeout } = resolveUrlAndTimeout(
    profileObj,
    options.url,
    options.timeout,
  );

  // Auto-resolve name from saved config
  const resolvedName = options.name ?? getSignerName();

  // Auto-resolve font from profile
  let resolvedFont = options.font ?? null;
  if (resolvedFont === null && profileObj !== null) {
    resolvedFont = profileObj.font;
  }

  // Auto-resolve signature fields from profile
  const visible = options.visible ?? true;
  let resolvedFields = options.fields ?? null;
  if (resolvedFields === null && visible) {
    resolvedFields = resolveSigFields(profileObj);
  }

  const transport = await setupTransport(resolvedUrl, profileObj);

  // Build PrepareOptions -- only include optional geometry if explicitly provided
  const prepareOptions: PrepareOptions = {
    page: options.page ?? "last",
    position: options.position ?? "bottom-right",
    reason: options.reason ?? "",
    name: resolvedName,
    fields: resolvedFields,
    visible,
    font: resolvedFont,
  };
  if (options.x != null) prepareOptions.x = options.x;
  if (options.y != null) prepareOptions.y = options.y;
  if (options.width != null) prepareOptions.width = options.width;
  if (options.height != null) prepareOptions.height = options.height;
  if (options.imagePath != null) prepareOptions.imagePath = options.imagePath;

  return signPdfEmbeddedWithTransport(
    pdfBytes,
    transport,
    username,
    password,
    resolvedTimeout,
    prepareOptions,
  );
}

/**
 * Sign a PDF and return a detached CMS/PKCS#7 signature.
 *
 * Server resolution is identical to sign().
 */
export async function signDetached(
  pdfBytes: Uint8Array,
  username: string,
  password: string,
  options: DetachedSignOptions = {},
): Promise<Uint8Array> {
  const profileObj = resolveProfile(options.profile, options.url);
  const { url: resolvedUrl, timeout: resolvedTimeout } = resolveUrlAndTimeout(
    profileObj,
    options.url,
    options.timeout,
  );
  const transport = await setupTransport(resolvedUrl, profileObj);

  return signPdfDetachedWithTransport(pdfBytes, transport, username, password, resolvedTimeout);
}

// -- Public API: hash / data / identity ---------------------------------------

/**
 * Sign a pre-computed hash and return a detached CMS/PKCS#7 signature.
 *
 * High-level convenience: handles profile resolution, transport
 * creation, and TLS registration.
 *
 * The EKENG CoSign appliance signs RSA with SHA-1 — `hashBytes` must
 * be exactly 20 bytes (`SHA1_DIGEST_SIZE`); other sizes throw
 * `RevenantError`.
 *
 * Server resolution is identical to `signDetached`.
 */
export async function signHash(
  hashBytes: Uint8Array,
  username: string,
  password: string,
  options: DetachedSignOptions = {},
): Promise<Uint8Array> {
  const profileObj = resolveProfile(options.profile, options.url);
  const { url: resolvedUrl, timeout: resolvedTimeout } = resolveUrlAndTimeout(
    profileObj,
    options.url,
    options.timeout,
  );
  const transport = await setupTransport(resolvedUrl, profileObj);
  return signHashWithTransport(hashBytes, transport, username, password, resolvedTimeout);
}

/**
 * Sign arbitrary data and return a detached CMS/PKCS#7 signature.
 * The server hashes the data internally (SHA-1) and signs the digest.
 *
 * High-level convenience: handles profile resolution, transport
 * creation, and TLS registration.
 *
 * Server resolution is identical to `signDetached`.
 */
export async function signData(
  dataBytes: Uint8Array,
  username: string,
  password: string,
  options: DetachedSignOptions = {},
): Promise<Uint8Array> {
  const profileObj = resolveProfile(options.profile, options.url);
  const { url: resolvedUrl, timeout: resolvedTimeout } = resolveUrlAndTimeout(
    profileObj,
    options.url,
    options.timeout,
  );
  const transport = await setupTransport(resolvedUrl, profileObj);
  return signDataWithTransport(dataBytes, transport, username, password, resolvedTimeout);
}

/**
 * Retrieve the signer's identity (CN, email, organization, validity
 * dates) from the appliance.
 *
 * Tries the `enum-certificates` SAPI operation first; falls back to
 * signing a dummy 20-byte SHA-1 hash and extracting the certificate
 * from the resulting CMS if the appliance doesn't expose
 * enum-certificates. Either way, `AuthError` is thrown on bad
 * credentials — useful for verifying credentials before persisting
 * them to a vault (see `verifyCredentials`).
 *
 * Server resolution is identical to `signDetached`.
 */
export async function getCertInfo(
  username: string,
  password: string,
  options: DetachedSignOptions = {},
): Promise<CertInfo> {
  const profileObj = resolveProfile(options.profile, options.url);
  const { url: resolvedUrl, timeout: resolvedTimeout } = resolveUrlAndTimeout(
    profileObj,
    options.url,
    options.timeout,
  );
  const transport = await setupTransport(resolvedUrl, profileObj);
  return discoverIdentityFromServer(transport, username, password, resolvedTimeout);
}

/**
 * Verify that credentials are accepted by the appliance.
 *
 * Throws `AuthError` (or any other revenant error from the transport)
 * if the credentials are invalid or the server is unreachable; returns
 * normally on success. The signer's identity is fetched as a
 * side-effect but discarded — call `getCertInfo` if you need it.
 *
 * Intended for credential-entry flows that want to fail fast before
 * persisting secrets to a vault: a wrong password caught here is
 * one failed attempt against the EKENG account lockout counter
 * (5 attempts total), not five.
 */
export async function verifyCredentials(
  username: string,
  password: string,
  options: DetachedSignOptions = {},
): Promise<void> {
  await getCertInfo(username, password, options);
}
