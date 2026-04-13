// SPDX-License-Identifier: Apache-2.0
/**
 * ETSI Trust Service List (TSL) parser and cache.
 *
 * Fetches and parses TSL XML documents (ETSI TS 119 612) to extract
 * trust anchor certificates. Used for PKI chain validation against
 * a country's trusted CA list.
 */

import { XMLParser } from "fast-xml-parser";

import { TSL_CACHE_TTL, TSL_FETCH_TIMEOUT } from "../constants.js";
import { httpGet } from "../network/transport.js";

// Service type suffix for qualified CAs
const CA_SERVICE_TYPE = "CA/QC";

// Active service status suffixes
const ACTIVE_STATUSES = new Set(["granted", "accredited", "undersupervision"]);

// -- Types --------------------------------------------------------------------

export interface TrustAnchor {
  readonly subjectName: string;
  readonly serviceName: string;
  readonly serviceType: string;
  readonly status: string;
  readonly certDer: Uint8Array;
}

export interface TrustStore {
  readonly anchors: readonly TrustAnchor[];
  readonly caAnchors: readonly TrustAnchor[];
  readonly schemeOperator: string;
  readonly tslUrl: string;
  readonly fetchedAt: number;
}

// -- XML helpers --------------------------------------------------------------

function extractServiceTypeSuffix(uri: string): string {
  const marker = "/Svctype/";
  const idx = uri.indexOf(marker);
  return idx >= 0 ? uri.slice(idx + marker.length) : uri;
}

function extractStatusSuffix(uri: string): string {
  const slash = uri.lastIndexOf("/");
  return slash >= 0 ? uri.slice(slash + 1) : uri;
}

function isActiveStatus(suffix: string): boolean {
  return ACTIVE_STATUSES.has(suffix.toLowerCase());
}

/**
 * Safely extract a text value from a fast-xml-parser node.
 *
 * fast-xml-parser returns either a plain string or an object with
 * `#text` when attributes are present on the element.
 */
function getText(val: unknown): string {
  if (typeof val === "string") return val.trim();
  if (val !== null && typeof val === "object" && "#text" in val) {
    return String((val as Record<string, unknown>)["#text"]).trim();
  }
  return "";
}

function toArray<T>(val: T | T[] | undefined): T[] {
  if (val === undefined) return [];
  return Array.isArray(val) ? val : [val];
}

// -- TSL XML shape (runtime-navigated, no `as` casts) -------------------------

/** Safely navigate a nested unknown object by dotted path. */
function dig(obj: unknown, ...keys: string[]): unknown {
  let current: unknown = obj;
  for (const key of keys) {
    if (current === null || current === undefined || typeof current !== "object") return undefined;
    current = (current as Record<string, unknown>)[key];
  }
  return current;
}

// -- TSL parsing --------------------------------------------------------------

const xmlParser = new XMLParser({
  ignoreAttributes: false,
  removeNSPrefix: true,
  parseTagValue: false,
  trimValues: true,
});

interface DigitalId {
  X509Certificate?: string;
  X509SubjectName?: string;
}

/**
 * Parse an ETSI TSL XML document into a TrustStore.
 *
 * Pure function -- no I/O.
 */
export function parseTsl(xmlBytes: Uint8Array, tslUrl = ""): TrustStore {
  const xmlStr = new TextDecoder().decode(xmlBytes);
  const parsed: unknown = xmlParser.parse(xmlStr);

  const root = dig(parsed, "TrustServiceStatusList");
  const schemeOperator =
    getText(dig(root, "SchemeInformation", "SchemeOperatorName", "Name")) || "Unknown";

  const anchors: TrustAnchor[] = [];
  const providers = toArray(dig(root, "TrustServiceProviderList", "TrustServiceProvider"));

  for (const provider of providers) {
    const services = toArray(dig(provider, "TSPServices", "TSPService"));

    for (const svc of services) {
      const info = dig(svc, "ServiceInformation");
      if (info === undefined) continue;

      const typeId = dig(info, "ServiceTypeIdentifier");
      const serviceType = extractServiceTypeSuffix(typeof typeId === "string" ? typeId : "");

      const serviceName = getText(dig(info, "ServiceName", "Name"));

      const statusUri = dig(info, "ServiceStatus");
      const status = extractStatusSuffix(typeof statusUri === "string" ? statusUri : "");

      if (!isActiveStatus(status)) continue;

      const digitalIds = toArray(dig(info, "ServiceDigitalIdentity", "DigitalId")) as DigitalId[];

      // Find subject name from any DigitalId
      let subjectName = "";
      for (const did of digitalIds) {
        if (typeof did.X509SubjectName === "string") {
          subjectName = did.X509SubjectName.trim();
          break;
        }
      }

      // Extract all X509Certificate entries
      for (const did of digitalIds) {
        if (typeof did.X509Certificate !== "string") continue;

        const b64 = did.X509Certificate.replace(/\s/g, "");
        let certDer: Uint8Array;
        try {
          certDer = Uint8Array.from(Buffer.from(b64, "base64"));
        } catch {
          continue;
        }

        anchors.push({ subjectName, serviceName, serviceType, status, certDer });
      }
    }
  }

  const caAnchors = anchors.filter((a) => a.serviceType === CA_SERVICE_TYPE);

  return { anchors, caAnchors, schemeOperator, tslUrl, fetchedAt: Date.now() };
}

// -- Fetching -----------------------------------------------------------------

/** Fetch a TSL from a URL and parse it. */
export async function fetchTrustStore(
  tslUrl: string,
  timeout: number = TSL_FETCH_TIMEOUT,
): Promise<TrustStore> {
  const xmlBytes = await httpGet(tslUrl, { timeout });
  return parseTsl(xmlBytes, tslUrl);
}

// -- Cache --------------------------------------------------------------------

const cache = new Map<string, TrustStore>();

/** Get a cached TrustStore, fetching if needed. Returns null on failure. */
export async function getTrustStore(
  tslUrl: string,
  ttl: number = TSL_CACHE_TTL,
): Promise<TrustStore | null> {
  const cached = cache.get(tslUrl);
  const ttlMs = ttl * 1000;
  if (cached !== undefined && Date.now() - cached.fetchedAt < ttlMs) {
    return cached;
  }

  try {
    const store = await fetchTrustStore(tslUrl);
    cache.set(tslUrl, store);
    return store;
  } catch {
    // Return stale cache if available
    return cache.get(tslUrl) ?? null;
  }
}

/** Clear the TSL cache (for testing). */
export function clearCache(): void {
  cache.clear();
}
