// SPDX-License-Identifier: Apache-2.0
/**
 * PKI certificate chain validation against a Trust Service List.
 *
 * Extracts all certificates from a CMS SignedData blob, builds the
 * certificate chain, and validates it against trust anchors from a TSL.
 */

import * as asn1js from "asn1js";
import * as pkijs from "pkijs";

import { MAX_AIA_FETCHES } from "../constants.js";
import { httpGet } from "../network/transport.js";
import { toArrayBuffer } from "../utils.js";
import { getOidName } from "./cert-info.js";
import { getTrustStore, type TrustStore } from "./tsl.js";

// -- Types --------------------------------------------------------------------

export interface ChainResult {
  readonly chainValid: boolean | null;
  readonly trustAnchor: string | null;
  readonly chainDepth: number;
  readonly details: string[];
}

// -- Certificate extraction from CMS ------------------------------------------

function extractAllCertsFromCms(cmsDer: Uint8Array): pkijs.Certificate[] {
  const asn1 = asn1js.fromBER(toArrayBuffer(cmsDer));
  if (asn1.offset === -1) return [];

  const contentInfo = new pkijs.ContentInfo({ schema: asn1.result });
  const signedData = new pkijs.SignedData({ schema: contentInfo.content });

  if (!signedData.certificates) return [];

  const certs: pkijs.Certificate[] = [];
  for (const cert of signedData.certificates) {
    if (cert instanceof pkijs.Certificate) {
      certs.push(cert);
    }
  }
  return certs;
}

// -- Certificate helpers ------------------------------------------------------

function getSubjectDn(cert: pkijs.Certificate): string {
  return cert.subject.typesAndValues
    .map((tv) => {
      const oid = tv.type;
      const val = tv.value.valueBlock.value;
      const name = getOidName(oid);
      return `${name}=${val}`;
    })
    .join(", ");
}

function getSki(cert: pkijs.Certificate): Uint8Array | null {
  if (!cert.extensions) return null;
  for (const ext of cert.extensions) {
    if (ext.extnID === "2.5.29.14") {
      // Subject Key Identifier
      const asn1 = asn1js.fromBER(ext.extnValue.valueBlock.valueHexView);
      if (asn1.offset !== -1 && asn1.result instanceof asn1js.OctetString) {
        return new Uint8Array(asn1.result.valueBlock.valueHexView);
      }
    }
  }
  return null;
}

function getAkiKeyId(cert: pkijs.Certificate): Uint8Array | null {
  if (!cert.extensions) return null;
  for (const ext of cert.extensions) {
    if (ext.extnID === "2.5.29.35") {
      // Authority Key Identifier
      const asn1 = asn1js.fromBER(ext.extnValue.valueBlock.valueHexView);
      if (asn1.offset === -1) return null;
      const seq = asn1.result;
      // keyIdentifier is context-tagged [0], extract via Primitive wrapper
      if (seq instanceof asn1js.Sequence && seq.valueBlock.value.length > 0) {
        const first = seq.valueBlock.value[0];
        if (first !== undefined && first.idBlock.tagNumber === 0) {
          // Re-parse as OctetString to get proper typed access
          const wrapped = new asn1js.OctetString({ valueHex: first.valueBeforeDecodeView });
          return new Uint8Array(wrapped.valueBlock.valueHexView);
        }
      }
    }
  }
  return null;
}

function isSelfSigned(cert: pkijs.Certificate): boolean {
  return cert.issuer.isEqual(cert.subject);
}

function bytesEqual(a: Uint8Array | null, b: Uint8Array | null): boolean {
  if (a === null || b === null) return false;
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

// -- AIA fetching -------------------------------------------------------------

function getAiaCaIssuerUrls(cert: pkijs.Certificate): string[] {
  if (!cert.extensions) return [];
  const urls: string[] = [];
  for (const ext of cert.extensions) {
    if (ext.extnID === "1.3.6.1.5.5.7.1.1") {
      // Authority Information Access
      try {
        const parsedValue = ext.parsedValue as pkijs.InfoAccess | undefined;
        if (parsedValue?.accessDescriptions) {
          for (const desc of parsedValue.accessDescriptions) {
            // caIssuers OID: 1.3.6.1.5.5.7.48.2
            if (desc.accessMethod === "1.3.6.1.5.5.7.48.2" && desc.accessLocation.type === 6) {
              urls.push(desc.accessLocation.value as string);
            }
          }
        }
      } catch {
        // ignore parse errors
      }
    }
  }
  return urls;
}

async function fetchIntermediateCert(url: string): Promise<pkijs.Certificate | null> {
  try {
    const certDer = await httpGet(url, { timeout: 15 });
    const asn1 = asn1js.fromBER(toArrayBuffer(certDer));
    if (asn1.offset === -1) return null;
    return new pkijs.Certificate({ schema: asn1.result });
  } catch {
    return null;
  }
}

// -- Chain building -----------------------------------------------------------

async function buildChain(
  leaf: pkijs.Certificate,
  pool: pkijs.Certificate[],
): Promise<pkijs.Certificate[]> {
  const chain = [leaf];
  let current = leaf;
  let fetched = 0;

  for (let i = 0; i < 20; i++) {
    if (isSelfSigned(current)) break;

    const aki = getAkiKeyId(current);
    if (aki === null) break;

    // Search pool
    let issuer: pkijs.Certificate | null = null;
    for (const candidate of pool) {
      const candidateSki = getSki(candidate);
      if (bytesEqual(candidateSki, aki) && candidate !== current) {
        issuer = candidate;
        break;
      }
    }

    // AIA fetch if not found
    if (issuer === null && fetched < MAX_AIA_FETCHES) {
      for (const url of getAiaCaIssuerUrls(current)) {
        const fetchedCert = await fetchIntermediateCert(url);
        if (fetchedCert !== null) {
          fetched++;
          pool.push(fetchedCert);
          const fetchedSki = getSki(fetchedCert);
          if (bytesEqual(fetchedSki, aki)) {
            issuer = fetchedCert;
            break;
          }
        }
      }
    }

    if (issuer === null) break;
    chain.push(issuer);
    current = issuer;
  }

  return chain;
}

// -- Chain validation ---------------------------------------------------------

function findMatchingAnchor(chain: pkijs.Certificate[], trustStore: TrustStore): string | null {
  for (const cert of chain) {
    const certSki = getSki(cert);
    if (certSki === null) continue;
    for (const anchor of trustStore.caAnchors) {
      const anchorAsn1 = asn1js.fromBER(toArrayBuffer(anchor.certDer));
      if (anchorAsn1.offset === -1) continue;
      const anchorCert = new pkijs.Certificate({ schema: anchorAsn1.result });
      const anchorSki = getSki(anchorCert);
      if (bytesEqual(anchorSki, certSki)) {
        return anchor.serviceName;
      }
    }
  }
  return null;
}

// -- Public API ---------------------------------------------------------------

/** Validate the certificate chain in a CMS blob against a trust store. */
export async function validateChain(
  cmsDer: Uint8Array,
  trustStore: TrustStore,
): Promise<ChainResult> {
  const details: string[] = [];

  let cmsCerts: pkijs.Certificate[];
  try {
    cmsCerts = extractAllCertsFromCms(cmsDer);
  } catch {
    return {
      chainValid: null,
      trustAnchor: null,
      chainDepth: 0,
      details: ["Chain: failed to parse CMS certificates"],
    };
  }

  if (cmsCerts.length === 0) {
    return {
      chainValid: null,
      trustAnchor: null,
      chainDepth: 0,
      details: ["Chain: no certificates in CMS"],
    };
  }

  const leaf = cmsCerts[0];
  if (leaf === undefined) {
    return {
      chainValid: null,
      trustAnchor: null,
      chainDepth: 0,
      details: ["Chain: no certificates in CMS"],
    };
  }
  details.push(`Chain: signer cert: ${getSubjectDn(leaf)}`);

  // Build pool: CMS certs + trust anchors
  const pool = [...cmsCerts];
  for (const anchor of trustStore.caAnchors) {
    const asn1Result = asn1js.fromBER(toArrayBuffer(anchor.certDer));
    if (asn1Result.offset !== -1) {
      pool.push(new pkijs.Certificate({ schema: asn1Result.result }));
    }
  }

  const chain = await buildChain(leaf, pool);
  const chainDepth = chain.length;

  if (chainDepth > 1) {
    const subjects = chain.map(getSubjectDn);
    details.push(`Chain: depth ${chainDepth}: ${subjects.join(" -> ")}`);
  }

  const anchorName = findMatchingAnchor(chain, trustStore);

  if (anchorName === null) {
    details.push(`Chain: no trusted CA found (operator: ${trustStore.schemeOperator})`);
    return { chainValid: false, trustAnchor: null, chainDepth, details };
  }

  // pkijs chain verification
  try {
    const trustedCerts = trustStore.caAnchors.map((a) => {
      const r = asn1js.fromBER(toArrayBuffer(a.certDer));
      return new pkijs.Certificate({ schema: r.result });
    });

    const chainEngine = new pkijs.CertificateChainValidationEngine({
      trustedCerts,
      certs: chain,
    });

    const result = await chainEngine.verify();
    if (result.result) {
      details.push(`Chain: trusted (${anchorName}, ${trustStore.schemeOperator})`);
      return { chainValid: true, trustAnchor: anchorName, chainDepth, details };
    }

    details.push(
      `Chain: anchor matched (${anchorName}) but verification failed: ${result.resultMessage}`,
    );
    return { chainValid: null, trustAnchor: anchorName, chainDepth, details };
  } catch {
    details.push(`Chain: anchor matched (${anchorName}) but cryptographic verification failed`);
    return { chainValid: null, trustAnchor: anchorName, chainDepth, details };
  }
}

/** High-level: fetch trust store and validate chain. */
export async function validateChainForProfile(
  cmsDer: Uint8Array,
  tslUrl: string,
): Promise<ChainResult> {
  const store = await getTrustStore(tslUrl);
  if (store === null) {
    return {
      chainValid: null,
      trustAnchor: null,
      chainDepth: 0,
      details: ["Chain: trust store unavailable"],
    };
  }
  return validateChain(cmsDer, store);
}
