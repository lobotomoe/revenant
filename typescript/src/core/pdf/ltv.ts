// SPDX-License-Identifier: Apache-2.0
/**
 * LTV (Long Term Validation) status detection for CMS signatures.
 *
 * Checks whether a CMS/PKCS#7 signature contains embedded revocation
 * data (CRL or OCSP responses) required for long-term validation.
 *
 * EKENG CoSign signatures are NOT LTV-enabled -- they contain no embedded
 * revocation data.  This is expected behavior, not a defect.
 */

import * as asn1js from "asn1js";
import * as pkijs from "pkijs";

import { logger } from "../../logger.js";

// Adobe RevocationInfoArchival attribute OID
const OID_REVOCATION_INFO_ARCHIVAL = "1.2.840.113583.1.1.8";

// id-smime-aa-ets-revocationRefs (CAdES)
const OID_REVOCATION_REFS = "1.2.840.113549.1.9.16.2.22";

// id-smime-aa-ets-revocationValues (CAdES)
const OID_REVOCATION_VALUES = "1.2.840.113549.1.9.16.2.24";

const REVOCATION_OID_NAMES: Record<string, string> = {
  [OID_REVOCATION_INFO_ARCHIVAL]: "Adobe RevocationInfoArchival",
  [OID_REVOCATION_REFS]: "CAdES revocation references",
  [OID_REVOCATION_VALUES]: "CAdES revocation values",
};

export interface LtvStatus {
  ltvEnabled: boolean;
  hasCrl: boolean;
  hasOcsp: boolean;
  hasRevocationArchival: boolean;
  details: string[];
}

/**
 * Check if a CMS signature contains LTV (Long Term Validation) data.
 */
export function checkLtvStatus(cmsDer: Uint8Array): LtvStatus {
  const details: string[] = [];
  let hasCrl = false;
  let hasOcsp = false;
  let hasRevocationArchival = false;

  let signedData: pkijs.SignedData;
  try {
    const buf = new ArrayBuffer(cmsDer.byteLength);
    new Uint8Array(buf).set(cmsDer);
    const asn1 = asn1js.fromBER(buf);
    if (asn1.offset === -1) throw new Error("Invalid ASN.1");
    const contentInfo = new pkijs.ContentInfo({ schema: asn1.result });
    signedData = new pkijs.SignedData({ schema: contentInfo.content });
  } catch (e) {
    logger.warn(`Cannot parse CMS for LTV check: ${e}`);
    details.push("Cannot parse CMS structure for LTV check");
    return {
      ltvEnabled: false,
      hasCrl: false,
      hasOcsp: false,
      hasRevocationArchival: false,
      details,
    };
  }

  // Check for embedded CRLs
  if (signedData.crls && signedData.crls.length > 0) {
    hasCrl = true;
    details.push(`Embedded CRLs: ${signedData.crls.length}`);
  }

  // Check signer attributes for revocation-related OIDs
  const signerInfos = signedData.signerInfos;
  const firstSigner = signerInfos[0];
  if (firstSigner) {
    // Check signed attributes
    if (firstSigner.signedAttrs) {
      for (const attr of firstSigner.signedAttrs.attributes) {
        const oid = attr.type;
        const name = REVOCATION_OID_NAMES[oid];
        if (name) {
          details.push(`Signed attribute: ${name}`);
          if (oid === OID_REVOCATION_INFO_ARCHIVAL) {
            hasRevocationArchival = true;
            hasOcsp = true;
          }
        }
      }
    }

    // Check unsigned attributes
    if (firstSigner.unsignedAttrs) {
      for (const attr of firstSigner.unsignedAttrs.attributes) {
        const oid = attr.type;
        const name = REVOCATION_OID_NAMES[oid];
        if (name) {
          details.push(`Unsigned attribute: ${name}`);
          if (oid === OID_REVOCATION_INFO_ARCHIVAL) {
            hasRevocationArchival = true;
            hasOcsp = true;
          }
        }
      }
    }
  }

  const ltvEnabled = hasCrl || hasOcsp || hasRevocationArchival;

  if (!ltvEnabled) {
    details.push("No embedded revocation data (CRL/OCSP)");
  }

  return { ltvEnabled, hasCrl, hasOcsp, hasRevocationArchival, details };
}
