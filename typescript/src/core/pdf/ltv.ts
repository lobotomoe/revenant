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
  /**
   * True only when well-formed revocation material travels inside the signer's
   * *signed* attributes, so the signer committed to it. Material anyone can
   * append after the fact never raises this, whatever it claims to be.
   */
  ltvEnabled: boolean;
  hasCrl: boolean;
  hasOcsp: boolean;
  hasRevocationArchival: boolean;
  /**
   * Revocation material that is present but outside the signature: unsigned
   * attributes and the `crls` field, neither of which the signer signed.
   * Reported so it is visible, never counted as evidence.
   */
  hasUnauthenticatedMaterial: boolean;
  details: string[];
}

/** asn1js tag classes: 1 universal, 2 application, 3 context, 4 private. */
const ASN1_CONTEXT_CLASS = 3;
/** RevocationInfoArchival ::= SEQUENCE { crl [0], ocsp [1], otherRevInfo [2] } */
const ARCHIVAL_CRL_TAG = 0;
const ARCHIVAL_OCSP_TAG = 1;

/**
 * Read an attribute value as revocation material: `[hasCrl, hasOcsp]`.
 *
 * `undefined` when the value is not that kind of structure at all. The OID
 * proves nothing on its own: an attribute is a container, and whoever writes one
 * chooses what goes inside. This says which members are present, not whether the
 * revocation data inside them is genuine -- that check does not exist yet.
 */
function revocationContainerMembers(
  attribute: pkijs.Attribute,
): { hasCrl: boolean; hasOcsp: boolean } | undefined {
  const value = attribute.values[0];
  if (!(value instanceof asn1js.Sequence)) return undefined;

  let hasCrl = false;
  let hasOcsp = false;
  for (const member of value.valueBlock.value) {
    if (member.idBlock.tagClass !== ASN1_CONTEXT_CLASS) continue;
    if (member.idBlock.tagNumber === ARCHIVAL_CRL_TAG) hasCrl = true;
    if (member.idBlock.tagNumber === ARCHIVAL_OCSP_TAG) hasOcsp = true;
  }
  return { hasCrl, hasOcsp };
}

/**
 * Check whether a CMS signature carries long-term-validation evidence.
 *
 * Only material the signer actually signed can count. The CMS `crls` field and
 * the signer's *unsigned* attributes are outside the signature: a third party
 * can add either to a finished document without invalidating it, so they are
 * reported as present and explicitly not counted.
 *
 * This reports the presence of well-formed material, not its validity: the
 * responses and CRLs are not checked against the signer's chain, so a true
 * `ltvEnabled` means "the signer embedded revocation evidence", not "the
 * evidence was verified".
 */
export function checkLtvStatus(cmsDer: Uint8Array): LtvStatus {
  const details: string[] = [];
  let hasCrl = false;
  let hasOcsp = false;
  let hasRevocationArchival = false;
  let hasUnauthenticatedMaterial = false;
  let authenticatedMaterial = false;

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
      hasUnauthenticatedMaterial: false,
      details,
    };
  }

  // The crls field sits beside the signature rather than inside it: RFC 5652
  // puts the signature over the signed attributes, never over this collection.
  // Anyone can add or drop entries here without disturbing the signature.
  if (signedData.crls && signedData.crls.length > 0) {
    hasCrl = true;
    hasUnauthenticatedMaterial = true;
    details.push(`Embedded CRLs: ${signedData.crls.length} (outside the signature, not counted)`);
  }

  // Check signer attributes for revocation-related OIDs
  const signerInfos = signedData.signerInfos;
  const firstSigner = signerInfos[0];
  if (firstSigner) {
    // Signed attributes are the signature input, so what is found here is
    // material the signer committed to.
    if (firstSigner.signedAttrs) {
      for (const attr of firstSigner.signedAttrs.attributes) {
        const name = REVOCATION_OID_NAMES[attr.type];
        if (!name) continue;
        const members = revocationContainerMembers(attr);
        if (!members) {
          details.push(`Signed attribute: ${name} (malformed, not counted)`);
          continue;
        }
        details.push(`Signed attribute: ${name}`);
        authenticatedMaterial = true;
        hasCrl = hasCrl || members.hasCrl;
        hasOcsp = hasOcsp || members.hasOcsp;
        if (attr.type === OID_REVOCATION_INFO_ARCHIVAL) hasRevocationArchival = true;
      }
    }

    // Unsigned attributes are not covered by the signature: a third party can
    // staple one onto a finished document. Reported, never counted.
    if (firstSigner.unsignedAttrs) {
      for (const attr of firstSigner.unsignedAttrs.attributes) {
        const name = REVOCATION_OID_NAMES[attr.type];
        if (!name) continue;
        hasUnauthenticatedMaterial = true;
        details.push(`Unsigned attribute: ${name} (outside the signature, not counted)`);
      }
    }
  }

  const ltvEnabled = authenticatedMaterial;

  if (!ltvEnabled) {
    details.push("No signed revocation data (CRL/OCSP)");
  }

  return {
    ltvEnabled,
    hasCrl,
    hasOcsp,
    hasRevocationArchival,
    hasUnauthenticatedMaterial,
    details,
  };
}
