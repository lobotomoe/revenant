// SPDX-License-Identifier: Apache-2.0
/** Cryptographic verification of CMS SignerInfo signatures. */

import * as asn1js from "asn1js";
import * as pkijs from "pkijs";

import { toArrayBuffer } from "../../utils.js";
import { findSignerCertificate } from "../cms-certificates.js";
import { resolveHashAlgo } from "./cms-info.js";

const OID_SIGNED_DATA = "1.2.840.113549.1.7.2";
const OID_CONTENT_TYPE = "1.2.840.113549.1.9.3";
const OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4";

const STANDARD_DIGEST_OIDS: ReadonlyMap<string, string> = new Map([
  ["SHA-1", "1.3.14.3.2.26"],
  ["SHA-256", "2.16.840.1.101.3.4.2.1"],
  ["SHA-384", "2.16.840.1.101.3.4.2.2"],
  ["SHA-512", "2.16.840.1.101.3.4.2.3"],
]);

const DIGEST_LENGTHS: ReadonlyMap<string, number> = new Map([
  ["SHA-1", 20],
  ["SHA-256", 32],
  ["SHA-384", 48],
  ["SHA-512", 64],
]);

export interface SignatureVerification {
  /** true = verified, false = bad signature, null = verification unavailable. */
  valid: boolean | null;
  /** Stable diagnostic line for VerificationResult.details. */
  detail: string;
}

function unverifiable(reason: string): SignatureVerification {
  return {
    valid: null,
    detail: `Signature not verified (${reason})`,
  };
}

function validateSignedAttributes(
  signedData: pkijs.SignedData,
  signerInfo: pkijs.SignerInfo,
  digestAlgorithm: string,
): string | null {
  const signedAttrs = signerInfo.signedAttrs;
  if (!signedAttrs) return "no signed attributes";

  const contentTypeAttrs = signedAttrs.attributes.filter((attr) => attr.type === OID_CONTENT_TYPE);
  if (contentTypeAttrs.length !== 1 || contentTypeAttrs[0]?.values.length !== 1) {
    return "contentType attribute missing or duplicated";
  }
  const contentTypeValue = contentTypeAttrs[0].values[0];
  if (!(contentTypeValue instanceof asn1js.ObjectIdentifier)) {
    return "contentType attribute is malformed";
  }
  if (contentTypeValue.valueBlock.toString() !== signedData.encapContentInfo.eContentType) {
    return "contentType attribute is inconsistent";
  }

  const digestAttrs = signedAttrs.attributes.filter((attr) => attr.type === OID_MESSAGE_DIGEST);
  if (digestAttrs.length !== 1 || digestAttrs[0]?.values.length !== 1) {
    return "messageDigest attribute missing or duplicated";
  }
  const digestValue = digestAttrs[0].values[0];
  const expectedLength = DIGEST_LENGTHS.get(digestAlgorithm);
  if (
    !(digestValue instanceof asn1js.OctetString) ||
    expectedLength === undefined ||
    digestValue.valueBlock.valueHexView.byteLength !== expectedLength
  ) {
    return "messageDigest attribute is malformed";
  }

  return null;
}

/**
 * Verify the first CMS signer's signature with its embedded certificate.
 *
 * Certificate-chain trust is deliberately separate. Unsupported or malformed
 * inputs fail closed and can never produce a valid overall verification result.
 */
export async function verifySignerSignature(
  cmsDer: Uint8Array,
  data: Uint8Array,
): Promise<SignatureVerification> {
  try {
    const asn1 = asn1js.fromBER(toArrayBuffer(cmsDer));
    if (asn1.offset === -1 || asn1.offset !== cmsDer.byteLength) {
      return unverifiable("CMS did not parse as one complete ASN.1 value");
    }

    const contentInfo = new pkijs.ContentInfo({ schema: asn1.result });
    if (contentInfo.contentType !== OID_SIGNED_DATA) {
      return unverifiable("CMS content is not SignedData");
    }

    const signedData = new pkijs.SignedData({ schema: contentInfo.content });
    const signerInfo = signedData.signerInfos[0];
    if (!signerInfo) return unverifiable("no SignerInfo present");
    if (findSignerCertificate(signedData, signerInfo) === null) {
      return unverifiable("signer certificate not embedded or ambiguous");
    }

    const digestAlgorithm = resolveHashAlgo(signerInfo.digestAlgorithm.algorithmId);
    if (!digestAlgorithm) return unverifiable("unrecognized digest algorithm");

    const attrError = validateSignedAttributes(signedData, signerInfo, digestAlgorithm);
    if (attrError) return unverifiable(attrError);

    // CoSign may put a sha*WithRSAEncryption OID in digestAlgorithm. PKIjs
    // expects the corresponding pure digest OID there, so normalize only its
    // in-memory algorithm dispatch; signed attribute bytes remain untouched.
    const standardDigestOid = STANDARD_DIGEST_OIDS.get(digestAlgorithm);
    if (!standardDigestOid) return unverifiable("unrecognized digest algorithm");
    signerInfo.digestAlgorithm.algorithmId = standardDigestOid;

    const verified = await signedData.verify({
      signer: 0,
      checkChain: false,
      data: toArrayBuffer(data),
    });
    return verified
      ? { valid: true, detail: "Signature OK -- signer signature verifies" }
      : {
          valid: false,
          detail: "Signature INVALID -- does not verify against the signer certificate",
        };
  } catch (error) {
    if (error instanceof pkijs.SignedDataVerifyError && error.signatureVerified === false) {
      return {
        valid: false,
        detail: "Signature INVALID -- does not verify against the signer certificate",
      };
    }
    return unverifiable("CMS signature check failed");
  }
}
