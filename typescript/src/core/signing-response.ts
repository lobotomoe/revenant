// SPDX-License-Identifier: Apache-2.0
/**
 * Proof that a signing service returned a signature over what was submitted.
 *
 * A signing call that reports success while handing back bytes nobody checked
 * is, from the caller's side, indistinguishable from one that worked -- the
 * failure only surfaces later, in whatever verifier the document eventually
 * reaches. So every response a workflow is about to return passes through here
 * first: the CMS must parse, carry the signer's certificate, and verify as a
 * signature over exactly the bytes that were sent.
 *
 * This deliberately says nothing about *who* signed. Whether the certificate is
 * one worth trusting is a chain question, answered separately and reported
 * rather than enforced; binding the response to the request is the part that
 * has to hold for every profile, online or offline.
 *
 * Submitting a document and submitting its digest are different situations, so
 * they are different functions. With the content in hand the binding can be
 * proven. With only a digest it cannot: what a service signs in response to a
 * pre-computed digest is service-defined, and services differ. That gap is
 * reported rather than papered over.
 */

import { SigningResponseError } from "../errors.js";
import { logger } from "../logger.js";
import { extractDigestInfo } from "./pdf/cms-info.js";
import { verifySignerSignature } from "./pdf/cms-signature.js";
import { verifyDetachedSignature } from "./pdf/verify.js";

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  return a.every((byte, i) => byte === b[i]);
}

/**
 * Throw unless the response is a valid signature over exactly `content`.
 *
 * @throws SigningResponseError when the response is not a signature, or does
 *   not cover the submitted bytes.
 */
export async function checkResponseOverContent(
  cmsDer: Uint8Array,
  content: Uint8Array,
  operation: string,
): Promise<void> {
  const result = await verifyDetachedSignature(content, cmsDer);
  if (result.valid) {
    return;
  }

  const detailStr = result.details.join("\n  ");
  throw new SigningResponseError(
    `${operation}: the signing service's response is not a valid signature over ` +
      `the ${content.length} bytes submitted:\n  ${detailStr}\nNothing was saved.`,
  );
}

/**
 * Throw unless the response is a genuine signature; report what it binds.
 *
 * Only a digest was submitted, so there is no content to verify the signature
 * against and no way to prove the response covers the document that digest came
 * from. What is provable — that the response is a real signature by the
 * certificate it carries — is required. What is not provable is reported: if
 * the signed `messageDigest` differs from the digest submitted, the service did
 * not treat it as a pre-computed digest, and the signature must not be attached
 * to the document it was taken from.
 *
 * @throws SigningResponseError when the response is not a verifiable signature.
 */
export async function checkResponseOverDigest(
  cmsDer: Uint8Array,
  digest: Uint8Array,
  operation: string,
): Promise<void> {
  const signature = await verifySignerSignature(cmsDer, null);
  if (signature.valid !== true) {
    throw new SigningResponseError(
      `${operation}: the signing service returned a response that is not a ` +
        `verifiable signature (${signature.detail}). Nothing was saved.`,
    );
  }

  // A signature that verified without content signed its signed attributes, and
  // those must carry exactly one well-formed messageDigest — the verifier rejects
  // them otherwise. Its absence here means two readings of the same CMS disagree,
  // which is our bug, not a service quirk.
  const digestInfo = extractDigestInfo(cmsDer);
  if (digestInfo === null) {
    throw new SigningResponseError(
      `${operation}: the response verified as a signature but declares no ` +
        "messageDigest; the CMS could not be read consistently. Nothing was saved.",
    );
  }

  if (equalBytes(digestInfo.digest, digest)) {
    return;
  }

  logger.warn(
    `${operation}: the signing service signed the submitted digest as content ` +
      "rather than treating it as a pre-computed digest -- the response binds " +
      `${toHex(digestInfo.digest)}, not the ${toHex(digest)} that was submitted. ` +
      "It is a valid signature, but not one that can be attached to the document " +
      "that digest came from; use signData on the document itself for that.",
  );
}
