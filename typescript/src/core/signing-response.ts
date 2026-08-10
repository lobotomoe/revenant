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
 */

import { SigningResponseError } from "../errors.js";
import { verifySignerSignature } from "./pdf/cms-signature.js";
import { verifyDetachedSignature } from "./pdf/verify.js";

/**
 * Reject a signing response that cannot be proven to be a usable signature.
 *
 * `signedContent` is the exact byte string submitted for signing, when the
 * request determines it; the response must then verify as a signature over
 * those bytes. `null` belongs only where the submitted material does not
 * determine the signed content -- the signature itself is still verified, but
 * nothing ties it to a particular document.
 *
 * @throws SigningResponseError when the response is not a signature, or does
 *   not cover the submitted bytes.
 */
export async function checkSigningResponse(
  cmsDer: Uint8Array,
  signedContent: Uint8Array | null,
  operation: string,
): Promise<void> {
  if (signedContent === null) {
    const signature = await verifySignerSignature(cmsDer, null);
    if (signature.valid === true) {
      return;
    }
    throw new SigningResponseError(
      `${operation}: the signing service returned a response that is not a ` +
        `verifiable signature (${signature.detail}). Nothing was saved.`,
    );
  }

  const result = await verifyDetachedSignature(signedContent, cmsDer);
  if (result.valid) {
    return;
  }

  const detailStr = result.details.join("\n  ");
  throw new SigningResponseError(
    `${operation}: the signing service's response is not a valid signature over ` +
      `the ${signedContent.length} bytes submitted:\n  ${detailStr}\nNothing was saved.`,
  );
}
