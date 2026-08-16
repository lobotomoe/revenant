// SPDX-License-Identifier: Apache-2.0
/** Regression tests for what may count as long-term-validation evidence. */

import { readFileSync } from "node:fs";

import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import { describe, expect, it } from "vitest";

import { checkLtvStatus } from "../src/core/pdf/ltv.js";

const OID_SIGNED_DATA = "1.2.840.113549.1.7.2";
const OID_REVOCATION_INFO_ARCHIVAL = "1.2.840.113583.1.1.8";

/** RevocationInfoArchival ::= SEQUENCE { ocsp [1] SEQUENCE OF ... } */
function archivalWithOcsp(): asn1js.Sequence {
  return new asn1js.Sequence({
    value: [
      new asn1js.Constructed({
        idBlock: { tagClass: 3, tagNumber: 1 },
        value: [new asn1js.Sequence({ value: [new asn1js.Integer({ value: 1 })] })],
      }),
    ],
  });
}

/**
 * Put a RevocationInfoArchival attribute on a real CMS, signed side or not.
 *
 * The signature is not recomputed: nothing here verifies it, and an attacker
 * stapling an unsigned attribute onto a finished document does not recompute it
 * either -- that is the whole point of the attribute being unsigned.
 */
function cmsWithArchival(where: "signed" | "unsigned", value: asn1js.BaseBlock): Uint8Array {
  const raw = readFileSync(
    new URL(
      "../../rust/crates/revenant-sign-core/src/pki/testdata/cms_leaf_direct.der",
      import.meta.url,
    ),
  );
  const buf = new ArrayBuffer(raw.byteLength);
  new Uint8Array(buf).set(raw);
  const asn1 = asn1js.fromBER(buf);
  const contentInfo = new pkijs.ContentInfo({ schema: asn1.result });
  const signedData = new pkijs.SignedData({ schema: contentInfo.content });

  const attributes = new pkijs.SignedAndUnsignedAttributes({
    type: where === "signed" ? 0 : 1,
    attributes: [new pkijs.Attribute({ type: OID_REVOCATION_INFO_ARCHIVAL, values: [value] })],
  });
  const signer = signedData.signerInfos[0];
  if (!signer) throw new Error("fixture has no SignerInfo");
  if (where === "signed") {
    signer.signedAttrs = attributes;
  } else {
    signer.unsignedAttrs = attributes;
  }

  const rebuilt = new pkijs.ContentInfo({
    contentType: OID_SIGNED_DATA,
    content: signedData.toSchema(true),
  });
  return new Uint8Array(rebuilt.toSchema().toBER(false));
}

describe("checkLtvStatus", () => {
  it("counts revocation material the signer signed", () => {
    const status = checkLtvStatus(cmsWithArchival("signed", archivalWithOcsp()));

    expect(status.ltvEnabled).toBe(true);
    expect(status.hasRevocationArchival).toBe(true);
    expect(status.hasOcsp).toBe(true);
  });

  it("does not treat an unsigned attribute as evidence", () => {
    // The reported attack: unsigned attributes are outside the signature, so
    // anyone can staple one onto a finished document without breaking it.
    const status = checkLtvStatus(cmsWithArchival("unsigned", archivalWithOcsp()));

    expect(status.ltvEnabled).toBe(false);
    expect(status.hasUnauthenticatedMaterial).toBe(true);
    expect(status.details.some((detail) => detail.includes("outside the signature"))).toBe(true);
  });

  it("does not take the OID's word for what the attribute holds", () => {
    const bogus = new asn1js.OctetString({
      valueHex: new TextEncoder().encode("bogus-not-ocsp-or-crl"),
    });

    const status = checkLtvStatus(cmsWithArchival("signed", bogus));

    expect(status.ltvEnabled).toBe(false);
    expect(status.hasOcsp).toBe(false);
    expect(status.details.some((detail) => detail.includes("malformed"))).toBe(true);
  });
});
