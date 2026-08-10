// SPDX-License-Identifier: Apache-2.0
/** Regression tests for CMS signer-certificate selection during chain validation. */

import { readFileSync } from "node:fs";

import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { validateChain } from "../src/core/chain.js";
import { findSignerCertificate } from "../src/core/cms-certificates.js";
import type { TrustStore } from "../src/core/tsl.js";

/** Every URL chain validation tried to open, in order. */
const { attemptedUrls } = vi.hoisted(() => ({ attemptedUrls: [] as string[] }));

vi.mock("../src/network/transport.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/network/transport.js")>();
  return {
    ...actual,
    httpGet: (url: string): never => {
      attemptedUrls.push(url);
      // Refusing the way an unreachable host would: a caller that swallows the
      // failure still leaves the attempt recorded above.
      throw new Error(`network access is not allowed in this test: ${url}`);
    },
  };
});

function fixture(name: string): Uint8Array {
  return new Uint8Array(
    readFileSync(
      new URL(`../../rust/crates/revenant-sign-core/src/pki/testdata/${name}`, import.meta.url),
    ),
  );
}

function certificateFixture(name: string): pkijs.Certificate {
  const parsed = asn1js.fromBER(fixture(name));
  if (parsed.offset === -1) throw new Error(`Could not parse ${name}`);
  return new pkijs.Certificate({ schema: parsed.result });
}

function certificateSki(cert: pkijs.Certificate): Uint8Array {
  const extension = cert.extensions?.find((candidate) => candidate.extnID === "2.5.29.14");
  if (!extension) throw new Error("Certificate fixture has no Subject Key Identifier");
  const parsed = asn1js.fromBER(extension.extnValue.valueBlock.valueHexView);
  if (parsed.offset === -1 || !(parsed.result instanceof asn1js.OctetString)) {
    throw new Error("Certificate fixture has a malformed Subject Key Identifier");
  }
  return new Uint8Array(parsed.result.valueBlock.valueHexView);
}

beforeEach(() => {
  attemptedUrls.length = 0;
});

describe("validateChain", () => {
  it("selects the leaf by SignerInfo instead of certificate SET order", async () => {
    const anchor = {
      subjectName: "CN=Test Root CA",
      serviceName: "TestRootCA",
      serviceType: "CA/QC",
      status: "granted",
      certDer: fixture("root.der"),
    };
    const store: TrustStore = {
      anchors: [anchor],
      caAnchors: [anchor],
      schemeOperator: "Test",
      tslUrl: "https://example.com",
      fetchedAt: Date.now(),
    };

    const result = await validateChain(fixture("cms_chain3.der"), store);
    expect(result.chainValid).toBe(true);
    expect(result.trustAnchor).toBe("TestRootCA");
    expect(result.chainDepth).toBe(3);
    expect(result.details.some((detail) => detail.includes("signer cert: CN=Test Signer"))).toBe(
      true,
    );
    expect(result.details.some((detail) => detail.includes("signer cert: CN=Test Root CA"))).toBe(
      false,
    );
  });

  it("never follows the AIA URLs printed in a certificate", async () => {
    // The URLs live in the document being verified, so following them would let
    // whoever wrote it pick hosts for this machine to contact. This fixture's
    // issuer is reachable only through its AIA URL, and the anchor below is
    // unrelated to it, so the issuer cannot come from the pool either.
    const anchor = {
      subjectName: "CN=Test Root CA",
      serviceName: "TestRootCA",
      serviceType: "CA/QC",
      status: "granted",
      certDer: fixture("root.der"),
    };
    const store: TrustStore = {
      anchors: [anchor],
      caAnchors: [anchor],
      schemeOperator: "Test",
      tslUrl: "https://example.com",
      fetchedAt: Date.now(),
    };

    const result = await validateChain(fixture("cms_leaf_aia.der"), store);

    expect(attemptedUrls).toEqual([]);
    expect(result.chainDepth).toBe(1);
  });
});

describe("findSignerCertificate", () => {
  it("matches primitive and constructed SubjectKeyIdentifier forms", () => {
    const cert = certificateFixture("leaf_direct.der");
    const ski = certificateSki(cert);
    const identifiers: asn1js.BaseBlock[] = [
      new asn1js.Primitive({
        idBlock: { tagClass: 3, tagNumber: 0 },
        valueHex: ski,
      }),
      new asn1js.Constructed({
        idBlock: { tagClass: 3, tagNumber: 0 },
        value: [new asn1js.OctetString({ valueHex: ski })],
      }),
    ];

    for (const sid of identifiers) {
      const signerInfo = new pkijs.SignerInfo({ sid });
      const signedData = new pkijs.SignedData({
        certificates: [cert],
        signerInfos: [signerInfo],
      });
      expect(findSignerCertificate(signedData, signerInfo)).toBe(cert);
    }
  });
});
