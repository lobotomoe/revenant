/**
 * A test-only signer that produces genuine CMS signatures.
 *
 * The signing workflow refuses a response it cannot verify, so tests can no
 * longer stand filler bytes in for the appliance's answer -- they have to sign
 * for real, over data that only exists at test time (a prepared PDF's ByteRange
 * is computed during the call).
 *
 * The certificate and key are the same committed pair the Rust tests use, so a
 * signature produced here is the signature the other implementations expect.
 */

import { readFileSync } from "node:fs";
import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import type { SigningTransport } from "../src/network/protocol.js";

const OID_SIGNED_DATA = "1.2.840.113549.1.7.2";
const OID_DATA = "1.2.840.113549.1.7.1";
const OID_SHA256 = "2.16.840.1.101.3.4.2.1";
const OID_CONTENT_TYPE = "1.2.840.113549.1.9.3";
const OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4";

function fixture(name: string): Uint8Array {
  return new Uint8Array(
    readFileSync(
      new URL(`../../rust/crates/revenant-sign-core/src/pki/testdata/${name}`, import.meta.url),
    ),
  );
}

const SIGNER_CERT_DER = fixture("test_signer_cert.der");
const SIGNER_KEY_DER = fixture("test_signer_key.der");

let cachedKey: CryptoKey | undefined;

async function signerKey(): Promise<CryptoKey> {
  cachedKey ??= await crypto.subtle.importKey(
    "pkcs8",
    SIGNER_KEY_DER,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return cachedKey;
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

/**
 * Build a detached CMS/PKCS#7 SignedData over `content`.
 *
 * Detached in the same sense as the appliance's output: no eContent, and the
 * digest of the signed bytes travels in the messageDigest signed attribute.
 */
export async function signCmsDetached(content: Uint8Array): Promise<Uint8Array> {
  const cert = pkijs.Certificate.fromBER(toArrayBuffer(SIGNER_CERT_DER));
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", toArrayBuffer(content)));

  const signerInfo = new pkijs.SignerInfo({
    version: 1,
    sid: new pkijs.IssuerAndSerialNumber({
      issuer: cert.issuer,
      serialNumber: cert.serialNumber,
    }),
    digestAlgorithm: new pkijs.AlgorithmIdentifier({ algorithmId: OID_SHA256 }),
    signedAttrs: new pkijs.SignedAndUnsignedAttributes({
      type: 0,
      attributes: [
        new pkijs.Attribute({
          type: OID_CONTENT_TYPE,
          values: [new asn1js.ObjectIdentifier({ value: OID_DATA })],
        }),
        new pkijs.Attribute({
          type: OID_MESSAGE_DIGEST,
          values: [new asn1js.OctetString({ valueHex: toArrayBuffer(digest) })],
        }),
      ],
    }),
  });

  const signedData = new pkijs.SignedData({
    version: 1,
    digestAlgorithms: [new pkijs.AlgorithmIdentifier({ algorithmId: OID_SHA256 })],
    encapContentInfo: new pkijs.EncapsulatedContentInfo({ eContentType: OID_DATA }),
    signerInfos: [signerInfo],
    certificates: [cert],
  });

  await signedData.sign(await signerKey(), 0, "SHA-256");

  const contentInfo = new pkijs.ContentInfo({
    contentType: OID_SIGNED_DATA,
    content: signedData.toSchema(true),
  });
  return new Uint8Array(contentInfo.toSchema().toBER(false));
}

/**
 * A transport that signs whatever it is handed, the way an appliance does.
 *
 * `signHash` signs the digest bytes as content rather than treating them as a
 * pre-computed digest — matching what the production appliance was observed to
 * do, so tests exercise the shape callers actually receive.
 */
export function createSigningTransport(): SigningTransport & { url: string } {
  return {
    url: "https://example.com",
    signHash: vi.fn((hash: Uint8Array) => signCmsDetached(hash)),
    signData: vi.fn((data: Uint8Array) => signCmsDetached(data)),
    signPdfDetached: vi.fn((pdf: Uint8Array) => signCmsDetached(pdf)),
  };
}
