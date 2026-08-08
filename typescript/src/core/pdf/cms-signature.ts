// SPDX-License-Identifier: Apache-2.0
/** Cryptographic verification of CMS SignerInfo signatures. */

import { createHash } from "node:crypto";

import * as asn1js from "asn1js";
import * as pkijs from "pkijs";

import { toArrayBuffer } from "../../utils.js";
import { findSignerCertificate } from "../cms-certificates.js";
import { resolveHashAlgo } from "./cms-info.js";

const OID_SIGNED_DATA = "1.2.840.113549.1.7.2";
const OID_CONTENT_TYPE = "1.2.840.113549.1.9.3";
const OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4";
const OID_SIGNING_CERTIFICATE = "1.2.840.113549.1.9.16.2.12";
const OID_SIGNING_CERTIFICATE_V2 = "1.2.840.113549.1.9.16.2.47";
const OID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1";

const RSA_SIGNATURE_DIGESTS: ReadonlyMap<string, string | null> = new Map([
  ["1.2.840.113549.1.1.1", null], // rsaEncryption: digestAlgorithm is authoritative
  ["1.2.840.113549.1.1.5", "SHA-1"],
  ["1.2.840.113549.1.1.11", "SHA-256"],
  ["1.2.840.113549.1.1.12", "SHA-384"],
  ["1.2.840.113549.1.1.13", "SHA-512"],
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
  /** Whether a matching signed ESS attribute binds the exact signer certificate. */
  signerCertificateBound: boolean;
  /**
   * True when the CMS carries no signed attributes, so the signature was
   * verified over the content itself and no separate digest exists to compare.
   */
  coversContent: boolean;
  /** Stable diagnostic line for VerificationResult.details. */
  detail: string;
}

/** Diagnostics are surfaced to users through VerificationResult.details. */
const MAX_REASON_LENGTH = 160;

/** Render a thrown value compactly enough to sit in a user-facing detail line. */
export function describeError(error: unknown): string {
  const name = error instanceof Error ? error.name : "Error";
  const raw = error instanceof Error ? error.message : String(error);
  const message = raw.trim().replace(/\s+/g, " ");
  if (message.length === 0) return name;
  const trimmed =
    message.length > MAX_REASON_LENGTH ? `${message.slice(0, MAX_REASON_LENGTH - 3)}...` : message;
  return `${name}: ${trimmed}`;
}

/** DER SET OF ordering: components sort by their complete encodings (X.690 11.6). */
function compareDerElements(a: Uint8Array, b: Uint8Array): number {
  const shared = Math.min(a.length, b.length);
  for (let i = 0; i < shared; i++) {
    const left = a[i] ?? 0;
    const right = b[i] ?? 0;
    if (left !== right) return left - right;
  }
  return a.length - b.length;
}

function derLength(size: number): Uint8Array {
  if (size < 0x80) return new Uint8Array([size]);
  const octets: number[] = [];
  for (let rest = size; rest > 0; rest = Math.floor(rest / 256)) octets.unshift(rest % 256);
  return new Uint8Array([0x80 | octets.length, ...octets]);
}

/**
 * Re-encode the signed attributes as a canonical DER SET OF.
 *
 * RFC 5652 section 5.4 defines the signature input this way, and a conforming
 * signer transmits exactly these bytes. Signers that emit another ordering sign
 * what they transmitted instead, so both encodings are tried; they encode the
 * same parsed attributes, which validateSignedAttributes has already checked.
 */
function canonicalSignedAttributes(signedAttrs: pkijs.SignedAndUnsignedAttributes): Uint8Array {
  const members = signedAttrs.attributes.map(
    (attribute) => new Uint8Array(attribute.toSchema().toBER(false)),
  );
  members.sort(compareDerElements);
  const body = new Uint8Array(members.reduce((total, member) => total + member.length, 0));
  let offset = 0;
  for (const member of members) {
    body.set(member, offset);
    offset += member.length;
  }
  const header = derLength(body.length);
  const encoded = new Uint8Array(1 + header.length + body.length);
  encoded[0] = 0x31; // universal SET OF, as required for the signature input
  encoded.set(header, 1);
  encoded.set(body, 1 + header.length);
  return encoded;
}

function unverifiable(reason: string): SignatureVerification {
  return {
    valid: null,
    signerCertificateBound: false,
    coversContent: false,
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

interface EssCertHash {
  algorithm: string;
  value: Uint8Array;
}

type SigningCertificateBinding = "absent" | "match" | "mismatch" | "unparsable";

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

function parseEssCertHash(value: asn1js.BaseBlock, isV2: boolean): EssCertHash | null {
  if (!(value instanceof asn1js.Sequence)) return null;
  const certs = value.valueBlock.value[0];
  if (!(certs instanceof asn1js.Sequence)) return null;
  const firstCertId = certs.valueBlock.value[0];
  if (!(firstCertId instanceof asn1js.Sequence)) return null;

  const fields = firstCertId.valueBlock.value;
  let algorithm = "SHA-1";
  let hashIndex = 0;
  if (isV2) {
    algorithm = "SHA-256";
    const optionalAlgorithm = fields[0];
    if (optionalAlgorithm instanceof asn1js.Sequence) {
      const algorithmIdentifier = new pkijs.AlgorithmIdentifier({ schema: optionalAlgorithm });
      const resolved = resolveHashAlgo(algorithmIdentifier.algorithmId);
      if (!resolved) return null;
      algorithm = resolved;
      hashIndex = 1;
    }
  }

  const certHash = fields[hashIndex];
  const expectedLength = DIGEST_LENGTHS.get(algorithm);
  if (
    !(certHash instanceof asn1js.OctetString) ||
    expectedLength === undefined ||
    certHash.valueBlock.valueHexView.byteLength !== expectedLength
  ) {
    return null;
  }
  return {
    algorithm,
    value: new Uint8Array(certHash.valueBlock.valueHexView),
  };
}

function signingCertificateBinding(
  signerInfo: pkijs.SignerInfo,
  signerCertificate: pkijs.Certificate,
): SigningCertificateBinding {
  const bindingAttrs = (signerInfo.signedAttrs?.attributes ?? []).filter(
    (attribute) =>
      attribute.type === OID_SIGNING_CERTIFICATE || attribute.type === OID_SIGNING_CERTIFICATE_V2,
  );
  if (bindingAttrs.length === 0) return "absent";
  if (new Set(bindingAttrs.map((attribute) => attribute.type)).size !== bindingAttrs.length) {
    return "unparsable";
  }

  let certificateDer: Uint8Array;
  try {
    certificateDer = new Uint8Array(signerCertificate.toSchema().toBER(false));
  } catch {
    return "unparsable";
  }
  let unparsable = false;
  for (const bindingAttr of bindingAttrs) {
    try {
      if (bindingAttr.values.length !== 1) {
        unparsable = true;
        continue;
      }
      const bindingValue = bindingAttr.values[0];
      if (!bindingValue) {
        unparsable = true;
        continue;
      }
      const parsed = parseEssCertHash(
        bindingValue,
        bindingAttr.type === OID_SIGNING_CERTIFICATE_V2,
      );
      if (!parsed) {
        unparsable = true;
        continue;
      }

      const nodeAlgorithm = parsed.algorithm.toLowerCase().replace("-", "");
      const actualHash = new Uint8Array(createHash(nodeAlgorithm).update(certificateDer).digest());
      if (!bytesEqual(actualHash, parsed.value)) return "mismatch";
    } catch {
      unparsable = true;
    }
  }

  return unparsable ? "unparsable" : "match";
}

/**
 * Verify the first CMS signer's signature with its embedded certificate.
 *
 * Certificate-chain trust is deliberately separate. Unsupported or malformed
 * inputs fail closed and can never produce a valid overall verification result.
 */
export async function verifySignerSignature(
  cmsDer: Uint8Array,
  content: Uint8Array | null = null,
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
    const signerCertificate = findSignerCertificate(signedData, signerInfo);
    if (signerCertificate === null) {
      return unverifiable("signer certificate not embedded or ambiguous");
    }

    const digestAlgorithm = resolveHashAlgo(signerInfo.digestAlgorithm.algorithmId);
    if (!digestAlgorithm) return unverifiable("unrecognized digest algorithm");

    const signatureAlgorithm = signerInfo.signatureAlgorithm.algorithmId;
    if (!RSA_SIGNATURE_DIGESTS.has(signatureAlgorithm)) {
      return unverifiable("non-RSA signer is unsupported");
    }
    const signatureDigest = RSA_SIGNATURE_DIGESTS.get(signatureAlgorithm);
    if (signatureDigest !== null && signatureDigest !== digestAlgorithm) {
      return unverifiable("signatureAlgorithm conflicts with digestAlgorithm");
    }
    if (signerCertificate.subjectPublicKeyInfo.algorithm.algorithmId !== OID_RSA_ENCRYPTION) {
      return unverifiable("RSA signatureAlgorithm used with a non-RSA signer key");
    }

    // RFC 5652 section 5.4: the signature covers the DER-encoded signed
    // attributes when they are present, and the content itself when they are
    // not. The branch is taken strictly on presence, so a CMS that carries
    // signed attributes can never fall back to the content path.
    const signedAttrs = signerInfo.signedAttrs;
    let signatureInputs: ArrayBuffer[];
    if (signedAttrs) {
      const attrError = validateSignedAttributes(signedData, signerInfo, digestAlgorithm);
      if (attrError) return unverifiable(attrError);
      if (signedAttrs.encodedValue.byteLength === 0) {
        return unverifiable("cannot encode signed attributes");
      }
      // The as-transmitted encoding first, then the canonical DER re-encoding.
      const transmitted = new Uint8Array(signedAttrs.encodedValue);
      const canonical = canonicalSignedAttributes(signedAttrs);
      signatureInputs = bytesEqual(transmitted, canonical)
        ? [signedAttrs.encodedValue]
        : [signedAttrs.encodedValue, toArrayBuffer(canonical)];
    } else {
      const eContent = signedData.encapContentInfo.eContent;
      const body = eContent ? new Uint8Array(eContent.valueBlock.valueHexView) : content;
      if (!body) return unverifiable("no signed attributes and no content to verify");
      signatureInputs = [toArrayBuffer(body)];
    }

    // SignedData.verify() performs its own signer-certificate lookup. For an
    // SKI SignerIdentifier, PKIjs 3.4.0 hashes SubjectPublicKey instead of
    // matching the certificate's Subject Key Identifier extension, so it can
    // verify with a different certificate than findSignerCertificate selected.
    // Invoke the crypto primitive directly with the already selected key.
    const crypto = pkijs.getCrypto(true);
    let verified = false;
    for (const signatureInput of signatureInputs) {
      verified = await crypto.verifyWithPublicKey(
        signatureInput,
        signerInfo.signature,
        signerCertificate.subjectPublicKeyInfo,
        signerInfo.signatureAlgorithm,
        digestAlgorithm,
      );
      if (verified) break;
    }
    if (!verified) {
      return {
        valid: false,
        signerCertificateBound: false,
        coversContent: !signedAttrs,
        detail: "Signature INVALID -- does not verify against the signer certificate",
      };
    }

    // An ESS binding lives in the signed attributes, so without them there is
    // nothing to bind the certificate beyond the signature itself.
    let binding: SigningCertificateBinding = "absent";
    if (signedAttrs) {
      binding = signingCertificateBinding(signerInfo, signerCertificate);
      if (binding === "mismatch") {
        return unverifiable("signingCertificate attribute names a different certificate");
      }
      if (binding === "unparsable") {
        return unverifiable("signingCertificate attribute could not be parsed");
      }
    }
    return {
      valid: true,
      signerCertificateBound: binding === "match",
      coversContent: !signedAttrs,
      detail: "Signature OK -- signer signature verifies",
    };
  } catch (error) {
    // CMS is untrusted input and this API promises a verdict rather than a
    // thrown parser error, so it fails closed. The reason names the underlying
    // failure: an opaque "check failed" once masked a certificate-parsing
    // incompatibility that silently invalidated genuine signatures, and a
    // diagnostic nobody can read is how that reaches production unnoticed.
    return unverifiable(`CMS signature check failed -- ${describeError(error)}`);
  }
}
