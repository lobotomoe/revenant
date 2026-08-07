// SPDX-License-Identifier: Apache-2.0
/** Certificate selection helpers for CMS SignedData values. */

import * as asn1js from "asn1js";
import * as pkijs from "pkijs";

const OID_SUBJECT_KEY_IDENTIFIER = "2.5.29.14";

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

function subjectKeyIdentifier(cert: pkijs.Certificate): Uint8Array | null {
  const extension = cert.extensions?.find(
    (candidate) => candidate.extnID === OID_SUBJECT_KEY_IDENTIFIER,
  );
  if (!extension) return null;

  const parsed = asn1js.fromBER(extension.extnValue.valueBlock.valueHexView);
  if (parsed.offset === -1 || !(parsed.result instanceof asn1js.OctetString)) return null;
  return new Uint8Array(parsed.result.valueBlock.valueHexView);
}

function signerKeyIdentifier(sid: asn1js.BaseBlock): Uint8Array | null {
  if (sid instanceof asn1js.Primitive) {
    return new Uint8Array(sid.valueBlock.valueHexView);
  }
  if (!(sid instanceof asn1js.Constructed)) return null;

  const parts: Uint8Array[] = [];
  for (const block of sid.valueBlock.value) {
    if (!(block instanceof asn1js.OctetString)) return null;
    parts.push(new Uint8Array(block.getValue()));
  }
  const result = new Uint8Array(parts.reduce((length, part) => length + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

/** Return all embedded X.509 certificates, ignoring other certificate choices. */
export function x509Certificates(signedData: pkijs.SignedData): pkijs.Certificate[] {
  return (signedData.certificates ?? []).filter(
    (certificate): certificate is pkijs.Certificate => certificate instanceof pkijs.Certificate,
  );
}

/**
 * Find exactly one certificate identified by a CMS SignerInfo.sid.
 *
 * CMS certificates are a SET OF, so their encoded order must never be used to
 * identify the signer. Zero or multiple matches are deliberately unverifiable.
 */
export function findSignerCertificate(
  signedData: pkijs.SignedData,
  signerInfo: pkijs.SignerInfo | undefined = signedData.signerInfos[0],
): pkijs.Certificate | null {
  if (!signerInfo) return null;

  const matches = x509Certificates(signedData).filter((certificate) => {
    if (signerInfo.sid instanceof pkijs.IssuerAndSerialNumber) {
      return (
        certificate.issuer.isEqual(signerInfo.sid.issuer) &&
        certificate.serialNumber.isEqual(signerInfo.sid.serialNumber)
      );
    }

    const sid = signerKeyIdentifier(signerInfo.sid);
    const ski = subjectKeyIdentifier(certificate);
    return sid !== null && ski !== null && bytesEqual(sid, ski);
  });

  return matches.length === 1 ? (matches[0] ?? null) : null;
}
