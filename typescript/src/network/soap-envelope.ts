// SPDX-License-Identifier: Apache-2.0
/** SOAP envelope builders for CoSign API requests. */

export const SIGNATURE_TYPE_CMS = "urn:ietf:rfc:3369";
export const SIGNATURE_TYPE_XMLDSIG = "urn:ietf:rfc:3275";
export const SIGNATURE_TYPE_FIELD_VERIFY = "http://arx.com/SAPIWS/DSS/1.0/signature-field-verify";
export const SIGNATURE_TYPE_ENUM_CERTS = "http://arx.com/SAPIWS/DSS/1.0/enum-certificates";

export function xmlEscape(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

function buildSoapEnvelope(
  username: string,
  password: string,
  sigType: string,
  inputDocuments: string,
  extraNamespaces: string = "",
): string {
  const safeUser = xmlEscape(username);
  const safePass = xmlEscape(password);
  const safeType = xmlEscape(sigType);
  const nsPart = extraNamespaces ? `\n               ${extraNamespaces}` : "";
  return `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:arx="http://arx.com/SAPIWS/DSS/1.0"${nsPart}>
  <soap:Body>
    <DssSign xmlns="http://arx.com/SAPIWS/DSS/1.0/">
      <SignRequest xmlns="urn:oasis:names:tc:dss:1.0:core:schema">
        <OptionalInputs>
          <ClaimedIdentity>
            <Name>${safeUser}</Name>
            <SupportingInfo>
              <arx:LogonPassword>${safePass}</arx:LogonPassword>
            </SupportingInfo>
          </ClaimedIdentity>
          <SignatureType>${safeType}</SignatureType>
        </OptionalInputs>
        <InputDocuments>
          ${inputDocuments}
        </InputDocuments>
      </SignRequest>
    </DssSign>
  </soap:Body>
</soap:Envelope>`;
}

export function buildSignEnvelope(
  username: string,
  password: string,
  sigType: string,
  dataB64: string,
): string {
  const inputDocs =
    `<Document><Base64Data MimeType="application/pdf">` +
    `${xmlEscape(dataB64)}</Base64Data></Document>`;
  return buildSoapEnvelope(username, password, sigType, inputDocs);
}

export function buildSignHashEnvelope(
  username: string,
  password: string,
  sigType: string,
  hashB64: string,
): string {
  const inputDocs =
    `<DocumentHash>` +
    `<ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>` +
    `<ds:DigestValue>${xmlEscape(hashB64)}</ds:DigestValue>` +
    `</DocumentHash>`;
  const extraNs = 'xmlns:ds="http://www.w3.org/2000/09/xmldsig#"';
  return buildSoapEnvelope(username, password, sigType, inputDocs, extraNs);
}

export function buildEnumCertificatesEnvelope(username: string, password: string): string {
  return buildSoapEnvelope(username, password, SIGNATURE_TYPE_ENUM_CERTS, "");
}

export function buildVerifyEnvelope(
  pdfB64: string,
  sigType: string = SIGNATURE_TYPE_FIELD_VERIFY,
): string {
  const safeType = xmlEscape(sigType);
  return `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:arx="http://arx.com/SAPIWS/DSS/1.0">
  <soap:Body>
    <DssVerify xmlns="http://arx.com/SAPIWS/DSS/1.0/">
      <VerifyRequest xmlns="urn:oasis:names:tc:dss:1.0:core:schema">
        <OptionalInputs>
          <SignatureType>${safeType}</SignatureType>
        </OptionalInputs>
        <InputDocuments>
          <Document><Base64Data MimeType="application/pdf">${xmlEscape(pdfB64)}</Base64Data></Document>
        </InputDocuments>
      </VerifyRequest>
    </DssVerify>
  </soap:Body>
</soap:Envelope>`;
}
