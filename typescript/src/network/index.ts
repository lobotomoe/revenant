// SPDX-License-Identifier: Apache-2.0
/** Network layer re-exports. */

export { pingServer } from "./discovery.js";
export { legacyRequest } from "./legacy-tls.js";
export type { SigningTransport } from "./protocol.js";
export {
  buildEnumCertificatesEnvelope,
  buildSignEnvelope,
  buildSignHashEnvelope,
  buildVerifyEnvelope,
  parseEnumCertificatesResponse,
  parseSignResponse,
  parseVerifyResponse,
  type ServerVerifyResult,
  SIGNATURE_TYPE_CMS,
  SIGNATURE_TYPE_ENUM_CERTS,
  SIGNATURE_TYPE_FIELD_VERIFY,
  SIGNATURE_TYPE_XMLDSIG,
  sendSoap,
  xmlEscape,
} from "./soap.js";
export {
  enumCertificates,
  SoapSigningTransport,
  verifyPdfServer,
} from "./soap-transport.js";
export {
  getHostTlsInfo,
  httpGet,
  httpPost,
  registerHostTls,
} from "./transport.js";
