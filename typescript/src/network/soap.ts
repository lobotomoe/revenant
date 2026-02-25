// SPDX-License-Identifier: Apache-2.0
/**
 * SOAP transport and XML parsing for CoSign API.
 *
 * Standard servers use Node's HTTPS. EKENG's ca.gov.am requires
 * TLS 1.0 + RC4 via node-forge; callers pass legacy TLS config for that.
 */

import { DEFAULT_TIMEOUT_HTTP_POST } from "../constants.js";
import { httpPost } from "./transport.js";

export {
  buildEnumCertificatesEnvelope,
  buildSignEnvelope,
  buildSignHashEnvelope,
  buildVerifyEnvelope,
  SIGNATURE_TYPE_CMS,
  SIGNATURE_TYPE_ENUM_CERTS,
  SIGNATURE_TYPE_FIELD_VERIFY,
  SIGNATURE_TYPE_XMLDSIG,
  xmlEscape,
} from "./soap-envelope.js";

export {
  parseEnumCertificatesResponse,
  parseSignResponse,
  parseVerifyResponse,
  type ServerVerifyResult,
} from "./soap-parsers.js";

export async function sendSoap(
  url: string,
  envelope: string,
  action: string = "DssSign",
  timeout: number = DEFAULT_TIMEOUT_HTTP_POST,
): Promise<string> {
  const headers = {
    "Content-Type": "text/xml; charset=utf-8",
    SOAPAction: `http://arx.com/SAPIWS/DSS/1.0/${action}`,
  };
  const body = new TextEncoder().encode(envelope);
  const response = await httpPost(url, body, { headers, timeout });
  return new TextDecoder("utf-8").decode(response);
}
