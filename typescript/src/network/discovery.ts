// SPDX-License-Identifier: Apache-2.0
/**
 * Network-level server discovery for CoSign setup.
 *
 * Provides server ping (WSDL check).
 */

import { DEFAULT_TIMEOUT_HTTP_GET } from "../constants.js";
import { RevenantError, TLSError } from "../errors.js";
import { httpGet } from "./transport.js";

export async function pingServer(
  url: string,
  timeout: number = DEFAULT_TIMEOUT_HTTP_GET,
): Promise<{ ok: boolean; info: string }> {
  let wsdlUrl = url.replace(/\/+$/, "");
  if (!wsdlUrl.includes("?")) {
    wsdlUrl += "?WSDL";
  }

  let raw: Uint8Array;
  try {
    raw = await httpGet(wsdlUrl, { timeout });
  } catch (exc) {
    if (exc instanceof TLSError) {
      return { ok: false, info: exc.message };
    }
    if (exc instanceof RevenantError) {
      return { ok: false, info: `Connection failed: ${exc.message}` };
    }
    throw exc;
  }

  const body = new TextDecoder("utf-8").decode(raw);

  if (body.includes("DssSign") && body.includes("SAPIWS")) {
    return { ok: true, info: "CoSign DSS endpoint confirmed" };
  }

  if (body.includes("<wsdl:") || body.includes("<definitions")) {
    return { ok: true, info: "WSDL found (may not be CoSign)" };
  }

  return { ok: false, info: "Not a recognized CoSign endpoint" };
}
