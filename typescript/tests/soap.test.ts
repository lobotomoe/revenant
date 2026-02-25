/**
 * Tests for SOAP envelope building and response parsing.
 */

import { describe, expect, it } from "vitest";
import { AuthError, RevenantError, ServerError } from "../src/errors.js";
import {
  buildEnumCertificatesEnvelope,
  buildSignEnvelope,
  buildSignHashEnvelope,
  buildVerifyEnvelope,
  parseEnumCertificatesResponse,
  parseSignResponse,
  parseVerifyResponse,
  SIGNATURE_TYPE_CMS,
  SIGNATURE_TYPE_ENUM_CERTS,
  SIGNATURE_TYPE_FIELD_VERIFY,
  SIGNATURE_TYPE_XMLDSIG,
  xmlEscape,
} from "../src/network/soap.js";

// -- Helpers ------------------------------------------------------------------

/** Build a base64 string of at least `n` bytes to exceed MIN_SIGNATURE_B64_LEN. */
function makeLongB64(byteCount: number): string {
  const bytes = new Uint8Array(byteCount);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = i & 0xff;
  }
  return btoa(String.fromCharCode(...bytes));
}

function wrapSoapSignResponse(body: string): string {
  return `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <dss:SignResponse xmlns:dss="urn:oasis:names:tc:dss:1.0:core:schema">
      ${body}
    </dss:SignResponse>
  </soap:Body>
</soap:Envelope>`;
}

function wrapSoapEnumCertsResponse(body: string): string {
  return `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <dss:SignResponse xmlns:dss="urn:oasis:names:tc:dss:1.0:core:schema">
      ${body}
    </dss:SignResponse>
  </soap:Body>
</soap:Envelope>`;
}

function wrapSoapVerifyResponse(body: string): string {
  return `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <dss:VerifyResponse xmlns:dss="urn:oasis:names:tc:dss:1.0:core:schema">
      ${body}
    </dss:VerifyResponse>
  </soap:Body>
</soap:Envelope>`;
}

const SUCCESS_MAJOR = "urn:oasis:names:tc:dss:1.0:resultmajor:Success";
const FAILURE_MAJOR = "urn:oasis:names:tc:dss:1.0:resultmajor:RequesterError";

// -- Signature type constants -------------------------------------------------

describe("signature type constants", () => {
  it("has expected values", () => {
    expect(SIGNATURE_TYPE_CMS).toBeTruthy();
    expect(SIGNATURE_TYPE_XMLDSIG).toBeTruthy();
    expect(SIGNATURE_TYPE_ENUM_CERTS).toBeTruthy();
    expect(SIGNATURE_TYPE_FIELD_VERIFY).toBeTruthy();
  });
});

// -- xmlEscape ----------------------------------------------------------------

describe("xmlEscape", () => {
  it("escapes XML special characters", () => {
    expect(xmlEscape("a<b>c&d")).toBe("a&lt;b&gt;c&amp;d");
    expect(xmlEscape('"hello"')).toBe("&quot;hello&quot;");
    expect(xmlEscape("it's")).toBe("it&apos;s");
  });

  it("passes through safe strings", () => {
    expect(xmlEscape("hello world")).toBe("hello world");
  });

  it("handles empty string", () => {
    expect(xmlEscape("")).toBe("");
  });

  it("returns normal strings unchanged", () => {
    expect(xmlEscape("abc123")).toBe("abc123");
    expect(xmlEscape("test user")).toBe("test user");
  });
});

// -- buildSignEnvelope --------------------------------------------------------

describe("buildSignEnvelope", () => {
  it("contains username and base64 data", () => {
    const data = new Uint8Array([1, 2, 3]);
    const dataB64 = btoa(String.fromCharCode(...data));
    const envelope = buildSignEnvelope("testuser", "testpass", SIGNATURE_TYPE_CMS, dataB64);
    expect(envelope).toContain("testuser");
    expect(envelope).toContain("testpass");
    expect(envelope).toContain("DssSign");
  });
});

// -- buildSignHashEnvelope ----------------------------------------------------

describe("buildSignHashEnvelope", () => {
  it("contains hash data", () => {
    const hash = new Uint8Array(20);
    const hashB64 = btoa(String.fromCharCode(...hash));
    const envelope = buildSignHashEnvelope("user", "pass", SIGNATURE_TYPE_CMS, hashB64);
    expect(envelope).toContain("user");
    expect(envelope).toContain("pass");
    expect(envelope).toContain("DigestValue");
  });
});

// -- buildVerifyEnvelope ------------------------------------------------------

describe("buildVerifyEnvelope", () => {
  it("produces valid XML", () => {
    const pdf = new TextEncoder().encode("%PDF-1.7 test");
    const pdfB64 = btoa(String.fromCharCode(...pdf));
    const envelope = buildVerifyEnvelope(pdfB64);
    expect(envelope).toContain("DssVerify");
    expect(envelope).toContain(pdfB64);
  });
});

// -- buildEnumCertificatesEnvelope --------------------------------------------

describe("buildEnumCertificatesEnvelope", () => {
  it("contains username and password", () => {
    const envelope = buildEnumCertificatesEnvelope("myuser", "mypass");
    expect(envelope).toContain("myuser");
    expect(envelope).toContain("mypass");
  });

  it("contains enum-certificates signature type", () => {
    const envelope = buildEnumCertificatesEnvelope("u", "p");
    expect(envelope).toContain(SIGNATURE_TYPE_ENUM_CERTS);
  });
});

// -- parseSignResponse --------------------------------------------------------

describe("parseSignResponse", () => {
  it("extracts base64 signature from success response", () => {
    const sigB64 = makeLongB64(64);
    const xml = wrapSoapSignResponse(`
      <dss:Result>
        <dss:ResultMajor>${SUCCESS_MAJOR}</dss:ResultMajor>
      </dss:Result>
      <dss:SignatureObject>
        <dss:Base64Signature>${sigB64}</dss:Base64Signature>
      </dss:SignatureObject>`);

    const result = parseSignResponse(xml);
    expect(result.length).toBe(64);
    expect(result[0]).toBe(0);
    expect(result[1]).toBe(1);
  });

  it("extracts signature from Base64Data tag", () => {
    const sigB64 = makeLongB64(64);
    const xml = wrapSoapSignResponse(`
      <dss:Result>
        <dss:ResultMajor>${SUCCESS_MAJOR}</dss:ResultMajor>
      </dss:Result>
      <dss:SignatureObject>
        <dss:Base64Data MimeType="application/pkcs7-signature">${sigB64}</dss:Base64Data>
      </dss:SignatureObject>`);

    const result = parseSignResponse(xml);
    expect(result.length).toBe(64);
  });

  it("throws AuthError when ResultMinor ends with :AuthenticationError", () => {
    const xml = wrapSoapSignResponse(`
      <dss:Result>
        <dss:ResultMajor>${FAILURE_MAJOR}</dss:ResultMajor>
        <dss:ResultMinor>urn:oasis:names:tc:dss:1.0:resultminor:AuthenticationError</dss:ResultMinor>
        <dss:ResultMessage>Bad credentials</dss:ResultMessage>
      </dss:Result>`);

    expect(() => parseSignResponse(xml)).toThrow(AuthError);
  });

  it("throws ServerError for non-success without auth error", () => {
    const xml = wrapSoapSignResponse(`
      <dss:Result>
        <dss:ResultMajor>${FAILURE_MAJOR}</dss:ResultMajor>
        <dss:ResultMinor>urn:oasis:names:tc:dss:1.0:resultminor:GeneralError</dss:ResultMinor>
        <dss:ResultMessage>Something went wrong</dss:ResultMessage>
      </dss:Result>`);

    expect(() => parseSignResponse(xml)).toThrow(ServerError);
    expect(() => parseSignResponse(xml)).toThrow(/Something went wrong/);
  });

  it("throws ServerError when success but no signature data", () => {
    const xml = wrapSoapSignResponse(`
      <dss:Result>
        <dss:ResultMajor>${SUCCESS_MAJOR}</dss:ResultMajor>
      </dss:Result>`);

    expect(() => parseSignResponse(xml)).toThrow(ServerError);
    expect(() => parseSignResponse(xml)).toThrow(/no signature data/);
  });

  it("throws RevenantError for malformed XML", () => {
    expect(() => parseSignResponse("<<<not xml>>>")).toThrow(RevenantError);
  });

  it("throws RevenantError for completely empty input", () => {
    expect(() => parseSignResponse("")).toThrow(RevenantError);
  });

  it("redacts password in error output for malformed XML", () => {
    const xmlWithPassword = "<broken<arx:LogonPassword>secret123</arx:LogonPassword>";
    try {
      parseSignResponse(xmlWithPassword);
      expect.unreachable("should have thrown");
    } catch (err) {
      if (!(err instanceof Error)) {
        expect.unreachable("expected Error instance");
        return;
      }
      expect(err.message).not.toContain("secret123");
    }
  });

  it("redacts Name in error output for malformed XML", () => {
    const xmlWithName = "<broken<Name>JohnDoe</Name>";
    try {
      parseSignResponse(xmlWithName);
      expect.unreachable("should have thrown");
    } catch (err) {
      if (!(err instanceof Error)) {
        expect.unreachable("expected Error instance");
        return;
      }
      expect(err.message).not.toContain("JohnDoe");
    }
  });

  it("throws AuthError when message contains 'password'", () => {
    const xml = wrapSoapSignResponse(`
      <dss:Result>
        <dss:ResultMajor>${FAILURE_MAJOR}</dss:ResultMajor>
        <dss:ResultMessage>Invalid password provided</dss:ResultMessage>
      </dss:Result>`);

    expect(() => parseSignResponse(xml)).toThrow(AuthError);
  });

  it("throws AuthError when message contains 'user name'", () => {
    const xml = wrapSoapSignResponse(`
      <dss:Result>
        <dss:ResultMajor>${FAILURE_MAJOR}</dss:ResultMajor>
        <dss:ResultMessage>Unknown user name</dss:ResultMessage>
      </dss:Result>`);

    expect(() => parseSignResponse(xml)).toThrow(AuthError);
  });
});

// -- parseEnumCertificatesResponse --------------------------------------------

describe("parseEnumCertificatesResponse", () => {
  it("returns certificates on success", () => {
    const certB64One = btoa("cert-data-one");
    const certB64Two = btoa("cert-data-two");
    const xml = wrapSoapEnumCertsResponse(`
      <dss:Result>
        <dss:ResultMajor>${SUCCESS_MAJOR}</dss:ResultMajor>
      </dss:Result>
      <arx:CertificateList xmlns:arx="http://arx.com/SAPIWS/DSS/1.0">
        <arx:AvailableCertificate>${certB64One}</arx:AvailableCertificate>
        <arx:AvailableCertificate>${certB64Two}</arx:AvailableCertificate>
      </arx:CertificateList>`);

    const certs = parseEnumCertificatesResponse(xml);
    expect(certs.length).toBe(2);
    const decodedFirst = new TextDecoder().decode(certs[0]);
    expect(decodedFirst).toBe("cert-data-one");
  });

  it("returns single certificate (non-array branch)", () => {
    const certB64 = btoa("single-cert");
    const xml = wrapSoapEnumCertsResponse(`
      <dss:Result>
        <dss:ResultMajor>${SUCCESS_MAJOR}</dss:ResultMajor>
      </dss:Result>
      <arx:CertificateList xmlns:arx="http://arx.com/SAPIWS/DSS/1.0">
        <arx:AvailableCertificate>${certB64}</arx:AvailableCertificate>
      </arx:CertificateList>`);

    const certs = parseEnumCertificatesResponse(xml);
    expect(certs.length).toBe(1);
    const decoded = new TextDecoder().decode(certs[0]);
    expect(decoded).toBe("single-cert");
  });

  it("returns empty array on success with no certificates", () => {
    const xml = wrapSoapEnumCertsResponse(`
      <dss:Result>
        <dss:ResultMajor>${SUCCESS_MAJOR}</dss:ResultMajor>
      </dss:Result>`);

    const certs = parseEnumCertificatesResponse(xml);
    expect(certs).toEqual([]);
  });

  it("throws AuthError on authentication failure", () => {
    const xml = wrapSoapEnumCertsResponse(`
      <dss:Result>
        <dss:ResultMajor>${FAILURE_MAJOR}</dss:ResultMajor>
        <dss:ResultMinor>urn:oasis:names:tc:dss:1.0:resultminor:AuthenticationError</dss:ResultMinor>
      </dss:Result>`);

    expect(() => parseEnumCertificatesResponse(xml)).toThrow(AuthError);
  });

  it("throws ServerError on non-auth failure", () => {
    const xml = wrapSoapEnumCertsResponse(`
      <dss:Result>
        <dss:ResultMajor>${FAILURE_MAJOR}</dss:ResultMajor>
        <dss:ResultMinor>urn:oasis:names:tc:dss:1.0:resultminor:GeneralError</dss:ResultMinor>
        <dss:ResultMessage>Server busy</dss:ResultMessage>
      </dss:Result>`);

    expect(() => parseEnumCertificatesResponse(xml)).toThrow(ServerError);
    expect(() => parseEnumCertificatesResponse(xml)).toThrow(/Server busy/);
  });

  it("throws RevenantError on malformed XML", () => {
    expect(() => parseEnumCertificatesResponse("<<<bad>>>")).toThrow(RevenantError);
  });
});

// -- parseVerifyResponse ------------------------------------------------------

describe("parseVerifyResponse", () => {
  it("returns valid result for success", () => {
    const xml = wrapSoapVerifyResponse(`
      <dss:Result>
        <dss:ResultMajor>${SUCCESS_MAJOR}</dss:ResultMajor>
      </dss:Result>`);

    const result = parseVerifyResponse(xml);
    expect(result.valid).toBe(true);
    expect(result.error).toBeNull();
  });

  it("extracts signer info attributes on success", () => {
    const xml = wrapSoapVerifyResponse(`
      <dss:Result>
        <dss:ResultMajor>${SUCCESS_MAJOR}</dss:ResultMajor>
      </dss:Result>
      <arx:OptionalOutputs xmlns:arx="http://arx.com/SAPIWS/DSS/1.0">
        <arx:SignedFieldInfo SignerName="John Doe" SignatureTime="2025-01-15T10:30:00"/>
        <arx:FieldStatus CertificateStatus="Valid"/>
      </arx:OptionalOutputs>`);

    const result = parseVerifyResponse(xml);
    expect(result.valid).toBe(true);
    expect(result.signerName).toBe("John Doe");
    expect(result.signTime).toBe("2025-01-15T10:30:00");
    expect(result.certificateStatus).toBe("Valid");
    expect(result.error).toBeNull();
  });

  it("returns invalid result for non-success", () => {
    const xml = wrapSoapVerifyResponse(`
      <dss:Result>
        <dss:ResultMajor>${FAILURE_MAJOR}</dss:ResultMajor>
        <dss:ResultMessage>Verification failed</dss:ResultMessage>
      </dss:Result>`);

    const result = parseVerifyResponse(xml);
    expect(result.valid).toBe(false);
    expect(result.error).toBe("Verification failed");
    expect(result.signerName).toBeNull();
    expect(result.signTime).toBeNull();
    expect(result.certificateStatus).toBeNull();
  });

  it("returns error message for non-success without ResultMessage", () => {
    const xml = wrapSoapVerifyResponse(`
      <dss:Result>
        <dss:ResultMajor>${FAILURE_MAJOR}</dss:ResultMajor>
      </dss:Result>`);

    const result = parseVerifyResponse(xml);
    expect(result.valid).toBe(false);
    expect(result.error).toBe("Server returned non-success result");
  });

  it("handles malformed XML gracefully", () => {
    const result = parseVerifyResponse("not xml at all");
    expect(result.valid).toBe(false);
    expect(result.error).toBeTruthy();
  });

  it("returns null fields on success without signer attributes", () => {
    const xml = wrapSoapVerifyResponse(`
      <dss:Result>
        <dss:ResultMajor>${SUCCESS_MAJOR}</dss:ResultMajor>
      </dss:Result>`);

    const result = parseVerifyResponse(xml);
    expect(result.valid).toBe(true);
    expect(result.signerName).toBeNull();
    expect(result.signTime).toBeNull();
    expect(result.certificateStatus).toBeNull();
  });
});
