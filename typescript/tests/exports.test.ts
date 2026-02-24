/**
 * Tests that index re-exports are accessible and cover src/index.ts and src/core/index.ts.
 */

import { describe, expect, it } from "vitest";

describe("src/index.ts re-exports", () => {
  it("exports high-level API functions", async () => {
    const mod = await import("../src/index.js");
    expect(typeof mod.sign).toBe("function");
    expect(typeof mod.signDetached).toBe("function");
  });

  it("exports configuration helpers", async () => {
    const mod = await import("../src/index.js");
    expect(typeof mod.getSignerName).toBe("function");
  });

  it("exports VERSION constant", async () => {
    const mod = await import("../src/index.js");
    expect(typeof mod.VERSION).toBe("string");
    expect(mod.VERSION.length).toBeGreaterThan(0);
  });

  it("exports PDF verification functions", async () => {
    const mod = await import("../src/index.js");
    expect(typeof mod.resolvePosition).toBe("function");
    expect(typeof mod.verifyAllEmbeddedSignatures).toBe("function");
    expect(typeof mod.verifyDetachedSignature).toBe("function");
    expect(typeof mod.verifyEmbeddedSignature).toBe("function");
  });

  it("exports core signing functions", async () => {
    const mod = await import("../src/index.js");
    expect(typeof mod.signData).toBe("function");
    expect(typeof mod.signHash).toBe("function");
    expect(typeof mod.signPdfDetached).toBe("function");
    expect(typeof mod.signPdfEmbedded).toBe("function");
  });

  it("exports error classes", async () => {
    const mod = await import("../src/index.js");
    expect(mod.AuthError).toBeDefined();
    expect(mod.CertificateError).toBeDefined();
    expect(mod.ConfigError).toBeDefined();
    expect(mod.PDFError).toBeDefined();
    expect(mod.RevenantError).toBeDefined();
    expect(mod.ServerError).toBeDefined();
    expect(mod.TLSError).toBeDefined();
  });

  it("exports logger functions", async () => {
    const mod = await import("../src/index.js");
    expect(typeof mod.setLogHandler).toBe("function");
    expect(typeof mod.setLogLevel).toBe("function");
  });
});

describe("src/core/index.ts re-exports", () => {
  it("exports cert-info functions", async () => {
    const mod = await import("../src/core/index.js");
    expect(typeof mod.discoverIdentityFromServer).toBe("function");
    expect(typeof mod.extractAllCertInfoFromPdf).toBe("function");
    expect(typeof mod.extractCertInfoFromCms).toBe("function");
    expect(typeof mod.extractCertInfoFromPdf).toBe("function");
    expect(typeof mod.extractCertInfoFromX509).toBe("function");
  });

  it("exports signing functions", async () => {
    const mod = await import("../src/core/index.js");
    expect(typeof mod.signData).toBe("function");
    expect(typeof mod.signHash).toBe("function");
    expect(typeof mod.signPdfDetached).toBe("function");
    expect(typeof mod.signPdfEmbedded).toBe("function");
  });
});

describe("src/network/index.ts re-exports", () => {
  it("exports discovery functions", async () => {
    const mod = await import("../src/network/index.js");
    expect(typeof mod.pingServer).toBe("function");
  });

  it("exports SOAP functions", async () => {
    const mod = await import("../src/network/index.js");
    expect(typeof mod.sendSoap).toBe("function");
    expect(typeof mod.xmlEscape).toBe("function");
    expect(typeof mod.parseSignResponse).toBe("function");
    expect(typeof mod.parseEnumCertificatesResponse).toBe("function");
    expect(typeof mod.parseVerifyResponse).toBe("function");
    expect(typeof mod.buildEnumCertificatesEnvelope).toBe("function");
    expect(typeof mod.buildSignEnvelope).toBe("function");
    expect(typeof mod.buildSignHashEnvelope).toBe("function");
    expect(typeof mod.buildVerifyEnvelope).toBe("function");
  });

  it("exports SOAP transport classes", async () => {
    const mod = await import("../src/network/index.js");
    expect(mod.SoapSigningTransport).toBeDefined();
    expect(typeof mod.enumCertificates).toBe("function");
    expect(typeof mod.verifyPdfServer).toBe("function");
  });

  it("exports transport functions", async () => {
    const mod = await import("../src/network/index.js");
    expect(typeof mod.httpGet).toBe("function");
    expect(typeof mod.httpPost).toBe("function");
    expect(typeof mod.registerHostTls).toBe("function");
    expect(typeof mod.getHostTlsInfo).toBe("function");
  });

  it("exports signature type constants", async () => {
    const mod = await import("../src/network/index.js");
    expect(typeof mod.SIGNATURE_TYPE_CMS).toBe("string");
    expect(typeof mod.SIGNATURE_TYPE_ENUM_CERTS).toBe("string");
    expect(typeof mod.SIGNATURE_TYPE_FIELD_VERIFY).toBe("string");
    expect(typeof mod.SIGNATURE_TYPE_XMLDSIG).toBe("string");
  });
});
