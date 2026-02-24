/**
 * Tests for SoapSigningTransport.
 */

import { beforeEach, describe, expect, it, vi } from "vitest";

const { FAKE_SIGN_RESULT } = vi.hoisted(() => ({
  FAKE_SIGN_RESULT: new Uint8Array([0x30, 0x82, 0x01, 0x00, 0xaa, 0xbb]),
}));

vi.mock("../src/network/soap.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/network/soap.js")>();
  return {
    ...actual,
    sendSoap: vi.fn().mockResolvedValue("<mock-response/>"),
    parseSignResponse: vi.fn().mockReturnValue(FAKE_SIGN_RESULT),
  };
});

import { parseSignResponse, sendSoap } from "../src/network/soap.js";
import {
  enumCertificates,
  SoapSigningTransport,
  verifyPdfServer,
} from "../src/network/soap-transport.js";

beforeEach(() => {
  vi.mocked(sendSoap).mockClear();
  vi.mocked(parseSignResponse).mockClear();
});

// -- SoapSigningTransport -----------------------------------------------------

describe("SoapSigningTransport", () => {
  const SOAP_URL = "https://example.com/SAPIWS/DSS.asmx";
  const transport = new SoapSigningTransport(SOAP_URL);

  it("has the correct url property", () => {
    expect(transport.url).toBe(SOAP_URL);
  });

  it("signData calls sendSoap with DssSign action", async () => {
    const data = new Uint8Array([1, 2, 3]);
    const result = await transport.signData(data, "user", "pass", 120);

    expect(sendSoap).toHaveBeenCalledOnce();
    const callArgs = vi.mocked(sendSoap).mock.calls[0];
    if (callArgs === undefined) {
      expect.unreachable("sendSoap should have been called");
      return;
    }
    expect(callArgs[0]).toBe(SOAP_URL);
    expect(callArgs[2]).toBe("DssSign");
    expect(callArgs[3]).toBe(120);
    expect(result).toEqual(FAKE_SIGN_RESULT);
  });

  it("signHash calls sendSoap with DssSign action", async () => {
    const hash = new Uint8Array([0xaa, 0xbb, 0xcc]);
    const result = await transport.signHash(hash, "user", "pass", 60);

    expect(sendSoap).toHaveBeenCalledOnce();
    const callArgs = vi.mocked(sendSoap).mock.calls[0];
    if (callArgs === undefined) {
      expect.unreachable("sendSoap should have been called");
      return;
    }
    expect(callArgs[0]).toBe(SOAP_URL);
    expect(callArgs[2]).toBe("DssSign");
    expect(callArgs[3]).toBe(60);
    expect(result).toEqual(FAKE_SIGN_RESULT);
  });

  it("signPdfDetached calls sendSoap with DssSign action", async () => {
    const pdf = new Uint8Array([0x25, 0x50, 0x44, 0x46]);
    const result = await transport.signPdfDetached(pdf, "user", "pass", 90);

    expect(sendSoap).toHaveBeenCalledOnce();
    const callArgs = vi.mocked(sendSoap).mock.calls[0];
    if (callArgs === undefined) {
      expect.unreachable("sendSoap should have been called");
      return;
    }
    expect(callArgs[0]).toBe(SOAP_URL);
    expect(callArgs[2]).toBe("DssSign");
    expect(callArgs[3]).toBe(90);
    expect(result).toEqual(FAKE_SIGN_RESULT);
  });

  it("passes base64-encoded data in the envelope", async () => {
    const data = new Uint8Array([72, 101, 108, 108, 111]); // "Hello"
    await transport.signData(data, "alice", "secret", 120);

    const callArgs = vi.mocked(sendSoap).mock.calls[0];
    if (callArgs === undefined) {
      expect.unreachable("sendSoap should have been called");
      return;
    }
    // The second argument is the envelope string containing base64
    const envelope = callArgs[1];
    if (typeof envelope !== "string") {
      expect.unreachable("envelope should be a string");
      return;
    }
    const expectedB64 = Buffer.from(data).toString("base64");
    expect(envelope).toContain(expectedB64);
  });
});

// -- verifyPdfServer ----------------------------------------------------------

describe("verifyPdfServer", () => {
  it("calls sendSoap with DssVerify action", async () => {
    vi.mocked(sendSoap).mockResolvedValueOnce(
      `<Envelope><Body><SignResponse>
        <Result><ResultMajor>urn:oasis:names:tc:dss:1.0:resultmajor:Success</ResultMajor></Result>
      </SignResponse></Body></Envelope>`,
    );

    const pdf = new Uint8Array([0x25, 0x50, 0x44, 0x46]);
    await verifyPdfServer("https://example.com/api", pdf, 120);

    const callArgs = vi.mocked(sendSoap).mock.calls[0];
    if (callArgs === undefined) {
      expect.unreachable("sendSoap should have been called");
      return;
    }
    expect(callArgs[2]).toBe("DssVerify");
  });

  it("returns error result when sendSoap throws", async () => {
    vi.mocked(sendSoap).mockRejectedValueOnce(new Error("connection failed"));

    const pdf = new Uint8Array([0x25, 0x50, 0x44, 0x46]);
    const result = await verifyPdfServer("https://example.com/api", pdf, 120);

    expect(result.valid).toBe(false);
    expect(result.error).toContain("connection failed");
  });
});

// -- enumCertificates ---------------------------------------------------------

describe("enumCertificates", () => {
  it("calls sendSoap with DssSign action", async () => {
    vi.mocked(sendSoap).mockResolvedValueOnce("<mock-enum-response/>");

    await enumCertificates("https://example.com/api", "user", "pass", 120).catch(() => {
      // parseEnumCertificatesResponse will fail on mock XML, that's expected
    });

    expect(sendSoap).toHaveBeenCalledOnce();
    const callArgs = vi.mocked(sendSoap).mock.calls[0];
    if (callArgs === undefined) {
      expect.unreachable("sendSoap should have been called");
      return;
    }
    expect(callArgs[0]).toBe("https://example.com/api");
    expect(callArgs[2]).toBe("DssSign");
  });
});
