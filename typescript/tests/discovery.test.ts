/**
 * Tests for network/discovery.ts.
 *
 * Tests pingServer with various response types, TLS errors,
 * and URL query string handling.
 */

import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../src/network/transport.js", () => ({
  httpGet: vi.fn(),
  httpPost: vi.fn(),
  registerHostTls: vi.fn(),
  getHostTlsInfo: vi.fn(),
}));

import { RevenantError, TLSError } from "../src/errors.js";
import { pingServer } from "../src/network/discovery.js";
import { httpGet } from "../src/network/transport.js";

beforeEach(() => {
  vi.mocked(httpGet).mockReset();
});

// -- URL handling -------------------------------------------------------------

describe("pingServer URL handling", () => {
  it("appends ?WSDL when URL has no query string", async () => {
    const body = new TextEncoder().encode("<not-wsdl/>");
    vi.mocked(httpGet).mockResolvedValueOnce(body);

    await pingServer("https://example.com/SAPIWS/DSS.asmx");

    const callArgs = vi.mocked(httpGet).mock.calls[0];
    if (callArgs === undefined) {
      expect.unreachable("httpGet should have been called");
      return;
    }
    expect(callArgs[0]).toBe("https://example.com/SAPIWS/DSS.asmx?WSDL");
  });

  it("does not append ?WSDL when URL already has a query", async () => {
    const body = new TextEncoder().encode("<not-wsdl/>");
    vi.mocked(httpGet).mockResolvedValueOnce(body);

    await pingServer("https://example.com/api?WSDL");

    const callArgs = vi.mocked(httpGet).mock.calls[0];
    if (callArgs === undefined) {
      expect.unreachable("httpGet should have been called");
      return;
    }
    expect(callArgs[0]).toBe("https://example.com/api?WSDL");
  });

  it("strips trailing slashes before appending ?WSDL", async () => {
    const body = new TextEncoder().encode("<not-wsdl/>");
    vi.mocked(httpGet).mockResolvedValueOnce(body);

    await pingServer("https://example.com/api///");

    const callArgs = vi.mocked(httpGet).mock.calls[0];
    if (callArgs === undefined) {
      expect.unreachable("httpGet should have been called");
      return;
    }
    expect(callArgs[0]).toBe("https://example.com/api?WSDL");
  });

  it("passes timeout option to httpGet", async () => {
    const body = new TextEncoder().encode("<not-wsdl/>");
    vi.mocked(httpGet).mockResolvedValueOnce(body);

    await pingServer("https://example.com/api", 42);

    const callArgs = vi.mocked(httpGet).mock.calls[0];
    if (callArgs === undefined) {
      expect.unreachable("httpGet should have been called");
      return;
    }
    expect(callArgs[1]).toEqual({ timeout: 42 });
  });
});

// -- Response parsing ---------------------------------------------------------

describe("pingServer response parsing", () => {
  it("returns ok=true with CoSign message for valid DssSign+SAPIWS WSDL", async () => {
    const wsdl = '<wsdl:definitions><service name="SAPIWS"><DssSign/></service></wsdl:definitions>';
    vi.mocked(httpGet).mockResolvedValueOnce(new TextEncoder().encode(wsdl));

    const result = await pingServer("https://example.com/api");
    expect(result.ok).toBe(true);
    expect(result.info).toBe("CoSign DSS endpoint confirmed");
  });

  it("returns ok=true with generic WSDL message for wsdl: prefix", async () => {
    const wsdl = '<wsdl:definitions><service name="OtherService"/></wsdl:definitions>';
    vi.mocked(httpGet).mockResolvedValueOnce(new TextEncoder().encode(wsdl));

    const result = await pingServer("https://example.com/api");
    expect(result.ok).toBe(true);
    expect(result.info).toContain("WSDL found");
  });

  it("returns ok=true with generic WSDL message for <definitions tag", async () => {
    const wsdl = '<definitions name="SomeService"></definitions>';
    vi.mocked(httpGet).mockResolvedValueOnce(new TextEncoder().encode(wsdl));

    const result = await pingServer("https://example.com/api");
    expect(result.ok).toBe(true);
    expect(result.info).toContain("WSDL found");
  });

  it("returns ok=false for non-WSDL response", async () => {
    const html = "<html><body>Hello World</body></html>";
    vi.mocked(httpGet).mockResolvedValueOnce(new TextEncoder().encode(html));

    const result = await pingServer("https://example.com/api");
    expect(result.ok).toBe(false);
    expect(result.info).toContain("Not a recognized CoSign endpoint");
  });
});

// -- Error handling -----------------------------------------------------------

describe("pingServer error handling", () => {
  it("returns ok=false with TLS error message on TLSError", async () => {
    vi.mocked(httpGet).mockRejectedValueOnce(
      new TLSError("SSL handshake failed", { retryable: false }),
    );

    const result = await pingServer("https://example.com/api");
    expect(result.ok).toBe(false);
    expect(result.info).toBe("SSL handshake failed");
  });

  it("returns ok=false with connection failed on RevenantError", async () => {
    vi.mocked(httpGet).mockRejectedValueOnce(new RevenantError("ECONNREFUSED"));

    const result = await pingServer("https://example.com/api");
    expect(result.ok).toBe(false);
    expect(result.info).toContain("Connection failed");
    expect(result.info).toContain("ECONNREFUSED");
  });

  it("re-throws non-RevenantError exceptions", async () => {
    vi.mocked(httpGet).mockRejectedValueOnce(new TypeError("unexpected error"));

    await expect(pingServer("https://example.com/api")).rejects.toThrow(TypeError);
  });
});
