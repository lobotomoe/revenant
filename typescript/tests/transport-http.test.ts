/**
 * Tests for httpGet and httpPost with mocked fetch.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { MAX_RESPONSE_SIZE } from "../src/constants.js";
import { RevenantError, TLSError } from "../src/errors.js";
import { httpGet, httpPost, registerHostTls } from "../src/network/transport.js";

const mockFetch = vi.fn();
vi.stubGlobal("fetch", mockFetch);

const mockLegacyRequest = vi.fn();
vi.mock("../src/network/legacy-tls.js", () => ({
  legacyRequest: (...args: unknown[]) => mockLegacyRequest(...args),
}));

function createMockResponse(body: Uint8Array): {
  ok: boolean;
  status: number;
  statusText: string;
  body: { getReader: () => { read: ReturnType<typeof vi.fn> } };
} {
  return {
    ok: true,
    status: 200,
    statusText: "OK",
    body: {
      getReader: () => ({
        read: vi
          .fn()
          .mockResolvedValueOnce({ done: false, value: body })
          .mockResolvedValueOnce({ done: true, value: undefined }),
      }),
    },
  };
}

beforeEach(() => {
  mockFetch.mockReset();
  mockLegacyRequest.mockReset();
});

afterEach(() => {
  // Clean up registered hosts
  registerHostTls("https-test.example.com", false);
});

// -- HTTPS requirement --------------------------------------------------------

describe("httpGet HTTPS requirement", () => {
  it("rejects non-HTTPS URLs", async () => {
    await expect(httpGet("http://example.com/path")).rejects.toThrow(/Only HTTPS URLs are allowed/);
  });

  it("rejects FTP URLs", async () => {
    await expect(httpGet("ftp://example.com/path")).rejects.toThrow(/Only HTTPS URLs are allowed/);
  });
});

describe("httpPost HTTPS requirement", () => {
  it("rejects non-HTTPS URLs", async () => {
    const body = new Uint8Array([1, 2, 3]);
    await expect(httpPost("http://example.com/path", body)).rejects.toThrow(
      /Only HTTPS URLs are allowed/,
    );
  });

  it("rejects FTP URLs", async () => {
    const body = new Uint8Array([1, 2, 3]);
    await expect(httpPost("ftp://example.com/path", body)).rejects.toThrow(
      /Only HTTPS URLs are allowed/,
    );
  });
});

// -- httpGet with standard mode -----------------------------------------------

describe("httpGet with standard HTTPS", () => {
  const TEST_URL = "https://https-test.example.com/path";

  beforeEach(() => {
    registerHostTls("https-test.example.com", false);
  });

  it("returns response bytes on success", async () => {
    const responseBody = new Uint8Array([10, 20, 30]);
    mockFetch.mockResolvedValueOnce(createMockResponse(responseBody));

    const result = await httpGet(TEST_URL, { maxRetries: 0 });
    expect(result).toEqual(Buffer.from(responseBody));
  });

  it("calls fetch with GET method", async () => {
    const responseBody = new Uint8Array([1]);
    mockFetch.mockResolvedValueOnce(createMockResponse(responseBody));

    await httpGet(TEST_URL, { maxRetries: 0 });

    expect(mockFetch).toHaveBeenCalledOnce();
    const callArgs = mockFetch.mock.calls[0];
    if (callArgs === undefined) {
      expect.unreachable("fetch should have been called");
      return;
    }
    expect(callArgs[0]).toBe(TEST_URL);
    const init = callArgs[1];
    if (typeof init !== "object" || init === null) {
      expect.unreachable("fetch init should be an object");
      return;
    }
    expect(init.method).toBe("GET");
  });

  it("throws RevenantError when response has no body", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      statusText: "OK",
      body: null,
    });

    await expect(httpGet(TEST_URL, { maxRetries: 0 })).rejects.toThrow(/No response body/);
  });
});

// -- httpPost with standard mode ----------------------------------------------

describe("httpPost with standard HTTPS", () => {
  const TEST_URL = "https://https-test.example.com/api";

  beforeEach(() => {
    registerHostTls("https-test.example.com", false);
  });

  it("returns response bytes on success", async () => {
    const responseBody = new Uint8Array([99, 88, 77]);
    mockFetch.mockResolvedValueOnce(createMockResponse(responseBody));

    const postBody = new Uint8Array([1, 2, 3]);
    const result = await httpPost(TEST_URL, postBody, { maxRetries: 0 });
    expect(result).toEqual(Buffer.from(responseBody));
  });

  it("passes headers to fetch", async () => {
    const responseBody = new Uint8Array([1]);
    mockFetch.mockResolvedValueOnce(createMockResponse(responseBody));

    const postBody = new Uint8Array([1, 2, 3]);
    const headers = { "Content-Type": "text/xml", SOAPAction: "test" };
    await httpPost(TEST_URL, postBody, { headers, maxRetries: 0 });

    expect(mockFetch).toHaveBeenCalledOnce();
    const callArgs = mockFetch.mock.calls[0];
    if (callArgs === undefined) {
      expect.unreachable("fetch should have been called");
      return;
    }
    const init = callArgs[1];
    if (typeof init !== "object" || init === null) {
      expect.unreachable("fetch init should be an object");
      return;
    }
    expect(init.method).toBe("POST");
    expect(init.headers).toEqual(headers);
  });

  it("throws on HTTP error with no body", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 500,
      statusText: "Internal Server Error",
      body: null,
    });

    const postBody = new Uint8Array([1]);
    await expect(httpPost(TEST_URL, postBody, { maxRetries: 0 })).rejects.toThrow(/HTTP 500/);
  });
});

// -- timeout handling ---------------------------------------------------------

describe("httpGet timeout", () => {
  const TEST_URL = "https://https-test.example.com/slow";

  beforeEach(() => {
    registerHostTls("https-test.example.com", false);
  });

  it("throws TLSError on abort/timeout", async () => {
    mockFetch.mockRejectedValueOnce(new Error("The operation was aborted"));

    await expect(httpGet(TEST_URL, { timeout: 1, maxRetries: 0 })).rejects.toThrow(/timed out/);
  });
});

// -- response size limit ------------------------------------------------------

describe("response size limit", () => {
  const TEST_URL = "https://https-test.example.com/large";

  beforeEach(() => {
    registerHostTls("https-test.example.com", false);
  });

  it("throws RevenantError when response exceeds MAX_RESPONSE_SIZE", async () => {
    // Create a response that exceeds the limit in two chunks
    const halfSize = Math.ceil(MAX_RESPONSE_SIZE / 2) + 1;
    const chunk = new Uint8Array(halfSize);

    const mockCancel = vi.fn();
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      statusText: "OK",
      body: {
        getReader: () => ({
          read: vi
            .fn()
            .mockResolvedValueOnce({ done: false, value: chunk })
            .mockResolvedValueOnce({ done: false, value: chunk }),
          cancel: mockCancel,
        }),
      },
    });

    await expect(httpGet(TEST_URL, { maxRetries: 0 })).rejects.toThrow(/exceeds.*MB limit/);
    expect(mockCancel).toHaveBeenCalled();
  });
});

// -- standard GET with retry ---------------------------------------------------

describe("httpGet with retry on standard HTTPS", () => {
  const TEST_URL = "https://https-test.example.com/retry-path";

  beforeEach(() => {
    registerHostTls("https-test.example.com", false);
  });

  it("returns result on first successful attempt (default retries)", async () => {
    const responseBody = new Uint8Array([42]);
    mockFetch.mockResolvedValueOnce(createMockResponse(responseBody));

    // Default maxRetries is > 0, so withRetry is used
    const result = await httpGet(TEST_URL);
    expect(result).toEqual(Buffer.from(responseBody));
  });
});

// -- undeclared hosts never reach the legacy transport ------------------------

describe("httpGet for an undeclared host", () => {
  it("uses standard HTTPS", async () => {
    const url = "https://undeclared-fresh.example.com/api";
    const body = new Uint8Array([1, 2, 3]);
    mockFetch.mockResolvedValueOnce(createMockResponse(body));

    const result = await httpGet(url, { maxRetries: 0 });
    expect(result).toEqual(Buffer.from(body));
    expect(mockLegacyRequest).not.toHaveBeenCalled();
  });

  it("reports a connection failure instead of downgrading", async () => {
    const url = "https://undeclared-legacy.example.com/api";
    mockFetch.mockRejectedValueOnce(new Error("fetch failed"));

    await expect(httpGet(url, { maxRetries: 0 })).rejects.toThrow(/Connection failed/);
    expect(mockLegacyRequest).not.toHaveBeenCalled();
  });

  it("does not answer a failed certificate check by dropping certificate checks", async () => {
    const url = "https://undeclared-ssl.example.com/api";
    mockFetch.mockRejectedValueOnce(new Error("ERR_TLS_CERT_INVALID"));

    await expect(httpGet(url, { maxRetries: 0 })).rejects.toThrow(/SSL error/);
    expect(mockLegacyRequest).not.toHaveBeenCalled();
  });

  it("propagates non-TLS errors", async () => {
    const url = "https://undeclared-err.example.com/api";
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 403,
      statusText: "Forbidden",
      body: null,
    });

    await expect(httpGet(url, { maxRetries: 0 })).rejects.toThrow(/HTTP 403/);
    expect(mockLegacyRequest).not.toHaveBeenCalled();
  });
});

// -- undeclared hosts never reach the legacy transport, POST ------------------

describe("httpPost for an undeclared host", () => {
  it("uses standard HTTPS", async () => {
    const url = "https://undeclared-post-std.example.com/api";
    const responseBody = new Uint8Array([10, 20]);
    mockFetch.mockResolvedValueOnce(createMockResponse(responseBody));

    const postBody = new Uint8Array([1, 2, 3]);
    const result = await httpPost(url, postBody);
    expect(result).toEqual(Buffer.from(responseBody));
    expect(mockLegacyRequest).not.toHaveBeenCalled();
  });

  it("reports a connection failure instead of downgrading", async () => {
    const url = "https://undeclared-post-legacy.example.com/api";
    mockFetch.mockRejectedValue(new Error("fetch failed"));

    const postBody = new Uint8Array([1, 2, 3]);
    const headers = { "Content-Type": "text/xml" };
    await expect(httpPost(url, postBody, { headers, maxRetries: 0 })).rejects.toThrow(
      /Connection failed/,
    );
    expect(mockLegacyRequest).not.toHaveBeenCalled();
  });
});

// -- error classification ----------------------------------------------------

describe("error classification", () => {
  it("classifies 'fetch failed' as TLSError", async () => {
    const url = "https://https-test.example.com/path";
    registerHostTls("https-test.example.com", false);
    mockFetch.mockRejectedValueOnce(new Error("fetch failed"));

    await expect(httpGet(url, { maxRetries: 0 })).rejects.toThrow(TLSError);
  });

  it("classifies ECONNRESET as TLSError", async () => {
    const url = "https://https-test.example.com/path";
    registerHostTls("https-test.example.com", false);
    mockFetch.mockRejectedValueOnce(new Error("ECONNRESET"));

    await expect(httpGet(url, { maxRetries: 0 })).rejects.toThrow(TLSError);
  });

  it("classifies generic errors as RevenantError", async () => {
    const url = "https://https-test.example.com/path";
    registerHostTls("https-test.example.com", false);
    mockFetch.mockRejectedValueOnce(new Error("Some unknown error"));

    await expect(httpGet(url, { maxRetries: 0 })).rejects.toThrow(RevenantError);
  });
});
