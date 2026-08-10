/**
 * Tests for HTTP transport TLS mode registration.
 */

import { afterEach, describe, expect, it } from "vitest";
import { TLSError } from "../src/errors.js";
import { getHostTlsInfo, registerHostTls } from "../src/network/transport.js";

const PIN = "ab".repeat(32);

describe("registerHostTls / getHostTlsInfo", () => {
  // There is no public "clear" API, so registrations are reset to a known
  // state after each test and order does not matter.
  afterEach(() => {
    for (const host of [
      "standard.example.com",
      "legacy.example.com",
      "flip.example.com",
      "flip2.example.com",
    ]) {
      registerHostTls(host, false);
    }
  });

  it("treats an undeclared host as standard HTTPS", () => {
    expect(getHostTlsInfo("never-registered-host.example.com")).toBe("Standard HTTPS");
  });

  it("reports standard HTTPS for a host registered with legacy=false", () => {
    registerHostTls("standard.example.com", false);
    expect(getHostTlsInfo("standard.example.com")).toBe("Standard HTTPS");
  });

  it("reports a pinned legacy host", () => {
    registerHostTls("legacy.example.com", true, [PIN]);
    expect(getHostTlsInfo("legacy.example.com")).toBe("Legacy TLS (RC4, pinned key)");
  });

  it("refuses to declare legacy TLS without a pinned key", () => {
    expect(() => registerHostTls("legacy.example.com", true)).toThrow(TLSError);
    expect(() => registerHostTls("legacy.example.com", true, [])).toThrow(
      "without a pinned server key",
    );
    expect(getHostTlsInfo("legacy.example.com")).toBe("Standard HTTPS");
  });

  it("allows updating a host from standard to legacy", () => {
    registerHostTls("flip.example.com", false);
    expect(getHostTlsInfo("flip.example.com")).toBe("Standard HTTPS");

    registerHostTls("flip.example.com", true, [PIN]);
    expect(getHostTlsInfo("flip.example.com")).toBe("Legacy TLS (RC4, pinned key)");
  });

  it("allows updating a host from legacy to standard", () => {
    registerHostTls("flip2.example.com", true, [PIN]);
    expect(getHostTlsInfo("flip2.example.com")).toBe("Legacy TLS (RC4, pinned key)");

    registerHostTls("flip2.example.com", false);
    expect(getHostTlsInfo("flip2.example.com")).toBe("Standard HTTPS");
  });
});
