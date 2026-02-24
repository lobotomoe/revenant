/**
 * Tests for HTTP transport TLS mode registration.
 */

import { afterEach, describe, expect, it } from "vitest";
import { getHostTlsInfo, registerHostTls } from "../src/network/transport.js";

describe("registerHostTls / getHostTlsInfo", () => {
  // Clean up after each test by re-registering known hosts to avoid leaking
  // state between tests. There is no public "clear" API, so we just
  // overwrite with deterministic values where needed.

  afterEach(() => {
    // Overwrite test hosts so order doesn't matter
    registerHostTls("standard.example.com", false);
    registerHostTls("legacy.example.com", true);
  });

  it("returns null for an unregistered host", () => {
    const info = getHostTlsInfo("never-registered-host.example.com");
    expect(info).toBeNull();
  });

  it("returns 'Standard HTTPS' for a host registered with legacy=false", () => {
    registerHostTls("standard.example.com", false);
    const info = getHostTlsInfo("standard.example.com");
    expect(info).toBe("Standard HTTPS");
  });

  it("returns 'Legacy TLS (RC4)' for a host registered with legacy=true", () => {
    registerHostTls("legacy.example.com", true);
    const info = getHostTlsInfo("legacy.example.com");
    expect(info).toBe("Legacy TLS (RC4)");
  });

  it("allows updating a host from standard to legacy", () => {
    registerHostTls("flip.example.com", false);
    expect(getHostTlsInfo("flip.example.com")).toBe("Standard HTTPS");

    registerHostTls("flip.example.com", true);
    expect(getHostTlsInfo("flip.example.com")).toBe("Legacy TLS (RC4)");
  });

  it("allows updating a host from legacy to standard", () => {
    registerHostTls("flip2.example.com", true);
    expect(getHostTlsInfo("flip2.example.com")).toBe("Legacy TLS (RC4)");

    registerHostTls("flip2.example.com", false);
    expect(getHostTlsInfo("flip2.example.com")).toBe("Standard HTTPS");
  });
});
