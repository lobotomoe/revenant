/**
 * Tests for the high-level API.
 */

import { beforeEach, describe, expect, it, vi } from "vitest";
import { BUILTIN_PROFILES } from "../src/config/profiles.js";
import { ConfigError } from "../src/errors.js";

// Mock signing functions to avoid actual network calls
vi.mock("../src/core/signing.js", () => ({
  signPdfEmbedded: vi.fn().mockResolvedValue(new Uint8Array([0x25, 0x50, 0x44, 0x46])),
  signPdfDetached: vi.fn().mockResolvedValue(new Uint8Array([0x30, 0x82])),
}));

// Mock the transport so it doesn't open real connections
vi.mock("../src/network/soap-transport.js", () => ({
  SoapSigningTransport: vi.fn().mockImplementation((url: string) => ({
    url,
    signData: vi.fn(),
    signHash: vi.fn(),
  })),
}));

// Mock config module to control profile/URL resolution without reading disk config
const mockGetServerConfig = vi.fn().mockReturnValue({
  url: null,
  timeout: null,
  profileName: null,
});
const mockGetActiveProfile = vi.fn().mockReturnValue(null);
const mockGetSignerName = vi.fn().mockReturnValue(null);
const mockGetSignerInfo = vi.fn().mockReturnValue({
  name: null,
  email: null,
  organization: null,
  dn: null,
});

vi.mock("../src/config/index.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/config/index.js")>();
  return {
    ...actual,
    getServerConfig: (...args: unknown[]) => mockGetServerConfig(...args),
    getActiveProfile: (...args: unknown[]) => mockGetActiveProfile(...args),
    getSignerName: (...args: unknown[]) => mockGetSignerName(...args),
    getSignerInfo: (...args: unknown[]) => mockGetSignerInfo(...args),
    registerProfileTlsMode: vi.fn().mockResolvedValue(undefined),
  };
});

// A minimal PDF header (enough to pass validation)
const FAKE_PDF = new Uint8Array([0x25, 0x50, 0x44, 0x46, 0x2d]);

beforeEach(() => {
  // Reset to "no config saved" state by default
  mockGetServerConfig.mockReturnValue({ url: null, timeout: null, profileName: null });
  mockGetActiveProfile.mockReturnValue(null);
  mockGetSignerName.mockReturnValue(null);
  mockGetSignerInfo.mockReturnValue({ name: null, email: null, organization: null, dn: null });
});

// -- Profile validation -------------------------------------------------------

describe("API parameter validation", () => {
  it("BUILTIN_PROFILES is not empty", () => {
    expect(BUILTIN_PROFILES.size).toBeGreaterThan(0);
  });

  it("profiles have required fields", () => {
    for (const [key, profile] of BUILTIN_PROFILES) {
      expect(profile.name).toBe(key);
      expect(profile.displayName).toBeTruthy();
      expect(profile.url).toBeTruthy();
      expect(profile.timeout).toBeGreaterThan(0);
    }
  });
});

// -- sign() -------------------------------------------------------------------

describe("sign()", () => {
  it("throws ConfigError when both profile and url are provided", async () => {
    const { sign } = await import("../src/api.js");
    await expect(
      sign(FAKE_PDF, "user", "pass", { profile: "ekeng", url: "https://example.com" }),
    ).rejects.toThrow(ConfigError);
  });

  it("throws ConfigError when no URL or profile configured", async () => {
    const { sign } = await import("../src/api.js");
    await expect(sign(FAKE_PDF, "user", "pass")).rejects.toThrow(ConfigError);
  });

  it("throws ConfigError message mentioning server URL", async () => {
    const { sign } = await import("../src/api.js");
    await expect(sign(FAKE_PDF, "user", "pass")).rejects.toThrow("No server URL configured");
  });

  it("succeeds with explicit profile option", async () => {
    const { sign } = await import("../src/api.js");
    const result = await sign(FAKE_PDF, "user", "pass", { profile: "ekeng" });
    expect(result).toBeInstanceOf(Uint8Array);
    expect(result.length).toBeGreaterThan(0);
  });

  it("succeeds with explicit url option", async () => {
    const { sign } = await import("../src/api.js");
    const result = await sign(FAKE_PDF, "user", "pass", {
      url: "https://signing.example.com/DSS.asmx",
    });
    expect(result).toBeInstanceOf(Uint8Array);
    expect(result.length).toBeGreaterThan(0);
  });

  it("uses saved config URL when available and no explicit options given", async () => {
    mockGetServerConfig.mockReturnValue({
      url: "https://saved.example.com/DSS.asmx",
      timeout: 60,
      profileName: null,
    });
    const { sign } = await import("../src/api.js");
    const result = await sign(FAKE_PDF, "user", "pass");
    expect(result).toBeInstanceOf(Uint8Array);
  });
});

// -- signDetached() -----------------------------------------------------------

describe("signDetached()", () => {
  it("throws ConfigError when both profile and url are provided", async () => {
    const { signDetached } = await import("../src/api.js");
    await expect(
      signDetached(FAKE_PDF, "user", "pass", { profile: "ekeng", url: "https://example.com" }),
    ).rejects.toThrow(ConfigError);
  });

  it("throws ConfigError when no URL configured", async () => {
    const { signDetached } = await import("../src/api.js");
    await expect(signDetached(FAKE_PDF, "user", "pass")).rejects.toThrow(ConfigError);
  });

  it("succeeds with explicit profile option", async () => {
    const { signDetached } = await import("../src/api.js");
    const result = await signDetached(FAKE_PDF, "user", "pass", { profile: "ekeng" });
    expect(result).toBeInstanceOf(Uint8Array);
    expect(result.length).toBeGreaterThan(0);
  });

  it("succeeds with explicit url option", async () => {
    const { signDetached } = await import("../src/api.js");
    const result = await signDetached(FAKE_PDF, "user", "pass", {
      url: "https://signing.example.com/DSS.asmx",
    });
    expect(result).toBeInstanceOf(Uint8Array);
    expect(result.length).toBeGreaterThan(0);
  });

  it("uses saved config URL when available", async () => {
    mockGetServerConfig.mockReturnValue({
      url: "https://saved.example.com/DSS.asmx",
      timeout: 90,
      profileName: null,
    });
    const { signDetached } = await import("../src/api.js");
    const result = await signDetached(FAKE_PDF, "user", "pass");
    expect(result).toBeInstanceOf(Uint8Array);
  });
});
