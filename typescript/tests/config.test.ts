/**
 * Tests for configuration and profile management.
 */

import { describe, expect, it } from "vitest";
import { getSignerInfo, getSignerName } from "../src/config/config.js";
import {
  BUILTIN_PROFILES,
  getProfile,
  hasIdentityMethod,
  makeCustomProfile,
} from "../src/config/profiles.js";
import { CONFIG_DIR, CONFIG_FILE, loadConfig, loadRawConfig } from "../src/config/storage.js";
import { DEFAULT_TIMEOUT_SOAP, VERSION } from "../src/constants.js";

// -- BUILTIN_PROFILES ---------------------------------------------------------

describe("BUILTIN_PROFILES", () => {
  it("contains at least one profile", () => {
    expect(BUILTIN_PROFILES.size).toBeGreaterThan(0);
  });

  it("all profiles have valid structure", () => {
    for (const [, profile] of BUILTIN_PROFILES) {
      expect(profile.url).toMatch(/^https?:\/\//);
      expect(profile.timeout).toBeGreaterThan(0);
      expect(profile.identityMethods.length).toBeGreaterThan(0);
    }
  });

  it("ekeng profile exists with expected properties", () => {
    const ekeng = BUILTIN_PROFILES.get("ekeng");
    expect(ekeng).toBeDefined();
    if (ekeng) {
      expect(ekeng.name).toBe("ekeng");
      expect(ekeng.legacyTls).toBe(true);
      expect(ekeng.url).toContain("ca.gov.am");
    }
  });
});

// -- getProfile ---------------------------------------------------------------

describe("getProfile", () => {
  it("returns a known profile", () => {
    const keys = [...BUILTIN_PROFILES.keys()];
    if (keys[0] !== undefined) {
      const profile = getProfile(keys[0]);
      expect(profile.name).toBe(keys[0]);
    }
  });

  it("is case-insensitive", () => {
    const profile = getProfile("EKENG");
    expect(profile.name).toBe("ekeng");
  });

  it("trims whitespace", () => {
    const profile = getProfile("  ekeng  ");
    expect(profile.name).toBe("ekeng");
  });

  it("throws for unknown profile", () => {
    expect(() => getProfile("nonexistent")).toThrow();
  });

  it("throws with available profiles listed in error", () => {
    try {
      getProfile("nonexistent");
      expect.unreachable("should have thrown");
    } catch (err) {
      if (!(err instanceof Error)) {
        expect.unreachable("expected Error instance");
        return;
      }
      expect(err.message).toContain("ekeng");
    }
  });
});

// -- hasIdentityMethod --------------------------------------------------------

describe("hasIdentityMethod", () => {
  it("returns true when profile has the method", () => {
    const ekeng = getProfile("ekeng");
    expect(hasIdentityMethod(ekeng, "server")).toBe(true);
    expect(hasIdentityMethod(ekeng, "manual")).toBe(true);
  });

  it("returns false when profile lacks the method", () => {
    const ekeng = getProfile("ekeng");
    expect(hasIdentityMethod(ekeng, "oauth")).toBe(false);
    expect(hasIdentityMethod(ekeng, "")).toBe(false);
  });
});

// -- makeCustomProfile --------------------------------------------------------

describe("makeCustomProfile", () => {
  it("creates a profile with the given URL", () => {
    const profile = makeCustomProfile("https://custom.example.com/SAPIWS/DSS.asmx");
    expect(profile.url).toBe("https://custom.example.com/SAPIWS/DSS.asmx");
    expect(profile.name).toBe("custom");
    expect(profile.displayName).toContain("custom");
  });

  it("uses default timeout when not specified", () => {
    const profile = makeCustomProfile("https://example.com/api");
    expect(profile.timeout).toBe(DEFAULT_TIMEOUT_SOAP);
  });

  it("uses custom timeout when specified", () => {
    const profile = makeCustomProfile("https://example.com/api", 60);
    expect(profile.timeout).toBe(60);
  });

  it("sets legacyTls to false for custom profiles", () => {
    const profile = makeCustomProfile("https://example.com/api");
    expect(profile.legacyTls).toBe(false);
  });

  it("rejects HTTP URLs", () => {
    expect(() => makeCustomProfile("http://example.com/api")).toThrow(
      /HTTP URLs are not supported/,
    );
  });

  it("rejects invalid URL schemes", () => {
    expect(() => makeCustomProfile("ftp://example.com/api")).toThrow(/Invalid URL scheme/);
  });

  it("rejects invalid URLs", () => {
    expect(() => makeCustomProfile("not a url")).toThrow(/Invalid URL/);
  });

  it("has empty certFields and sigFields", () => {
    const profile = makeCustomProfile("https://example.com/api");
    expect(profile.certFields).toEqual([]);
    expect(profile.sigFields).toEqual([]);
  });
});

// -- VERSION ------------------------------------------------------------------

describe("VERSION", () => {
  it("is a valid semver string", () => {
    expect(VERSION).toMatch(/^\d+\.\d+\.\d+/);
  });
});

// -- getSignerInfo ------------------------------------------------------------

describe("getSignerInfo", () => {
  it("returns an object with expected keys", () => {
    const info = getSignerInfo();
    expect(info).toHaveProperty("name");
    expect(info).toHaveProperty("email");
    expect(info).toHaveProperty("organization");
    expect(info).toHaveProperty("dn");
  });

  it("all values are string or null", () => {
    const info = getSignerInfo();
    for (const value of Object.values(info)) {
      expect(value === null || typeof value === "string").toBe(true);
    }
  });
});

// -- getSignerName ------------------------------------------------------------

describe("getSignerName", () => {
  it("returns null or string", () => {
    const name = getSignerName();
    expect(name === null || typeof name === "string").toBe(true);
  });
});

// -- CONFIG_DIR / CONFIG_FILE -------------------------------------------------

describe("CONFIG_DIR and CONFIG_FILE", () => {
  it("CONFIG_DIR is an absolute path under home directory", () => {
    expect(CONFIG_DIR).toContain(".revenant");
    // Absolute path starts with /
    expect(CONFIG_DIR.startsWith("/")).toBe(true);
  });

  it("CONFIG_FILE is config.json under CONFIG_DIR", () => {
    expect(CONFIG_FILE).toContain("config.json");
    expect(CONFIG_FILE.startsWith(CONFIG_DIR)).toBe(true);
  });
});

// -- loadRawConfig / loadConfig ------------------------------------------------

describe("loadRawConfig", () => {
  it("returns a plain object", () => {
    const raw = loadRawConfig();
    expect(typeof raw).toBe("object");
    expect(raw).not.toBeNull();
    expect(Array.isArray(raw)).toBe(false);
  });
});

describe("loadConfig", () => {
  it("returns an object with only expected keys (Zod-validated)", () => {
    const config = loadConfig();
    expect(typeof config).toBe("object");
    expect(config).not.toBeNull();

    // loadConfig returns ConfigDict -- all values are either string, number, or undefined
    const allowedKeys = new Set([
      "profile",
      "url",
      "timeout",
      "username",
      "password",
      "name",
      "email",
      "organization",
      "dn",
    ]);
    for (const key of Object.keys(config)) {
      expect(allowedKeys.has(key)).toBe(true);
    }
  });
});
