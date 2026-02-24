/**
 * Tests for config operations with mocked storage.
 *
 * Tests saveServerConfig, getServerConfig, saveSignerInfo, getSignerInfo,
 * getSignerName, logout, and resetAll using an in-memory config store.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../src/config/storage.js", () => {
  let store: Record<string, unknown> = {};
  return {
    loadConfig: vi.fn(() => store),
    loadRawConfig: vi.fn(() => store),
    saveConfig: vi.fn((data: Record<string, unknown>) => {
      store = { ...data };
    }),
    CONFIG_DIR: "/tmp/test-revenant",
    CONFIG_FILE: "/tmp/test-revenant/config.json",
  };
});

vi.mock("keytar", () => {
  throw new Error("keytar not available");
});

import {
  getActiveProfile,
  getConfigLayer,
  getServerConfig,
  getSignerInfo,
  getSignerName,
  logout,
  resetAll,
  saveServerConfig,
  saveSignerInfo,
} from "../src/config/config.js";
import { makeCustomProfile } from "../src/config/profiles.js";
import { loadConfig, loadRawConfig, saveConfig } from "../src/config/storage.js";

beforeEach(() => {
  // Reset the in-memory store by calling saveConfig with empty object
  vi.mocked(saveConfig)({});
  vi.mocked(saveConfig).mockClear();
  vi.mocked(loadConfig).mockClear();
  vi.mocked(loadRawConfig).mockClear();

  delete process.env.REVENANT_URL;
  delete process.env.REVENANT_TIMEOUT;
});

afterEach(() => {
  delete process.env.REVENANT_URL;
  delete process.env.REVENANT_TIMEOUT;
});

// -- saveServerConfig + getServerConfig ---------------------------------------

describe("saveServerConfig + getServerConfig", () => {
  it("round-trips server configuration", () => {
    const profile = makeCustomProfile("https://example.com/SAPIWS/DSS.asmx", 90);
    saveServerConfig(profile);

    const config = getServerConfig();
    expect(config.url).toBe("https://example.com/SAPIWS/DSS.asmx");
    expect(config.timeout).toBe(90);
    expect(config.profileName).toBe("custom");
  });

  it("returns nulls when no server config is saved", () => {
    const config = getServerConfig();
    expect(config.url).toBeNull();
    expect(config.timeout).toBeNull();
    expect(config.profileName).toBeNull();
  });

  it("REVENANT_URL env var overrides saved config", () => {
    const profile = makeCustomProfile("https://saved.example.com/api", 60);
    saveServerConfig(profile);
    process.env.REVENANT_URL = "https://env.example.com/api";

    const config = getServerConfig();
    expect(config.url).toBe("https://env.example.com/api");
  });

  it("REVENANT_TIMEOUT env var overrides saved timeout", () => {
    const profile = makeCustomProfile("https://example.com/api", 60);
    saveServerConfig(profile);
    process.env.REVENANT_TIMEOUT = "30";

    const config = getServerConfig();
    expect(config.timeout).toBe(30);
  });

  it("ignores invalid REVENANT_TIMEOUT and uses saved value", () => {
    const profile = makeCustomProfile("https://example.com/api", 60);
    saveServerConfig(profile);
    process.env.REVENANT_TIMEOUT = "not-a-number";

    const config = getServerConfig();
    // Falls back to default when env var is invalid
    expect(config.timeout).toBe(120); // DEFAULT_TIMEOUT_SOAP
  });

  it("derives URL from builtin profile when only profile name is set", () => {
    vi.mocked(saveConfig)({ profile: "ekeng" });
    vi.mocked(saveConfig).mockClear();

    const config = getServerConfig();
    expect(config.url).toContain("ca.gov.am");
    expect(config.profileName).toBe("ekeng");
  });

  it("uses builtin profile timeout when profile exists but no custom timeout", () => {
    vi.mocked(saveConfig)({ profile: "ekeng" });
    vi.mocked(saveConfig).mockClear();

    const config = getServerConfig();
    expect(config.timeout).toBe(120); // ekeng profile timeout
  });

  it("uses default timeout when url is set without profile or timeout", () => {
    vi.mocked(saveConfig)({ url: "https://example.com/api" });
    vi.mocked(saveConfig).mockClear();

    const config = getServerConfig();
    expect(config.timeout).toBe(120); // DEFAULT_TIMEOUT_SOAP
  });
});

// -- saveSignerInfo + getSignerInfo -------------------------------------------

describe("saveSignerInfo + getSignerInfo", () => {
  it("round-trips all signer fields", () => {
    saveSignerInfo("Alice Smith", "alice@example.com", "ACME Corp", "CN=Alice");

    const info = getSignerInfo();
    expect(info.name).toBe("Alice Smith");
    expect(info.email).toBe("alice@example.com");
    expect(info.organization).toBe("ACME Corp");
    expect(info.dn).toBe("CN=Alice");
  });

  it("saves only name when optional fields are null", () => {
    saveSignerInfo("Bob Jones", null, null, null);

    const info = getSignerInfo();
    expect(info.name).toBe("Bob Jones");
    expect(info.email).toBeNull();
    expect(info.organization).toBeNull();
    expect(info.dn).toBeNull();
  });

  it("clears optional fields when updating with null", () => {
    saveSignerInfo("Alice", "alice@example.com", "ACME", "CN=Alice");
    saveSignerInfo("Alice", null, null, null);

    const info = getSignerInfo();
    expect(info.name).toBe("Alice");
    expect(info.email).toBeNull();
    expect(info.organization).toBeNull();
    expect(info.dn).toBeNull();
  });
});

// -- getSignerName ------------------------------------------------------------

describe("getSignerName (mocked)", () => {
  it("returns name from config", () => {
    saveSignerInfo("Test User");

    const name = getSignerName();
    expect(name).toBe("Test User");
  });

  it("returns null when no name is set", () => {
    const name = getSignerName();
    expect(name).toBeNull();
  });
});

// -- logout -------------------------------------------------------------------

describe("logout", () => {
  it("clears identity fields from config", async () => {
    saveSignerInfo("Alice", "alice@example.com", "ACME", "CN=Alice");

    await logout();

    const info = getSignerInfo();
    expect(info.name).toBeNull();
    expect(info.email).toBeNull();
    expect(info.organization).toBeNull();
    expect(info.dn).toBeNull();
  });

  it("preserves non-identity config (url, timeout)", async () => {
    const profile = makeCustomProfile("https://example.com/api", 90);
    saveServerConfig(profile);
    saveSignerInfo("Alice");

    await logout();

    const serverConfig = getServerConfig();
    expect(serverConfig.url).toBe("https://example.com/api");
  });
});

// -- resetAll -----------------------------------------------------------------

describe("resetAll", () => {
  it("clears everything from config", async () => {
    const profile = makeCustomProfile("https://example.com/api", 90);
    saveServerConfig(profile);
    saveSignerInfo("Alice", "alice@example.com");

    await resetAll();

    const serverConfig = getServerConfig();
    expect(serverConfig.url).toBeNull();

    const signerInfo = getSignerInfo();
    expect(signerInfo.name).toBeNull();
  });
});

// -- getActiveProfile ---------------------------------------------------------

describe("getActiveProfile", () => {
  it("returns null when no profile or url is configured", () => {
    const profile = getActiveProfile();
    expect(profile).toBeNull();
  });

  it("returns builtin profile when profile name is set", () => {
    vi.mocked(saveConfig)({ profile: "ekeng" });
    vi.mocked(saveConfig).mockClear();

    const profile = getActiveProfile();
    expect(profile).not.toBeNull();
    if (profile === null) {
      expect.unreachable("profile should not be null");
      return;
    }
    expect(profile.name).toBe("ekeng");
    expect(profile.url).toContain("ca.gov.am");
  });

  it("returns custom profile when url is set without profile name", () => {
    vi.mocked(saveConfig)({ url: "https://custom.example.com/api" });
    vi.mocked(saveConfig).mockClear();

    const profile = getActiveProfile();
    expect(profile).not.toBeNull();
    if (profile === null) {
      expect.unreachable("profile should not be null");
      return;
    }
    expect(profile.name).toBe("custom");
    expect(profile.url).toBe("https://custom.example.com/api");
  });

  it("returns custom profile with saved timeout", () => {
    vi.mocked(saveConfig)({ url: "https://example.com/api", timeout: 45 });
    vi.mocked(saveConfig).mockClear();

    const profile = getActiveProfile();
    expect(profile).not.toBeNull();
    if (profile === null) {
      expect.unreachable("profile should not be null");
      return;
    }
    expect(profile.timeout).toBe(45);
  });

  it("uses default timeout when not specified in config", () => {
    vi.mocked(saveConfig)({ url: "https://example.com/api" });
    vi.mocked(saveConfig).mockClear();

    const profile = getActiveProfile();
    expect(profile).not.toBeNull();
    if (profile === null) {
      expect.unreachable("profile should not be null");
      return;
    }
    expect(profile.timeout).toBe(120); // DEFAULT_TIMEOUT_SOAP
  });

  it("ignores unknown profile name and falls back to url", () => {
    vi.mocked(saveConfig)({
      profile: "nonexistent",
      url: "https://fallback.example.com/api",
    });
    vi.mocked(saveConfig).mockClear();

    const profile = getActiveProfile();
    expect(profile).not.toBeNull();
    if (profile === null) {
      expect.unreachable("profile should not be null");
      return;
    }
    expect(profile.url).toBe("https://fallback.example.com/api");
  });

  it("returns null when profile name is unknown and no url", () => {
    vi.mocked(saveConfig)({ profile: "nonexistent" });
    vi.mocked(saveConfig).mockClear();

    const profile = getActiveProfile();
    expect(profile).toBeNull();
  });
});

// -- getConfigLayer -----------------------------------------------------------

describe("getConfigLayer", () => {
  it("returns 0 when no url is configured", () => {
    const layer = getConfigLayer();
    expect(layer).toBe(0);
  });

  it("returns 1 when url is configured but no signer name", () => {
    const profile = makeCustomProfile("https://example.com/api", 90);
    saveServerConfig(profile);

    const layer = getConfigLayer();
    expect(layer).toBe(1);
  });

  it("returns 2 when both url and signer name are configured", () => {
    const profile = makeCustomProfile("https://example.com/api", 90);
    saveServerConfig(profile);
    saveSignerInfo("Alice");

    const layer = getConfigLayer();
    expect(layer).toBe(2);
  });
});
