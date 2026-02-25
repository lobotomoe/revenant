/**
 * Tests for TLS bridge functions in config/index.ts.
 *
 * Tests registerProfileTlsMode and registerActiveProfileTls.
 */

import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../src/network/transport.js", () => ({
  httpGet: vi.fn(),
  httpPost: vi.fn(),
  registerHostTls: vi.fn(),
  getHostTlsInfo: vi.fn(),
}));

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

import { registerActiveProfileTls, registerProfileTlsMode } from "../src/config/index.js";
import { BUILTIN_PROFILES, makeCustomProfile } from "../src/config/profiles.js";
import { saveConfig } from "../src/config/storage.js";
import { registerHostTls } from "../src/network/transport.js";

beforeEach(() => {
  vi.mocked(registerHostTls).mockClear();
  vi.mocked(saveConfig)({});
  vi.mocked(saveConfig).mockClear();
});

// -- registerProfileTlsMode ---------------------------------------------------

describe("registerProfileTlsMode", () => {
  it("calls registerHostTls with correct host and legacyTls=false", async () => {
    const profile = makeCustomProfile("https://example.com/SAPIWS/DSS.asmx");

    await registerProfileTlsMode(profile);

    expect(registerHostTls).toHaveBeenCalledWith("example.com", false);
  });

  it("calls registerHostTls with legacyTls=true for ekeng profile", async () => {
    const ekeng = BUILTIN_PROFILES.get("ekeng");
    if (ekeng === undefined) {
      expect.unreachable("ekeng profile should exist");
      return;
    }

    await registerProfileTlsMode(ekeng);

    expect(registerHostTls).toHaveBeenCalledWith("ca.gov.am", true);
  });
});

// -- registerActiveProfileTls -------------------------------------------------

describe("registerActiveProfileTls", () => {
  it("registers TLS mode for the active profile", async () => {
    vi.mocked(saveConfig)({
      profile: "ekeng",
      url: "https://ca.gov.am:8080/SAPIWS/DSS.asmx",
    });
    vi.mocked(saveConfig).mockClear();

    await registerActiveProfileTls();

    expect(registerHostTls).toHaveBeenCalledWith("ca.gov.am", true);
  });

  it("does nothing when no active profile exists", async () => {
    // store is empty, so getActiveProfile returns null
    await registerActiveProfileTls();

    expect(registerHostTls).not.toHaveBeenCalled();
  });

  it("registers TLS mode for custom profile", async () => {
    vi.mocked(saveConfig)({ url: "https://custom.example.com/api" });
    vi.mocked(saveConfig).mockClear();

    await registerActiveProfileTls();

    expect(registerHostTls).toHaveBeenCalledWith("custom.example.com", false);
  });
});
