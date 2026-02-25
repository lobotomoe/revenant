/**
 * Tests for credential management.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../src/config/storage.js", () => {
  let store: Record<string, unknown> = {};
  return {
    loadConfig: vi.fn(() => ({ ...store })),
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
  clearCredentials,
  clearSessionCredentials,
  getCredentialStorageInfo,
  getCredentials,
  getSavedUsername,
  isKeyringAvailable,
  resolveCredentials,
  saveCredentials,
  setSessionCredentials,
} from "../src/config/credentials.js";
import { loadConfig, loadRawConfig, saveConfig } from "../src/config/storage.js";

/**
 * Reset all mock implementations to factory defaults before each test.
 * This prevents mockReturnValue/mockImplementation leaking between tests.
 */
beforeEach(() => {
  vi.restoreAllMocks();
  clearSessionCredentials();
  delete process.env.REVENANT_USER;
  delete process.env.REVENANT_PASS;
});

afterEach(() => {
  delete process.env.REVENANT_USER;
  delete process.env.REVENANT_PASS;
});

// -- Session credentials ------------------------------------------------------

describe("session credentials", () => {
  it("setSessionCredentials stores credentials that resolveCredentials returns", () => {
    setSessionCredentials("alice", "secret123");
    const creds = resolveCredentials();
    expect(creds.username).toBe("alice");
    expect(creds.password).toBe("secret123");
  });

  it("clearSessionCredentials clears stored session credentials", () => {
    setSessionCredentials("alice", "secret123");
    clearSessionCredentials();
    const creds = resolveCredentials();
    expect(creds.username).toBe("");
    expect(creds.password).toBe("");
  });

  it("resolveCredentials prioritizes env vars over session", () => {
    setSessionCredentials("session-user", "session-pass");
    process.env.REVENANT_USER = "env-user";
    process.env.REVENANT_PASS = "env-pass";

    const creds = resolveCredentials();
    expect(creds.username).toBe("env-user");
    expect(creds.password).toBe("env-pass");
  });

  it("resolveCredentials uses session when env vars are empty strings", () => {
    setSessionCredentials("session-user", "session-pass");
    process.env.REVENANT_USER = "  ";
    process.env.REVENANT_PASS = "  ";

    const creds = resolveCredentials();
    expect(creds.username).toBe("session-user");
    expect(creds.password).toBe("session-pass");
  });

  it("resolveCredentials falls back to config file", () => {
    vi.mocked(loadConfig).mockReturnValueOnce({
      username: "config-user",
      password: "config-pass",
    });

    const creds = resolveCredentials();
    expect(creds.username).toBe("config-user");
    expect(creds.password).toBe("config-pass");
  });

  it("resolveCredentials returns empty strings when nothing is available", () => {
    const creds = resolveCredentials();
    expect(creds.username).toBe("");
    expect(creds.password).toBe("");
  });

  it("resolveCredentials mixes env username with session password", () => {
    setSessionCredentials("session-user", "session-pass");
    process.env.REVENANT_USER = "env-user";

    const creds = resolveCredentials();
    expect(creds.username).toBe("env-user");
    expect(creds.password).toBe("session-pass");
  });
});

// -- isKeyringAvailable -------------------------------------------------------

describe("isKeyringAvailable", () => {
  it("returns false when keytar is unavailable", async () => {
    const available = await isKeyringAvailable();
    expect(available).toBe(false);
  });
});

// -- getCredentialStorageInfo --------------------------------------------------

describe("getCredentialStorageInfo", () => {
  it("returns config file path when keyring is unavailable", async () => {
    const info = await getCredentialStorageInfo();
    expect(info).toContain("/tmp/test-revenant/config.json");
    expect(info).toContain("plaintext");
  });
});

// -- getSavedUsername ----------------------------------------------------------

describe("getSavedUsername", () => {
  it("returns null when config has no username", () => {
    const username = getSavedUsername();
    expect(username).toBeNull();
  });

  it("returns saved username from config", () => {
    vi.mocked(loadConfig).mockReturnValueOnce({ username: "saved-user" });
    const username = getSavedUsername();
    expect(username).toBe("saved-user");
  });
});

// -- getCredentials (async) ---------------------------------------------------

describe("getCredentials (async)", () => {
  it("returns nulls when no username in config", async () => {
    const creds = await getCredentials();
    expect(creds.username).toBeNull();
    expect(creds.password).toBeNull();
  });

  it("returns username and password from config when keyring unavailable", async () => {
    vi.mocked(loadConfig).mockReturnValue({
      username: "stored-user",
      password: "stored-pass",
    });

    const creds = await getCredentials();
    expect(creds.username).toBe("stored-user");
    expect(creds.password).toBe("stored-pass");
  });

  it("returns username with null password when password not in config", async () => {
    vi.mocked(loadConfig).mockReturnValue({ username: "stored-user" });

    const creds = await getCredentials();
    expect(creds.username).toBe("stored-user");
    expect(creds.password).toBeNull();
  });
});

// -- saveCredentials ----------------------------------------------------------

describe("saveCredentials", () => {
  it("saves username and password to config file when keyring unavailable", async () => {
    const usedKeyring = await saveCredentials("new-user", "new-pass");
    expect(usedKeyring).toBe(false);
    expect(saveConfig).toHaveBeenCalledWith(
      expect.objectContaining({
        username: "new-user",
        password: "new-pass",
      }),
    );
  });
});

// -- clearCredentials ---------------------------------------------------------

describe("clearCredentials", () => {
  it("removes username and password from config", async () => {
    // Seed the in-memory store with credentials
    const store: Record<string, unknown> = {
      username: "old-user",
      password: "old-pass",
      url: "https://example.com",
    };
    vi.mocked(loadRawConfig).mockReturnValue(store);

    await clearCredentials();

    // clearCredentials calls delete on the object, then saveConfig
    expect(saveConfig).toHaveBeenCalled();
    // After delete, the store object should not have username/password
    expect("username" in store).toBe(false);
    expect("password" in store).toBe(false);
  });
});
