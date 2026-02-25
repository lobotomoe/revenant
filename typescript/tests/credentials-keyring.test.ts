/**
 * Tests for credential management when keytar IS available.
 *
 * This file tests the keyring-present code paths in credentials.ts:
 * getPassword from keyring, savePassword to keyring, deletePassword,
 * fallback on keyring failure, and migratePlaintextPassword.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const mockKeytar = {
  getPassword: vi.fn(),
  setPassword: vi.fn(),
  deletePassword: vi.fn(),
};

vi.mock("keytar", () => ({
  default: mockKeytar,
  ...mockKeytar,
}));

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

vi.mock("../src/logger.js", () => ({
  logger: {
    warn: vi.fn(),
    info: vi.fn(),
  },
}));

import {
  clearCredentials,
  clearSessionCredentials,
  getCredentialStorageInfo,
  getCredentials,
  isKeyringAvailable,
  saveCredentials,
} from "../src/config/credentials.js";
import { loadConfig, loadRawConfig, saveConfig } from "../src/config/storage.js";
import { logger } from "../src/logger.js";

beforeEach(() => {
  vi.mocked(saveConfig)({});
  vi.mocked(saveConfig).mockClear();
  vi.mocked(loadConfig).mockClear();
  vi.mocked(loadRawConfig).mockClear();
  vi.mocked(logger.warn).mockClear();
  mockKeytar.getPassword.mockReset();
  mockKeytar.setPassword.mockReset();
  mockKeytar.deletePassword.mockReset();
  clearSessionCredentials();
});

afterEach(() => {
  delete process.env.REVENANT_USER;
  delete process.env.REVENANT_PASS;
});

// -- isKeyringAvailable -------------------------------------------------------

describe("isKeyringAvailable (keytar present)", () => {
  it("returns true when keytar works", async () => {
    const available = await isKeyringAvailable();
    expect(available).toBe(true);
  });
});

// -- getCredentialStorageInfo --------------------------------------------------

describe("getCredentialStorageInfo (keytar present)", () => {
  const originalPlatform = process.platform;

  afterEach(() => {
    Object.defineProperty(process, "platform", { value: originalPlatform });
  });

  it("returns macOS Keychain on darwin", async () => {
    Object.defineProperty(process, "platform", { value: "darwin" });
    const info = await getCredentialStorageInfo();
    expect(info).toBe("macOS Keychain");
  });

  it("returns Windows Credential Manager on win32", async () => {
    Object.defineProperty(process, "platform", { value: "win32" });
    const info = await getCredentialStorageInfo();
    expect(info).toBe("Windows Credential Manager");
  });

  it("returns Linux Secret Service on linux", async () => {
    Object.defineProperty(process, "platform", { value: "linux" });
    const info = await getCredentialStorageInfo();
    expect(info).toBe("Linux Secret Service");
  });
});

// -- getCredentials -----------------------------------------------------------

describe("getCredentials (keytar present)", () => {
  it("returns password from keyring", async () => {
    vi.mocked(loadConfig).mockReturnValue({ username: "alice" });
    vi.mocked(loadRawConfig).mockReturnValue({ username: "alice" });
    mockKeytar.getPassword.mockResolvedValueOnce("keyring-password");

    const creds = await getCredentials();
    expect(creds.username).toBe("alice");
    expect(creds.password).toBe("keyring-password");
    expect(mockKeytar.getPassword).toHaveBeenCalledWith("revenant", "alice");
  });

  it("falls back to config when keyring read fails", async () => {
    vi.mocked(loadConfig).mockReturnValue({
      username: "bob",
      password: "config-pass",
    });
    vi.mocked(loadRawConfig).mockReturnValue({
      username: "bob",
      password: "config-pass",
    });
    mockKeytar.getPassword.mockRejectedValueOnce(new Error("keyring error"));

    const creds = await getCredentials();
    expect(creds.username).toBe("bob");
    expect(creds.password).toBe("config-pass");
  });

  it("falls back to config when keyring returns null", async () => {
    vi.mocked(loadConfig).mockReturnValue({
      username: "carol",
      password: "config-secret",
    });
    vi.mocked(loadRawConfig).mockReturnValue({
      username: "carol",
      password: "config-secret",
    });
    mockKeytar.getPassword.mockResolvedValueOnce(null);

    const creds = await getCredentials();
    expect(creds.username).toBe("carol");
    expect(creds.password).toBe("config-secret");
  });

  it("returns nulls when no username in config", async () => {
    vi.mocked(loadConfig).mockReturnValue({});
    vi.mocked(loadRawConfig).mockReturnValue({});

    const creds = await getCredentials();
    expect(creds.username).toBeNull();
    expect(creds.password).toBeNull();
  });
});

// -- saveCredentials ----------------------------------------------------------

describe("saveCredentials (keytar present)", () => {
  it("saves to keyring and returns true", async () => {
    vi.mocked(loadRawConfig).mockReturnValue({});
    mockKeytar.setPassword.mockResolvedValueOnce(undefined);

    const usedKeyring = await saveCredentials("alice", "secret");
    expect(usedKeyring).toBe(true);
    expect(mockKeytar.setPassword).toHaveBeenCalledWith("revenant", "alice", "secret");
    expect(saveConfig).toHaveBeenCalled();
  });

  it("removes password from config when saving to keyring", async () => {
    const store: Record<string, unknown> = { password: "old-plaintext" };
    vi.mocked(loadRawConfig).mockReturnValue(store);
    mockKeytar.setPassword.mockResolvedValueOnce(undefined);

    await saveCredentials("alice", "secret");

    const saveArgs = vi.mocked(saveConfig).mock.calls[0];
    if (saveArgs === undefined) {
      expect.unreachable("saveConfig should have been called");
      return;
    }
    // password should be deleted from config when saved to keyring
    expect(saveArgs[0]).not.toHaveProperty("password");
  });

  it("deletes old keyring entry when username changes", async () => {
    vi.mocked(loadRawConfig).mockReturnValue({ username: "old-user" });
    mockKeytar.deletePassword.mockResolvedValueOnce(true);
    mockKeytar.setPassword.mockResolvedValueOnce(undefined);

    await saveCredentials("new-user", "new-pass");

    expect(mockKeytar.deletePassword).toHaveBeenCalledWith("revenant", "old-user");
    expect(mockKeytar.setPassword).toHaveBeenCalledWith("revenant", "new-user", "new-pass");
  });

  it("does not delete old entry when username is the same", async () => {
    vi.mocked(loadRawConfig).mockReturnValue({ username: "same-user" });
    mockKeytar.setPassword.mockResolvedValueOnce(undefined);

    await saveCredentials("same-user", "new-pass");

    expect(mockKeytar.deletePassword).not.toHaveBeenCalled();
  });

  it("ignores deletePassword failure when username changes", async () => {
    vi.mocked(loadRawConfig).mockReturnValue({ username: "old-user" });
    mockKeytar.deletePassword.mockRejectedValueOnce(new Error("delete failed"));
    mockKeytar.setPassword.mockResolvedValueOnce(undefined);

    const usedKeyring = await saveCredentials("new-user", "new-pass");
    expect(usedKeyring).toBe(true);
  });

  it("falls back to config when keyring save fails", async () => {
    vi.mocked(loadRawConfig).mockReturnValue({});
    mockKeytar.setPassword.mockRejectedValueOnce(new Error("keyring write error"));

    const usedKeyring = await saveCredentials("alice", "secret");
    expect(usedKeyring).toBe(false);
    expect(logger.warn).toHaveBeenCalled();

    const saveArgs = vi.mocked(saveConfig).mock.calls[0];
    if (saveArgs === undefined) {
      expect.unreachable("saveConfig should have been called");
      return;
    }
    expect(saveArgs[0]).toHaveProperty("password", "secret");
  });
});

// -- clearCredentials ---------------------------------------------------------

describe("clearCredentials (keytar present)", () => {
  it("deletes from keyring", async () => {
    const store: Record<string, unknown> = {
      username: "alice",
      password: "plaintext",
      url: "https://example.com",
    };
    vi.mocked(loadRawConfig).mockReturnValue(store);
    mockKeytar.deletePassword.mockResolvedValueOnce(true);

    await clearCredentials();

    expect(mockKeytar.deletePassword).toHaveBeenCalledWith("revenant", "alice");
    expect(saveConfig).toHaveBeenCalled();
  });

  it("ignores keyring deletePassword failure", async () => {
    const store: Record<string, unknown> = { username: "alice" };
    vi.mocked(loadRawConfig).mockReturnValue(store);
    mockKeytar.deletePassword.mockRejectedValueOnce(new Error("keyring error"));

    await clearCredentials();
    expect(saveConfig).toHaveBeenCalled();
  });

  it("skips keyring delete when no username in config", async () => {
    vi.mocked(loadRawConfig).mockReturnValue({});

    await clearCredentials();
    expect(mockKeytar.deletePassword).not.toHaveBeenCalled();
    expect(saveConfig).toHaveBeenCalled();
  });
});

// -- migratePlaintextPassword -------------------------------------------------

describe("migratePlaintextPassword (via getCredentials)", () => {
  it("removes plaintext password from config when keyring has password", async () => {
    const store: Record<string, unknown> = {
      username: "alice",
      password: "plaintext-secret",
    };
    vi.mocked(loadConfig).mockReturnValue({
      username: "alice",
      password: "plaintext-secret",
    });
    vi.mocked(loadRawConfig).mockReturnValue(store);

    // migratePlaintextPassword checks keyring, finds password -> removes plaintext
    mockKeytar.getPassword.mockResolvedValue("keyring-password");

    await getCredentials();

    // saveConfig should have been called to remove plaintext password
    expect(saveConfig).toHaveBeenCalled();
    // The store should have password removed
    expect("password" in store).toBe(false);
  });

  it("keeps plaintext when keyring getPassword fails during migration", async () => {
    const store: Record<string, unknown> = {
      username: "bob",
      password: "plaintext-pw",
    };
    vi.mocked(loadConfig).mockReturnValue({
      username: "bob",
      password: "plaintext-pw",
    });
    vi.mocked(loadRawConfig).mockReturnValue(store);

    // First call during migration - fails
    // Second call during getCredentials - also fails
    mockKeytar.getPassword.mockRejectedValue(new Error("keyring unavailable"));

    await getCredentials();

    // password should NOT have been removed from store (migration failed)
    // getCredentials itself falls back to config
    expect(store.password).toBe("plaintext-pw");
  });

  it("does not migrate when no plaintext password exists", async () => {
    vi.mocked(loadConfig).mockReturnValue({ username: "carol" });
    vi.mocked(loadRawConfig).mockReturnValue({ username: "carol" });
    mockKeytar.getPassword.mockResolvedValueOnce("keyring-pw");

    await getCredentials();

    // saveConfig should not have been called for migration (no plaintext to remove)
    // but getCredentials may still read from keyring normally
    expect(mockKeytar.getPassword).toHaveBeenCalledWith("revenant", "carol");
  });
});
