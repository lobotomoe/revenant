/**
 * Tests for config/storage.ts with mocked node:fs.
 *
 * Covers loadRawConfig error paths (SyntaxError, non-ENOENT errors),
 * loadConfig validation failure, and saveConfig file operations.
 */

import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("node:fs", () => ({
  readFileSync: vi.fn(),
  writeFileSync: vi.fn(),
  mkdirSync: vi.fn(),
  chmodSync: vi.fn(),
}));

vi.mock("../src/logger.js", () => ({
  logger: {
    warn: vi.fn(),
    info: vi.fn(),
  },
}));

import { chmodSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import {
  CONFIG_DIR,
  CONFIG_FILE,
  loadConfig,
  loadRawConfig,
  saveConfig,
} from "../src/config/storage.js";
import { logger } from "../src/logger.js";

beforeEach(() => {
  vi.mocked(readFileSync).mockReset();
  vi.mocked(writeFileSync).mockReset();
  vi.mocked(mkdirSync).mockReset();
  vi.mocked(chmodSync).mockReset();
  vi.mocked(logger.warn).mockReset();
});

// -- loadRawConfig ------------------------------------------------------------

describe("loadRawConfig", () => {
  it("returns parsed data on valid JSON", () => {
    vi.mocked(readFileSync).mockReturnValueOnce('{"url":"https://example.com","timeout":60}');

    const result = loadRawConfig();
    expect(result).toEqual({ url: "https://example.com", timeout: 60 });
  });

  it("returns {} when file does not exist (ENOENT)", () => {
    const error = new Error("ENOENT: no such file or directory");
    Object.assign(error, { code: "ENOENT" });
    vi.mocked(readFileSync).mockImplementationOnce(() => {
      throw error;
    });

    const result = loadRawConfig();
    expect(result).toEqual({});
    expect(logger.warn).not.toHaveBeenCalled();
  });

  it("returns {} and logs warning on SyntaxError (corrupted JSON)", () => {
    vi.mocked(readFileSync).mockReturnValueOnce("{invalid json}}}");

    const result = loadRawConfig();
    expect(result).toEqual({});
    expect(logger.warn).toHaveBeenCalledOnce();
    const warnMsg = vi.mocked(logger.warn).mock.calls[0];
    if (warnMsg === undefined) {
      expect.unreachable("logger.warn should have been called");
      return;
    }
    expect(warnMsg[0]).toContain("corrupted");
  });

  it("returns {} and logs warning on non-ENOENT error (e.g., EACCES)", () => {
    const error = new Error("EACCES: permission denied");
    Object.assign(error, { code: "EACCES" });
    vi.mocked(readFileSync).mockImplementationOnce(() => {
      throw error;
    });

    const result = loadRawConfig();
    expect(result).toEqual({});
    expect(logger.warn).toHaveBeenCalledOnce();
    const warnMsg = vi.mocked(logger.warn).mock.calls[0];
    if (warnMsg === undefined) {
      expect.unreachable("logger.warn should have been called");
      return;
    }
    expect(warnMsg[0]).toContain("Cannot read config file");
  });

  it("returns {} when JSON parses to non-object (e.g., array)", () => {
    vi.mocked(readFileSync).mockReturnValueOnce("[1, 2, 3]");

    const result = loadRawConfig();
    expect(result).toEqual({});
  });

  it("returns {} when JSON parses to null", () => {
    vi.mocked(readFileSync).mockReturnValueOnce("null");

    const result = loadRawConfig();
    expect(result).toEqual({});
  });
});

// -- loadConfig ---------------------------------------------------------------

describe("loadConfig", () => {
  it("returns validated config on valid data", () => {
    vi.mocked(readFileSync).mockReturnValueOnce('{"url":"https://example.com","timeout":60}');

    const result = loadConfig();
    expect(result.url).toBe("https://example.com");
    expect(result.timeout).toBe(60);
  });

  it("returns {} on validation failure (e.g., timeout is a string)", () => {
    vi.mocked(readFileSync).mockReturnValueOnce('{"timeout":"not a number"}');

    const result = loadConfig();
    expect(result).toEqual({});
  });

  it("returns {} on validation failure (timeout out of range)", () => {
    vi.mocked(readFileSync).mockReturnValueOnce('{"timeout":-5}');

    const result = loadConfig();
    expect(result).toEqual({});
  });

  it("returns {} when raw config is empty", () => {
    const error = new Error("ENOENT: no such file or directory");
    Object.assign(error, { code: "ENOENT" });
    vi.mocked(readFileSync).mockImplementationOnce(() => {
      throw error;
    });

    const result = loadConfig();
    expect(result).toEqual({});
  });
});

// -- saveConfig ---------------------------------------------------------------

describe("saveConfig", () => {
  const originalPlatform = process.platform;

  afterEach(() => {
    Object.defineProperty(process, "platform", { value: originalPlatform });
  });

  it("creates directory and writes JSON file", () => {
    saveConfig({ url: "https://example.com" });

    expect(mkdirSync).toHaveBeenCalledWith(CONFIG_DIR, { recursive: true, mode: 0o700 });
    expect(writeFileSync).toHaveBeenCalledOnce();

    const writeArgs = vi.mocked(writeFileSync).mock.calls[0];
    if (writeArgs === undefined) {
      expect.unreachable("writeFileSync should have been called");
      return;
    }
    expect(writeArgs[0]).toBe(CONFIG_FILE);
    const content = writeArgs[1];
    if (typeof content !== "string") {
      expect.unreachable("content should be a string");
      return;
    }
    expect(content).toContain('"url": "https://example.com"');
    expect(content.endsWith("\n")).toBe(true);
    expect(writeArgs[2]).toEqual({ encoding: "utf-8", mode: 0o600 });
  });

  it("calls chmodSync on directory and file on non-Windows", () => {
    Object.defineProperty(process, "platform", { value: "linux" });

    saveConfig({ timeout: 30 });

    expect(chmodSync).toHaveBeenCalledTimes(2);
    expect(chmodSync).toHaveBeenCalledWith(CONFIG_DIR, 0o700);
    expect(chmodSync).toHaveBeenCalledWith(CONFIG_FILE, 0o600);
  });

  it("skips chmodSync on Windows", () => {
    Object.defineProperty(process, "platform", { value: "win32" });

    saveConfig({ timeout: 30 });

    expect(chmodSync).not.toHaveBeenCalled();
  });

  it("logs warning when chmodSync fails on directory", () => {
    Object.defineProperty(process, "platform", { value: "darwin" });
    vi.mocked(chmodSync).mockImplementationOnce(() => {
      throw new Error("chmod failed");
    });

    saveConfig({ url: "https://test.com" });

    expect(logger.warn).toHaveBeenCalled();
    const warnMsg = vi.mocked(logger.warn).mock.calls[0];
    if (warnMsg === undefined) {
      expect.unreachable("logger.warn should have been called");
      return;
    }
    expect(warnMsg[0]).toContain("Failed to set restrictive permissions");
  });

  it("logs warning when chmodSync fails on file", () => {
    Object.defineProperty(process, "platform", { value: "darwin" });
    // First call (directory) succeeds, second call (file) fails
    vi.mocked(chmodSync)
      .mockImplementationOnce(() => {})
      .mockImplementationOnce(() => {
        throw new Error("chmod failed on file");
      });

    saveConfig({ url: "https://test.com" });

    expect(logger.warn).toHaveBeenCalledOnce();
    const warnMsg = vi.mocked(logger.warn).mock.calls[0];
    if (warnMsg === undefined) {
      expect.unreachable("logger.warn should have been called");
      return;
    }
    expect(warnMsg[0]).toContain("Failed to set restrictive permissions");
    expect(warnMsg[0]).toContain(CONFIG_FILE);
  });

  it("writes pretty-printed JSON with trailing newline", () => {
    saveConfig({ url: "https://x.com", timeout: 10 });

    const writeArgs = vi.mocked(writeFileSync).mock.calls[0];
    if (writeArgs === undefined) {
      expect.unreachable("writeFileSync should have been called");
      return;
    }
    const content = writeArgs[1];
    if (typeof content !== "string") {
      expect.unreachable("content should be a string");
      return;
    }

    const parsed: unknown = JSON.parse(content);
    expect(parsed).toEqual({ url: "https://x.com", timeout: 10 });
    // Indented (pretty-printed)
    expect(content).toContain("  ");
    expect(content.endsWith("\n")).toBe(true);
  });
});
