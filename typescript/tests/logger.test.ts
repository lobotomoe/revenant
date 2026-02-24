/**
 * Tests for the logger module.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { logger, setLogHandler, setLogLevel } from "../src/logger.js";

afterEach(() => {
  setLogHandler(null);
  setLogLevel("warn");
});

describe("logger.warn", () => {
  it("calls handler when level is 'warn' (default)", () => {
    const handler = vi.fn();
    setLogHandler(handler);

    logger.warn("test warning");

    expect(handler).toHaveBeenCalledOnce();
    expect(handler).toHaveBeenCalledWith("warn", "test warning");
  });

  it("is suppressed when level is 'silent'", () => {
    const handler = vi.fn();
    setLogHandler(handler);
    setLogLevel("silent");

    logger.warn("should not appear");

    expect(handler).not.toHaveBeenCalled();
  });
});

describe("logger.info", () => {
  it("calls handler when level is 'info'", () => {
    const handler = vi.fn();
    setLogHandler(handler);
    setLogLevel("info");

    logger.info("test info");

    expect(handler).toHaveBeenCalledOnce();
    expect(handler).toHaveBeenCalledWith("info", "test info");
  });

  it("is suppressed when level is 'warn' (default)", () => {
    const handler = vi.fn();
    setLogHandler(handler);

    logger.info("should not appear");

    expect(handler).not.toHaveBeenCalled();
  });

  it("is suppressed when level is 'silent'", () => {
    const handler = vi.fn();
    setLogHandler(handler);
    setLogLevel("silent");

    logger.info("should not appear");

    expect(handler).not.toHaveBeenCalled();
  });
});

describe("setLogHandler", () => {
  it("restores default handler when passed null", () => {
    const custom = vi.fn();
    setLogHandler(custom);
    setLogHandler(null);

    // Default handler calls console.warn - spy on it
    const consoleSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    logger.warn("after restore");

    expect(custom).not.toHaveBeenCalled();
    expect(consoleSpy).toHaveBeenCalledWith("after restore");

    consoleSpy.mockRestore();
  });

  it("custom handler receives correct level and message", () => {
    const handler = vi.fn();
    setLogHandler(handler);
    setLogLevel("info");

    logger.warn("a warning");
    logger.info("some info");

    expect(handler).toHaveBeenCalledTimes(2);
    expect(handler).toHaveBeenNthCalledWith(1, "warn", "a warning");
    expect(handler).toHaveBeenNthCalledWith(2, "info", "some info");
  });
});

describe("setLogLevel", () => {
  it("'info' level allows both warn and info", () => {
    const handler = vi.fn();
    setLogHandler(handler);
    setLogLevel("info");

    logger.warn("w");
    logger.info("i");

    expect(handler).toHaveBeenCalledTimes(2);
  });

  it("'warn' level allows warn but not info", () => {
    const handler = vi.fn();
    setLogHandler(handler);
    setLogLevel("warn");

    logger.warn("w");
    logger.info("i");

    expect(handler).toHaveBeenCalledOnce();
    expect(handler).toHaveBeenCalledWith("warn", "w");
  });

  it("'silent' level suppresses everything", () => {
    const handler = vi.fn();
    setLogHandler(handler);
    setLogLevel("silent");

    logger.warn("w");
    logger.info("i");

    expect(handler).not.toHaveBeenCalled();
  });
});
