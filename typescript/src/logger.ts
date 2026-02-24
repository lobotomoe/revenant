// SPDX-License-Identifier: Apache-2.0
/**
 * Minimal logger for library code.
 *
 * Library code must never write to stdout/stderr directly -- it breaks
 * consumers who pipe output or run in serverless environments.
 *
 * By default warnings go to console.warn. Consumers can replace or
 * silence the handler via setLogHandler / setLogLevel.
 */

export type LogLevel = "silent" | "warn" | "info";

export type LogHandler = (level: LogLevel, message: string) => void;

const DEFAULT_HANDLER: LogHandler = (_level, message) => {
  console.warn(message);
};

let handler: LogHandler = DEFAULT_HANDLER;
let currentLevel: LogLevel = "warn";

const LEVEL_PRIORITY: Record<LogLevel, number> = {
  silent: 0,
  warn: 1,
  info: 2,
};

/** Replace the log handler. Pass null to restore the default. */
export function setLogHandler(h: LogHandler | null): void {
  handler = h ?? DEFAULT_HANDLER;
}

/** Set the minimum log level. "silent" suppresses all output. */
export function setLogLevel(level: LogLevel): void {
  currentLevel = level;
}

function shouldLog(level: LogLevel): boolean {
  return LEVEL_PRIORITY[level] <= LEVEL_PRIORITY[currentLevel];
}

export const logger = {
  warn(message: string): void {
    if (shouldLog("warn")) {
      handler("warn", message);
    }
  },
  info(message: string): void {
    if (shouldLog("info")) {
      handler("info", message);
    }
  },
};
