// SPDX-License-Identifier: Apache-2.0
/**
 * Low-level config file I/O for Revenant.
 *
 * Handles reading, writing, and validating the on-disk config.json.
 */

import { chmodSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { z } from "zod";
import { MAX_TIMEOUT, MIN_TIMEOUT } from "../constants.js";
import { isNodeError } from "../errors.js";
import { logger } from "../logger.js";

export const CONFIG_DIR = join(homedir(), ".revenant");
export const CONFIG_FILE = join(CONFIG_DIR, "config.json");

const ConfigSchema = z.object({
  profile: z.string().optional(),
  url: z.string().optional(),
  timeout: z.number().int().min(MIN_TIMEOUT).max(MAX_TIMEOUT).optional(),
  username: z.string().optional(),
  password: z.string().optional(),
  name: z.string().optional(),
  email: z.string().optional(),
  organization: z.string().optional(),
  dn: z.string().optional(),
});

export type ConfigDict = z.infer<typeof ConfigSchema>;

const RawConfigSchema = z.record(z.string(), z.unknown());

export function loadRawConfig(): Record<string, unknown> {
  try {
    const text = readFileSync(CONFIG_FILE, "utf-8");
    const data: unknown = JSON.parse(text);
    const parsed = RawConfigSchema.safeParse(data);
    if (parsed.success) {
      return parsed.data;
    }
  } catch (err) {
    if (err instanceof SyntaxError) {
      logger.warn(`Config file corrupted, ignoring: ${err.message}`);
    } else if (isNodeError(err) && err.code !== "ENOENT") {
      logger.warn(`Cannot read config file: ${err.message}`);
    }
  }
  return {};
}

export function loadConfig(): ConfigDict {
  const raw = loadRawConfig();
  const result = ConfigSchema.safeParse(raw);
  if (result.success) {
    return result.data;
  }
  // On validation failure, return empty config rather than crashing
  return {};
}

export function saveConfig(config: Record<string, unknown>): void {
  mkdirSync(CONFIG_DIR, { recursive: true, mode: 0o700 });

  if (process.platform !== "win32") {
    try {
      chmodSync(CONFIG_DIR, 0o700);
    } catch {
      logger.warn(`Failed to set restrictive permissions on ${CONFIG_DIR}`);
    }
  }

  const content = `${JSON.stringify(config, null, 2)}\n`;
  writeFileSync(CONFIG_FILE, content, { encoding: "utf-8", mode: 0o600 });

  if (process.platform !== "win32") {
    try {
      chmodSync(CONFIG_FILE, 0o600);
    } catch {
      logger.warn(`Failed to set restrictive permissions on ${CONFIG_FILE}`);
    }
  }
}
