// SPDX-License-Identifier: Apache-2.0
/**
 * Change the account password on the signing server.
 */

import { AuthError, RevenantError, ServerError, TLSError } from "../errors.js";

function fail(message: string): never {
  process.stderr.write(`${message}\n`);
  process.exit(1);
}

export async function cmdPassword(): Promise<void> {
  const { changePassword } = await import("../api.js");
  const {
    applyPasswordChange,
    getActiveProfile,
    getCredentialStorageInfo,
    getCredentials,
    getServerConfig,
    resolveCredentials,
  } = await import("../config/index.js");
  const { checkNewPassword, describeNewPasswordProblem, shorterThanObservedMinimum } = await import(
    "../core/password.js"
  );
  const { printAuthFailure, promptCredentials, promptHidden } = await import("./helpers.js");

  const { url, timeout } = getServerConfig();
  if (!url || !timeout) {
    fail("Error: no server configured. Run 'revenant setup' first.");
  }
  const profile = getActiveProfile();

  // resolveCredentials reads the environment, the session and the config
  // file; the keychain is only reachable through the async getCredentials.
  const resolved = resolveCredentials();
  let username = resolved.username;
  let current = resolved.password;
  if (!username || !current) {
    const saved = await getCredentials();
    username = username || (saved.username ?? "");
    current = current || (saved.password ?? "");
  }
  if (!username || !current) {
    const prompted = await promptCredentials(username, current);
    username = prompted.username;
    current = prompted.password;
  }

  console.log(`Changing the password for ${username} on ${url}`);
  const newPassword = await promptHidden("New password: ");
  const repeated = await promptHidden("Repeat new password: ");
  if (newPassword !== repeated) {
    fail("Error: the two passwords do not match.");
  }
  const problem = checkNewPassword(current, newPassword, profile?.asciiCredentialsOnly ?? false);
  if (problem !== null) {
    fail(`Error: ${describeNewPasswordProblem(problem)}`);
  }

  let outcome: Awaited<ReturnType<typeof changePassword>>;
  try {
    outcome = await changePassword(username, current, newPassword);
  } catch (e) {
    if (e instanceof AuthError) {
      printAuthFailure(e, profile);
      process.exit(1);
    }
    if (e instanceof ServerError) {
      const minimum = shorterThanObservedMinimum(
        newPassword,
        profile?.observedMinPasswordLength ?? null,
      );
      const hint =
        minimum === null
          ? "It may not meet the server's password rules."
          : `It is shorter than ${minimum} characters, the shortest this server is known to accept.`;
      fail(`Error: ${e.message}\nThe password was not changed. ${hint}`);
    }
    if (e instanceof TLSError) {
      fail(`Error: connection failed: ${e.message}`);
    }
    if (e instanceof RevenantError) {
      fail(`Error: ${e.message}`);
    }
    throw e;
  }

  if (!outcome.confirmed) {
    fail(
      "The connection failed before the change could be confirmed:\n" +
        `  ${outcome.reason}\n` +
        "Either password may be the valid one now. Saved credentials were not\n" +
        "touched. Run 'revenant setup' and try the new password first.",
    );
  }

  console.log("Password changed.");
  const update = await applyPasswordChange(username, newPassword);
  if (update.saved) {
    console.log(`Saved credentials updated: ${await getCredentialStorageInfo()}`);
  }
  if (update.envOverride) {
    console.log("REVENANT_PASS is set and still holds the old password. Update it.");
  }
}
