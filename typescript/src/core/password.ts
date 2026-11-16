// SPDX-License-Identifier: Apache-2.0
/**
 * Changing the signing account's password.
 *
 * The request itself is one logon carrying the new password. What this module
 * adds is the part a caller would otherwise get wrong: a new password that
 * would lock the user out of a client is refused before it is sent, and the
 * outcome is settled by logging on with the new password, so the caller only
 * replaces a stored password with one the server is known to accept.
 */

import { AuthError, getErrorMessage, RevenantError, ServerError } from "../errors.js";
import { logger } from "../logger.js";
import {
  enumCertificates,
  changePassword as sendChangePassword,
} from "../network/soap-transport.js";

/** Why a new password cannot be sent to the server. */
export type NewPasswordProblem =
  | "empty"
  | "same-as-current"
  /**
   * Every client trims the password it reads at login, so such a password
   * could never be entered again.
   */
  | "surrounding-whitespace"
  /** The profile issues ASCII-only credentials; the desktop login form enforces it. */
  | "non-ascii";

const PROBLEM_MESSAGES: Record<NewPasswordProblem, string> = {
  empty: "The new password is empty.",
  "same-as-current": "The new password is the same as the current one.",
  "surrounding-whitespace": "The new password must not begin or end with a space.",
  "non-ascii": "The new password may only contain Latin letters, digits and symbols.",
};

export function describeNewPasswordProblem(problem: NewPasswordProblem): string {
  return PROBLEM_MESSAGES[problem];
}

const ASCII_MAX_CHAR_CODE = 0x7f;

function isAscii(text: string): boolean {
  for (let index = 0; index < text.length; index++) {
    if (text.charCodeAt(index) > ASCII_MAX_CHAR_CODE) return false;
  }
  return true;
}

/**
 * Check a new password before sending it. Returns the first problem found, or
 * null if the password can be sent. `asciiOnly` is the server profile's
 * `asciiCredentialsOnly`.
 *
 * The server's own password policy is not known to the client and is not
 * checked here; a password it refuses comes back as ServerError from
 * `changePassword`.
 */
export function checkNewPassword(
  current: string,
  next: string,
  asciiOnly: boolean,
): NewPasswordProblem | null {
  if (next === "") return "empty";
  if (next !== next.trim()) return "surrounding-whitespace";
  if (next === current) return "same-as-current";
  if (asciiOnly && !isAscii(next)) return "non-ascii";
  return null;
}

/**
 * Explain a new password the server refused, as far as the profile allows.
 *
 * Returns the profile's observed minimum length when the password is shorter
 * than it: the one reason for a refusal the client can name. null means the
 * reason is not known, not that the password was fine.
 */
export function shorterThanObservedMinimum(
  newPassword: string,
  observedMinLength: number | null,
): number | null {
  if (observedMinLength === null) return null;
  return [...newPassword].length < observedMinLength ? observedMinLength : null;
}

/** How a password change ended when it did not fail outright. */
export type PasswordChange =
  /** The server accepts the new password: a logon with it succeeded. */
  | { readonly confirmed: true }
  /**
   * The request went out, but no logon with the new password could be
   * completed afterwards, so which password is in force is not known.
   * `reason` is the connection failure that left it open.
   */
  | { readonly confirmed: false; readonly reason: string };

/**
 * Change the password and confirm the result by logging on with the new one.
 *
 * The confirming logon covers two things the change request alone cannot tell
 * apart. A server that ignores NewLogonPassword answers the request with the
 * same success as one that applied it. And a connection lost after the request
 * was sent says nothing about whether it was applied.
 *
 * Throws AuthError when the current password is wrong, ServerError when the
 * server refused the new password or reported success without putting it in
 * force. Any other error means the request failed and a logon with the new
 * password was refused, so the old password is still in force.
 */
export async function changePassword(
  url: string,
  username: string,
  password: string,
  newPassword: string,
  timeout: number,
): Promise<PasswordChange> {
  try {
    await sendChangePassword(url, username, password, newPassword, timeout);
  } catch (requestError) {
    if (requestError instanceof AuthError || requestError instanceof ServerError) {
      throw requestError;
    }
    if (!(requestError instanceof RevenantError)) throw requestError;
    return settleInterruptedChange(url, username, newPassword, timeout, requestError);
  }
  return confirmAcceptedChange(url, username, newPassword, timeout);
}

/** The server answered with success: check the new password is in force. */
async function confirmAcceptedChange(
  url: string,
  username: string,
  newPassword: string,
  timeout: number,
): Promise<PasswordChange> {
  try {
    await enumCertificates(url, username, newPassword, timeout);
  } catch (e) {
    if (e instanceof AuthError) {
      throw new ServerError(
        "The server reported success but does not accept the new password. " +
          "The password was not changed.",
      );
    }
    if (!(e instanceof RevenantError)) throw e;
    logger.warn(`Password change accepted, but the confirming logon failed: ${e.message}`);
    return { confirmed: false, reason: e.message };
  }
  return { confirmed: true };
}

/**
 * The request got no answer, so it may or may not have been applied. One logon
 * with the new password decides it.
 */
async function settleInterruptedChange(
  url: string,
  username: string,
  newPassword: string,
  timeout: number,
  requestError: RevenantError,
): Promise<PasswordChange> {
  logger.warn(
    `Password change request failed, checking whether it was applied: ${getErrorMessage(requestError)}`,
  );
  try {
    await enumCertificates(url, username, newPassword, timeout);
  } catch (e) {
    if (e instanceof AuthError) throw requestError;
    if (!(e instanceof RevenantError)) throw e;
    return { confirmed: false, reason: requestError.message };
  }
  return { confirmed: true };
}
