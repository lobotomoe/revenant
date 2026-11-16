# SPDX-License-Identifier: Apache-2.0
"""
Changing the signing account's password.

The request itself is one logon carrying the new password. What this module
adds is the part a caller would otherwise get wrong: a new password that would
lock the user out of this client is refused before it is sent, and the outcome
is settled by logging on with the new password, so the caller only replaces a
stored password with one the server is known to accept.
"""

from __future__ import annotations

import enum
import logging
from dataclasses import dataclass

from ..errors import AuthError, RevenantError, ServerError
from ..network import soap_transport

_logger = logging.getLogger(__name__)


class NewPasswordProblem(enum.Enum):
    """Why a new password cannot be sent to the server."""

    EMPTY = "The new password is empty."
    SAME_AS_CURRENT = "The new password is the same as the current one."
    # Every client trims the password it reads at login, so such a password
    # could never be entered again.
    SURROUNDING_WHITESPACE = "The new password must not begin or end with a space."
    # The profile issues ASCII-only credentials, which the login form enforces.
    NON_ASCII = "The new password may only contain Latin letters, digits and symbols."


def check_new_password(current: str, new: str, ascii_only: bool) -> NewPasswordProblem | None:
    """Check a new password before sending it.

    The server's own password policy is not known to the client and is not
    checked here; a password it refuses comes back as ``ServerError`` from
    :func:`change_password`.

    Args:
        current: The current password.
        new: The password to change to.
        ascii_only: The server profile's ``ascii_credentials_only``.

    Returns:
        The first problem found, or None if the password can be sent.
    """
    if not new:
        return NewPasswordProblem.EMPTY
    if new != new.strip():
        return NewPasswordProblem.SURROUNDING_WHITESPACE
    if new == current:
        return NewPasswordProblem.SAME_AS_CURRENT
    if ascii_only and not new.isascii():
        return NewPasswordProblem.NON_ASCII
    return None


def shorter_than_observed_minimum(new_password: str, observed_min_length: int | None) -> int | None:
    """Explain a new password the server refused, as far as the profile allows.

    Args:
        new_password: The password the server refused.
        observed_min_length: The profile's ``observed_min_password_length``.

    Returns:
        The observed minimum length when the password is shorter than it: the
        one reason for a refusal the client can name. None means the reason is
        not known, not that the password was fine.
    """
    if observed_min_length is not None and len(new_password) < observed_min_length:
        return observed_min_length
    return None


@dataclass(frozen=True)
class PasswordChange:
    """How a password change ended when it did not fail outright.

    Attributes:
        confirmed: True when a logon with the new password succeeded. False
            when the request went out but no such logon could be completed,
            so which password is in force is not known.
        reason: The connection failure that left the outcome open; None when
            confirmed.
    """

    confirmed: bool
    reason: str | None = None


def change_password(
    url: str, username: str, password: str, new_password: str, timeout: int
) -> PasswordChange:
    """Change the password and confirm the result by logging on with the new one.

    The confirming logon covers two things the change request alone cannot
    tell apart. A server that ignores ``NewLogonPassword`` answers the request
    with the same success as one that applied it. And a connection lost after
    the request was sent says nothing about whether it was applied.

    Args:
        url: CoSign SOAP endpoint URL.
        username: Revenant username.
        password: Current password.
        new_password: Password to change to.
        timeout: Request timeout in seconds.

    Returns:
        The outcome: confirmed, or sent but unconfirmed.

    Raises:
        AuthError: The current password is wrong. Nothing changed.
        ServerError: The server refused the new password, or reported success
            without putting it in force. Nothing changed.
        RevenantError: The request failed and a logon with the new password
            was refused, so the old password is still in force.
    """
    try:
        soap_transport.change_password(url, username, password, new_password, timeout)
    except (AuthError, ServerError):
        raise
    except RevenantError as request_error:
        return _settle_interrupted_change(url, username, new_password, timeout, request_error)
    return _confirm_accepted_change(url, username, new_password, timeout)


def _confirm_accepted_change(
    url: str, username: str, new_password: str, timeout: int
) -> PasswordChange:
    """The server answered with success: check the new password is in force."""
    try:
        soap_transport.enum_certificates(url, username, new_password, timeout)
    except AuthError as e:
        raise ServerError(
            "The server reported success but does not accept the new password. "
            "The password was not changed."
        ) from e
    except RevenantError as e:
        _logger.warning("Password change accepted, but the confirming logon failed: %s", e)
        return PasswordChange(confirmed=False, reason=str(e))
    return PasswordChange(confirmed=True)


def _settle_interrupted_change(
    url: str, username: str, new_password: str, timeout: int, request_error: RevenantError
) -> PasswordChange:
    """The request got no answer, so it may or may not have been applied.

    One logon with the new password decides it.
    """
    _logger.warning(
        "Password change request failed, checking whether it was applied: %s", request_error
    )
    try:
        soap_transport.enum_certificates(url, username, new_password, timeout)
    except AuthError:
        raise request_error from None
    except RevenantError:
        return PasswordChange(confirmed=False, reason=str(request_error))
    return PasswordChange(confirmed=True)
