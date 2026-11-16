# SPDX-License-Identifier: Apache-2.0
"""Change the account password on the signing server."""

from __future__ import annotations

import getpass
import sys

from ...errors import AuthError, RevenantError, ServerError, TLSError


def _prompt_new_password() -> str:
    """Prompt for a new password twice, without echo."""
    try:
        first = getpass.getpass("New password: ").strip()
        second = getpass.getpass("Repeat new password: ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(1)
    if first != second:
        print("Error: the two passwords do not match.", file=sys.stderr)
        sys.exit(1)
    return first


def cmd_password() -> None:
    """Ask for a new password, change it on the server, update saved credentials."""
    from ... import api
    from ...config import (
        apply_password_change,
        get_active_profile,
        get_credential_storage_info,
        get_server_config,
        resolve_credentials,
    )
    from ...core.password import check_new_password, shorter_than_observed_minimum
    from ..helpers import print_auth_failure, prompt_credentials

    url, timeout, _ = get_server_config()
    if not url or not timeout:
        print("Error: no server configured. Run 'revenant setup' first.", file=sys.stderr)
        sys.exit(1)
    profile = get_active_profile()

    username, current = resolve_credentials()
    if not username or not current:
        username, current = prompt_credentials(username, current)

    print(f"Changing the password for {username} on {url}")
    new_password = _prompt_new_password()
    ascii_only = profile is not None and profile.ascii_credentials_only
    problem = check_new_password(current, new_password, ascii_only)
    if problem is not None:
        print(f"Error: {problem.value}", file=sys.stderr)
        sys.exit(1)

    try:
        outcome = api.change_password(username, current, new_password)
    except AuthError as e:
        print_auth_failure(e, profile)
        sys.exit(1)
    except ServerError as e:
        print(f"Error: {e}", file=sys.stderr)
        observed_minimum = profile.observed_min_password_length if profile else None
        too_short = shorter_than_observed_minimum(new_password, observed_minimum) is not None
        if too_short:
            # The number printed is the profile's, not anything read from the
            # password.
            hint = (
                f"It is shorter than {observed_minimum} characters, "
                "the shortest this server is known to accept."
            )
        else:
            hint = "It may not meet the server's password rules."
        print(f"The password was not changed. {hint}", file=sys.stderr)
        sys.exit(1)
    except TLSError as e:
        print(f"Error: connection failed: {e}", file=sys.stderr)
        sys.exit(1)
    except RevenantError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    if not outcome.confirmed:
        print("The connection failed before the change could be confirmed:", file=sys.stderr)
        print(f"  {outcome.reason}", file=sys.stderr)
        print(
            "Either password may be the valid one now. Saved credentials were not\n"
            "touched. Run 'revenant setup' and try the new password first.",
            file=sys.stderr,
        )
        sys.exit(1)

    print("Password changed.")
    update = apply_password_change(username, new_password)
    if update.saved:
        print(f"Saved credentials updated: {get_credential_storage_info()}")
    if update.env_override:
        print("REVENANT_PASS is set and still holds the old password. Update it.")
