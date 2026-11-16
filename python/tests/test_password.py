"""Tests for changing the account password."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from revenant import api
from revenant.core.password import (
    NewPasswordProblem,
    PasswordChange,
    change_password,
    check_new_password,
)
from revenant.errors import AuthError, ConfigError, RevenantError, ServerError, TLSError
from revenant.network.soap_envelope import (
    build_change_password_envelope,
    build_enum_certificates_envelope,
    build_sign_envelope,
    build_sign_hash_envelope,
)
from revenant.network.soap_parsers import (
    parse_change_password_response,
    parse_enum_certificates_response,
)
from revenant.network.soap_transport import change_password as send_change_password

URL = "https://example.com/SAPIWS/DSS.asmx"
TRANSPORT = "revenant.core.password.soap_transport"


def _response(major: str, message: str | None = None) -> str:
    message_xml = f"<ResultMessage>{message}</ResultMessage>" if message else ""
    return (
        '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body>'
        "<DssSignResponse><DssSignResult><Result>"
        f"<ResultMajor>urn:oasis:names:tc:dss:1.0:resultmajor:{major}</ResultMajor>"
        "<ResultMinor>urn:oasis:names:tc:dss:1.0:resultminor:GeneralError</ResultMinor>"
        f"{message_xml}</Result></DssSignResult></DssSignResponse></soap:Body></soap:Envelope>"
    )


# ── envelope ───────────────────────────────────────────────────────


def test_envelope_adds_the_new_password_after_the_current_one():
    envelope = build_change_password_envelope("alice", "old", "n<w")
    expected = """\
            <SupportingInfo>
              <arx:LogonPassword>old</arx:LogonPassword>
              <arx:NewLogonPassword>n&lt;w</arx:NewLogonPassword>
            </SupportingInfo>"""
    assert expected in envelope
    assert "enum-certificates</SignatureType>" in envelope


def test_only_the_change_request_carries_a_new_password():
    requests = [
        build_sign_envelope("u", "p", "urn:ietf:rfc:3369", "ZA=="),
        build_sign_hash_envelope("u", "p", "urn:ietf:rfc:3369", "aGFzaA=="),
        build_enum_certificates_envelope("u", "p"),
    ]
    for request in requests:
        assert "NewLogonPassword" not in request


# ── response ───────────────────────────────────────────────────────


def test_success_response_is_accepted():
    parse_change_password_response(_response("Success"))


def test_wrong_current_password_is_an_auth_error():
    """The appliance's answer to a wrong current password, as captured live."""
    xml = _response("ResponderError", "Failed to verify user name and password")
    with pytest.raises(AuthError):
        parse_change_password_response(xml)
    with pytest.raises(AuthError):
        parse_enum_certificates_response(xml)


def test_refused_new_password_is_a_server_error():
    """The appliance's answer to a one-character new password, as captured live.

    It must not read as bad credentials: the logon itself succeeded.
    """
    xml = _response("ResponderError", "Error changing password err 90020150")
    with pytest.raises(ServerError, match="90020150"):
        parse_change_password_response(xml)


def test_malformed_response_does_not_leak_the_new_password():
    xml = "<a><arx:NewLogonPassword>hunter2</arx:NewLogonPassword><unclosed>"
    with pytest.raises(RevenantError) as excinfo:
        parse_change_password_response(xml)
    assert "hunter2" not in str(excinfo.value)


def test_the_change_request_is_never_retried():
    with patch(
        "revenant.network.soap.http_post", return_value=_response("Success").encode()
    ) as post:
        send_change_password(URL, "user", "old", "new", 30)
    assert post.call_args.kwargs["max_retries"] == 0


# ── new password checks ────────────────────────────────────────────


@pytest.mark.parametrize(
    ("new", "ascii_only", "expected"),
    [
        ("", False, NewPasswordProblem.EMPTY),
        ("old", False, NewPasswordProblem.SAME_AS_CURRENT),
        (" new", False, NewPasswordProblem.SURROUNDING_WHITESPACE),
        ("new\n", False, NewPasswordProblem.SURROUNDING_WHITESPACE),
        ("пароль", True, NewPasswordProblem.NON_ASCII),
        ("пароль", False, None),
        ("new pass-1", True, None),
    ],
)
def test_check_new_password(new, ascii_only, expected):
    assert check_new_password("old", new, ascii_only) is expected


# ── change and confirm ─────────────────────────────────────────────


def _run(change_effect, logon_effect):
    with (
        patch(f"{TRANSPORT}.change_password", side_effect=change_effect) as change,
        patch(f"{TRANSPORT}.enum_certificates", side_effect=logon_effect) as logon,
    ):
        try:
            return change_password(URL, "user", "old", "new", 30), change, logon
        except RevenantError as e:
            return e, change, logon


def test_an_accepted_change_is_confirmed_with_the_new_password():
    outcome, change, logon = _run([None], [[b"cert"]])
    assert outcome == PasswordChange(confirmed=True)
    change.assert_called_once_with(URL, "user", "old", "new", 30)
    logon.assert_called_once_with(URL, "user", "new", 30)


def test_a_wrong_current_password_is_reported_without_a_second_logon():
    outcome, _, logon = _run([AuthError("bad")], [])
    assert isinstance(outcome, AuthError)
    logon.assert_not_called()


def test_a_refused_new_password_is_reported_without_a_second_logon():
    outcome, _, logon = _run([ServerError("refused")], [])
    assert isinstance(outcome, ServerError)
    logon.assert_not_called()


def test_success_from_a_server_that_ignored_the_new_password_is_an_error():
    outcome, _, _ = _run([None], [AuthError("bad")])
    assert isinstance(outcome, ServerError)
    assert not isinstance(outcome, AuthError)


def test_an_accepted_change_that_cannot_be_confirmed_is_unconfirmed():
    outcome, _, _ = _run([None], [TLSError("timed out", retryable=True)])
    assert isinstance(outcome, PasswordChange)
    assert not outcome.confirmed


def test_a_lost_response_to_an_applied_change_counts_as_changed():
    outcome, _, _ = _run([TLSError("timed out", retryable=True)], [[b"cert"]])
    assert outcome == PasswordChange(confirmed=True)


def test_a_failed_request_that_was_not_applied_raises_the_request_error():
    outcome, _, _ = _run([TLSError("timed out", retryable=True)], [AuthError("bad")])
    assert isinstance(outcome, TLSError)


def test_a_failed_request_with_no_way_to_check_is_unconfirmed():
    outcome, _, _ = _run([TLSError("request timed out")], [TLSError("still down")])
    assert outcome == PasswordChange(confirmed=False, reason="request timed out")


# ── api ────────────────────────────────────────────────────────────


def test_api_refuses_a_bad_new_password_before_sending():
    with patch(f"{TRANSPORT}.change_password") as change:
        with pytest.raises(RevenantError, match="same as the current"):
            api.change_password("user", "old", "old", profile="ekeng")
        with pytest.raises(RevenantError, match="Latin"):
            api.change_password("user", "old", "пароль", profile="ekeng")
    change.assert_not_called()


def test_api_rejects_profile_and_url_together():
    with pytest.raises(ConfigError):
        api.change_password("user", "old", "new", profile="ekeng", url=URL)


def test_api_resolves_the_profile_and_changes_the_password():
    with (
        patch(f"{TRANSPORT}.change_password") as change,
        patch(f"{TRANSPORT}.enum_certificates", return_value=[b"cert"]),
    ):
        outcome = api.change_password("user", "old", "new-pass", profile="ekeng")
    assert outcome.confirmed
    assert change.call_args.args[1:4] == ("user", "old", "new-pass")


# ── cli ────────────────────────────────────────────────────────────


def _run_cli(typed, *, outcome=None, error=None, update_saved=True):
    """Run ``revenant password`` with ``typed`` as the two hidden entries."""
    from revenant.config import StoredPasswordUpdate
    from revenant.config.profiles import get_profile
    from revenant.ui.cli.password import cmd_password

    change = patch("revenant.api.change_password", return_value=outcome, side_effect=error)
    stored = StoredPasswordUpdate(saved=update_saved, env_override=False)
    with (
        patch("revenant.config.get_server_config", return_value=(URL, 30, "ekeng")),
        patch("revenant.config.get_active_profile", return_value=get_profile("ekeng")),
        patch("revenant.config.resolve_credentials", return_value=("user", "old")),
        patch("revenant.config.get_credential_storage_info", return_value="Test keychain"),
        patch("revenant.config.apply_password_change", return_value=stored) as apply,
        patch("getpass.getpass", side_effect=typed),
        change as change_mock,
    ):
        try:
            cmd_password()
            code = 0
        except SystemExit as e:
            code = e.code
    return code, change_mock, apply


def test_cli_changes_the_password_and_updates_saved_credentials(capsys):
    code, change, apply = _run_cli(["new-pass", "new-pass"], outcome=PasswordChange(confirmed=True))

    assert code == 0
    change.assert_called_once_with("user", "old", "new-pass")
    apply.assert_called_once_with("user", "new-pass")
    out = capsys.readouterr().out
    assert "Password changed." in out
    assert "Test keychain" in out


def test_cli_refuses_mismatched_entries_without_contacting_the_server(capsys):
    code, change, apply = _run_cli(["new-pass", "new-pas"])

    assert code == 1
    change.assert_not_called()
    apply.assert_not_called()
    assert "do not match" in capsys.readouterr().err


def test_cli_refuses_a_non_ascii_password_for_an_ascii_only_profile(capsys):
    code, change, _ = _run_cli(["пароль", "пароль"])

    assert code == 1
    change.assert_not_called()
    assert "Latin" in capsys.readouterr().err


def test_cli_leaves_saved_credentials_alone_when_unconfirmed(capsys):
    outcome = PasswordChange(confirmed=False, reason="timed out")
    code, _, apply = _run_cli(["new-pass", "new-pass"], outcome=outcome)

    assert code == 1
    apply.assert_not_called()
    assert "Either password may be the valid one" in capsys.readouterr().err


def test_cli_reports_a_wrong_current_password_with_the_lockout_warning(capsys):
    code, _, apply = _run_cli(["new-pass", "new-pass"], error=AuthError("bad credentials"))

    assert code == 1
    apply.assert_not_called()
    err = capsys.readouterr().err
    assert "AUTH FAILED" in err
    assert "5 failed attempts" in err


def test_cli_reports_a_refused_new_password(capsys):
    code, _, apply = _run_cli(["new-pass", "new-pass"], error=ServerError("refused: 90020150"))

    assert code == 1
    apply.assert_not_called()
    err = capsys.readouterr().err
    assert "90020150" in err
    assert "was not changed" in err
    assert "password rules" in err


def test_cli_names_the_length_when_a_refused_password_is_too_short(capsys):
    code, _, _ = _run_cli(["abc12", "abc12"], error=ServerError("refused: 90020150"))

    assert code == 1
    assert "shorter than 6 characters" in capsys.readouterr().err
