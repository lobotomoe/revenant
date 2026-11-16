//! Changing the signing account's password.
//!
//! The request itself is one logon carrying the new password
//! ([`SigningTransport::change_password`]). What this module adds is the part a
//! caller would otherwise get wrong: a new password that would lock the user
//! out of this client is refused before it is sent, and the outcome is settled
//! by logging on with the new password, so the caller only replaces a stored
//! password with one the server is known to accept.

use std::fmt;
use std::time::Duration;

use crate::net::SigningTransport;
use crate::{Result, RevenantError};

/// Why a new password cannot be sent to the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NewPasswordProblem {
    /// Nothing was entered.
    Empty,
    /// It equals the current password.
    SameAsCurrent,
    /// It begins or ends with whitespace. Every client trims the password it
    /// reads at login, so such a password could never be entered again.
    SurroundingWhitespace,
    /// It has non-ASCII characters and the server profile issues ASCII-only
    /// credentials, which the login form enforces.
    NonAscii,
}

impl fmt::Display for NewPasswordProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            NewPasswordProblem::Empty => "The new password is empty.",
            NewPasswordProblem::SameAsCurrent => "The new password is the same as the current one.",
            NewPasswordProblem::SurroundingWhitespace => {
                "The new password must not begin or end with a space."
            }
            NewPasswordProblem::NonAscii => {
                "The new password may only contain Latin letters, digits and symbols."
            }
        })
    }
}

/// Check a new password before sending it. `ascii_only` is the server
/// profile's `ascii_credentials_only`.
///
/// The server's own password policy is not known to the client and is not
/// checked here; a password it refuses comes back as
/// [`RevenantError::Server`] from [`change_password`].
///
/// # Errors
///
/// Returns the first [`NewPasswordProblem`] found.
pub fn check_new_password(
    current: &str,
    new: &str,
    ascii_only: bool,
) -> std::result::Result<(), NewPasswordProblem> {
    if new.is_empty() {
        return Err(NewPasswordProblem::Empty);
    }
    if new != new.trim() {
        return Err(NewPasswordProblem::SurroundingWhitespace);
    }
    if new == current {
        return Err(NewPasswordProblem::SameAsCurrent);
    }
    if ascii_only && !new.is_ascii() {
        return Err(NewPasswordProblem::NonAscii);
    }
    Ok(())
}

/// Explain a new password the server refused, as far as the profile allows.
///
/// Returns the profile's observed minimum length when `new_password` is
/// shorter than it: the one reason for a refusal the client can name. `None`
/// means the reason is not known, not that the password was fine.
#[must_use]
pub fn shorter_than_observed_minimum(
    new_password: &str,
    observed_min_length: Option<usize>,
) -> Option<usize> {
    let length = new_password.chars().count();
    observed_min_length.filter(|&minimum| length < minimum)
}

/// How a password change ended when it did not fail outright.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PasswordChange {
    /// The server accepts the new password: a logon with it succeeded.
    Changed,
    /// The request went out, but no logon with the new password could be
    /// completed afterwards, so which password is in force is not known.
    /// `reason` is the connection failure that left it open.
    Unconfirmed { reason: String },
}

/// Change the password and confirm the result by logging on with the new one.
///
/// The confirming logon covers two things the change request alone cannot
/// tell apart. A server that ignores `NewLogonPassword` answers the request
/// with the same success as one that applied it. And a connection lost after
/// the request was sent says nothing about whether it was applied.
///
/// # Errors
///
/// - [`RevenantError::Auth`]: the current password is wrong. Nothing changed.
/// - [`RevenantError::Server`]: the server refused the new password, or
///   reported success without putting it in force. Nothing changed.
/// - Any other [`RevenantError`]: the request failed and a logon with the new
///   password was refused, so the old password is still in force.
pub fn change_password<T: SigningTransport + ?Sized>(
    transport: &T,
    username: &str,
    password: &str,
    new_password: &str,
    timeout: Duration,
) -> Result<PasswordChange> {
    match transport.change_password(username, password, new_password, timeout) {
        Ok(()) => confirm_accepted_change(transport, username, new_password, timeout),
        Err(err @ (RevenantError::Auth(_) | RevenantError::Server(_))) => Err(err),
        Err(err) => settle_interrupted_change(transport, username, new_password, timeout, err),
    }
}

/// The server answered the change request with success: check that the new
/// password is really in force.
fn confirm_accepted_change<T: SigningTransport + ?Sized>(
    transport: &T,
    username: &str,
    new_password: &str,
    timeout: Duration,
) -> Result<PasswordChange> {
    match transport.enum_certificates(username, new_password, timeout) {
        Ok(_) => Ok(PasswordChange::Changed),
        Err(RevenantError::Auth(_)) => Err(RevenantError::Server(
            "The server reported success but does not accept the new password. \
             The password was not changed."
                .to_owned(),
        )),
        Err(err) => {
            log::warn!("Password change accepted, but the confirming logon failed: {err}");
            Ok(PasswordChange::Unconfirmed {
                reason: err.to_string(),
            })
        }
    }
}

/// The change request failed without an answer from the server, so it may or
/// may not have been applied. One logon with the new password decides it.
fn settle_interrupted_change<T: SigningTransport + ?Sized>(
    transport: &T,
    username: &str,
    new_password: &str,
    timeout: Duration,
    request_error: RevenantError,
) -> Result<PasswordChange> {
    log::warn!("Password change request failed, checking whether it was applied: {request_error}");
    match transport.enum_certificates(username, new_password, timeout) {
        Ok(_) => Ok(PasswordChange::Changed),
        Err(RevenantError::Auth(_)) => Err(request_error),
        Err(_) => Ok(PasswordChange::Unconfirmed {
            reason: request_error.to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;

    #[test]
    fn a_refused_password_is_explained_only_when_it_is_too_short() {
        assert_eq!(shorter_than_observed_minimum("abcde", Some(6)), Some(6));
        assert_eq!(shorter_than_observed_minimum("abcdef", Some(6)), None);
        assert_eq!(shorter_than_observed_minimum("abc", None), None);
    }

    /// A transport scripted with one answer per operation, recording which
    /// passwords it was asked to log on with.
    struct Scripted {
        change: RefCell<Option<Result<()>>>,
        logon: RefCell<Option<Result<Vec<Vec<u8>>>>>,
        logons: RefCell<Vec<String>>,
    }

    impl Scripted {
        fn new(change: Result<()>, logon: Result<Vec<Vec<u8>>>) -> Self {
            Scripted {
                change: RefCell::new(Some(change)),
                logon: RefCell::new(Some(logon)),
                logons: RefCell::new(Vec::new()),
            }
        }
    }

    impl SigningTransport for Scripted {
        fn sign_data(&self, _: &[u8], _: &str, _: &str, _: Duration) -> Result<Vec<u8>> {
            unreachable!("a password change signs nothing")
        }

        fn sign_hash(&self, _: &[u8], _: &str, _: &str, _: Duration) -> Result<Vec<u8>> {
            unreachable!("a password change signs nothing")
        }

        fn sign_pdf_detached(&self, _: &[u8], _: &str, _: &str, _: Duration) -> Result<Vec<u8>> {
            unreachable!("a password change signs nothing")
        }

        fn enum_certificates(&self, _: &str, password: &str, _: Duration) -> Result<Vec<Vec<u8>>> {
            self.logons.borrow_mut().push(password.to_owned());
            self.logon
                .borrow_mut()
                .take()
                .expect("only one confirming logon is expected")
        }

        fn change_password(&self, _: &str, _: &str, _: &str, _: Duration) -> Result<()> {
            self.change
                .borrow_mut()
                .take()
                .expect("the change request must be sent once")
        }
    }

    fn run(transport: &Scripted) -> Result<PasswordChange> {
        change_password(transport, "user", "old", "new", Duration::from_secs(1))
    }

    fn auth() -> RevenantError {
        RevenantError::Auth("Authentication failed".to_owned())
    }

    fn dropped() -> RevenantError {
        RevenantError::tls_retryable("timed out after 1s talking to host:443")
    }

    #[test]
    fn an_accepted_change_is_confirmed_with_the_new_password() {
        let transport = Scripted::new(Ok(()), Ok(vec![vec![1]]));
        assert_eq!(run(&transport).unwrap(), PasswordChange::Changed);
        assert_eq!(*transport.logons.borrow(), ["new"]);
    }

    #[test]
    fn a_wrong_current_password_is_reported_without_a_second_logon() {
        let transport = Scripted::new(Err(auth()), Ok(Vec::new()));
        assert!(matches!(run(&transport), Err(RevenantError::Auth(_))));
        assert!(transport.logons.borrow().is_empty());
    }

    #[test]
    fn a_refused_new_password_is_reported_without_a_second_logon() {
        let refusal = RevenantError::Server("refused".to_owned());
        let transport = Scripted::new(Err(refusal), Ok(Vec::new()));
        assert!(matches!(run(&transport), Err(RevenantError::Server(_))));
        assert!(transport.logons.borrow().is_empty());
    }

    #[test]
    fn success_from_a_server_that_ignored_the_new_password_is_an_error() {
        let transport = Scripted::new(Ok(()), Err(auth()));
        let err = run(&transport).unwrap_err();
        assert!(matches!(err, RevenantError::Server(_)), "got {err:?}");
    }

    #[test]
    fn an_accepted_change_that_cannot_be_confirmed_is_unconfirmed() {
        let transport = Scripted::new(Ok(()), Err(dropped()));
        assert!(matches!(
            run(&transport).unwrap(),
            PasswordChange::Unconfirmed { .. }
        ));
    }

    #[test]
    fn a_lost_response_to_an_applied_change_counts_as_changed() {
        let transport = Scripted::new(Err(dropped()), Ok(vec![vec![1]]));
        assert_eq!(run(&transport).unwrap(), PasswordChange::Changed);
    }

    #[test]
    fn a_failed_request_that_was_not_applied_returns_the_request_error() {
        let transport = Scripted::new(Err(dropped()), Err(auth()));
        let err = run(&transport).unwrap_err();
        assert!(err.is_tls(), "got {err:?}");
    }

    #[test]
    fn a_failed_request_with_no_way_to_check_is_unconfirmed() {
        let transport = Scripted::new(Err(dropped()), Err(dropped()));
        let outcome = run(&transport).unwrap();
        let PasswordChange::Unconfirmed { reason } = outcome else {
            panic!("expected Unconfirmed, got {outcome:?}");
        };
        assert!(reason.contains("timed out"), "got {reason}");
    }

    #[test]
    fn new_password_checks() {
        assert_eq!(
            check_new_password("old", "", false),
            Err(NewPasswordProblem::Empty)
        );
        assert_eq!(
            check_new_password("old", "old", false),
            Err(NewPasswordProblem::SameAsCurrent)
        );
        assert_eq!(
            check_new_password("old", " new", false),
            Err(NewPasswordProblem::SurroundingWhitespace)
        );
        assert_eq!(
            check_new_password("old", "new\n", false),
            Err(NewPasswordProblem::SurroundingWhitespace)
        );
        assert_eq!(
            check_new_password("old", "пароль", true),
            Err(NewPasswordProblem::NonAscii)
        );
        assert_eq!(check_new_password("old", "пароль", false), Ok(()));
        assert_eq!(check_new_password("old", "new pass-1", true), Ok(()));
    }
}
