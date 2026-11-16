//! Config-resolving entry point for changing the account password.

use std::sync::Arc;

use crate::config::ConfigStore;
use crate::net::Transport;
use crate::password::{self, check_new_password, PasswordChange};
use crate::{Result, RevenantError};

use super::{resolve_profile, resolve_url_and_timeout, setup_transport, ServerChoice};

/// Change the signing account's password on the server.
///
/// Server resolution is identical to [`sign`](super::sign). The new password is
/// checked against the resolved profile before anything is sent, and the result
/// is confirmed by a logon with the new password.
///
/// Stored credentials are left alone: on [`PasswordChange::Changed`] the caller
/// follows up with [`ConfigStore::apply_password_change`].
///
/// # Errors
///
/// Returns [`RevenantError::Config`] if no server URL can be resolved or both a
/// profile and URL are given, [`RevenantError::Other`] if the new password
/// fails [`check_new_password`], and otherwise the errors of
/// [`password::change_password`].
pub fn change_password(
    store: &ConfigStore,
    transport: &Arc<Transport>,
    username: &str,
    password: &str,
    new_password: &str,
    server: &ServerChoice<'_>,
) -> Result<PasswordChange> {
    let profile = resolve_profile(store, server)?;
    let (url, timeout) = resolve_url_and_timeout(store, profile.as_ref(), server)?;

    let ascii_only = profile
        .as_ref()
        .is_some_and(|profile| profile.ascii_credentials_only);
    check_new_password(password, new_password, ascii_only)
        .map_err(|problem| RevenantError::Other(problem.to_string()))?;

    let soap = setup_transport(transport, &url, profile.as_ref());
    password::change_password(&soap, username, password, new_password, timeout)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::test_store;

    fn ekeng() -> ServerChoice<'static> {
        ServerChoice {
            profile: Some("ekeng"),
            ..ServerChoice::default()
        }
    }

    /// A password the client refuses never reaches the network: these would
    /// otherwise fail on the unreachable transport, not on the check.
    #[test]
    fn a_refused_new_password_is_not_sent() {
        let (_dir, store) = test_store();
        let transport = Arc::new(Transport::new());

        let same = change_password(&store, &transport, "user", "old", "old", &ekeng());
        let message = same.unwrap_err().to_string();
        assert!(message.contains("same as the current"), "got {message}");

        let non_ascii = change_password(&store, &transport, "user", "old", "пароль", &ekeng());
        let message = non_ascii.unwrap_err().to_string();
        assert!(message.contains("Latin"), "got {message}");
    }

    #[test]
    fn no_server_is_a_config_error() {
        let (_dir, store) = test_store();
        let transport = Arc::new(Transport::new());
        let result = change_password(
            &store,
            &transport,
            "user",
            "old",
            "new",
            &ServerChoice::default(),
        );
        assert!(matches!(result, Err(RevenantError::Config(_))));
    }
}
