//! The background half of the change-password dialog.

use std::sync::Arc;

use revenant_sign_core::api::{self, ServerChoice};
use revenant_sign_core::config::ConfigStore;
use revenant_sign_core::net::Transport;
use revenant_sign_core::password::{
    check_new_password, shorter_than_observed_minimum, PasswordChange,
};
use revenant_sign_core::RevenantError;

use crate::worker::PasswordChangeOutcome;

/// Change the password of the account the app signs with to `new_password`,
/// then bring the stored credentials in line.
///
/// The stored copies are updated here, on the worker thread, and not when the
/// UI gets around to reading the result: once the server accepts the new
/// password the old stored one is wrong, whatever happens to the dialog.
pub(crate) fn change_password(
    store: &ConfigStore,
    transport: &Arc<Transport>,
    new_password: &str,
) -> PasswordChangeOutcome {
    let credentials = store.resolve_credentials();
    let (Some(username), Some(current)) = (credentials.username, credentials.password) else {
        return PasswordChangeOutcome::NoCredentials;
    };

    let profile = store.active_profile();
    let ascii_only = profile
        .as_ref()
        .is_some_and(|profile| profile.ascii_credentials_only);
    let observed_minimum = profile.and_then(|profile| profile.observed_min_password_length);
    if let Err(problem) = check_new_password(current.expose(), new_password, ascii_only) {
        return PasswordChangeOutcome::Invalid(problem);
    }

    let result = api::change_password(
        store,
        transport,
        &username,
        current.expose(),
        new_password,
        &ServerChoice::default(),
    );
    match result {
        Ok(PasswordChange::Changed) => match store.apply_password_change(&username, new_password) {
            Ok(_) => PasswordChangeOutcome::Changed,
            Err(err) => PasswordChangeOutcome::ChangedNotSaved(err.to_string()),
        },
        Ok(PasswordChange::Unconfirmed { reason }) => PasswordChangeOutcome::Unconfirmed(reason),
        Err(RevenantError::Auth(detail)) => PasswordChangeOutcome::AuthFailed(detail),
        Err(RevenantError::Server(detail)) => PasswordChangeOutcome::Refused {
            detail,
            shorter_than: shorter_than_observed_minimum(new_password, observed_minimum),
        },
        Err(err) => PasswordChangeOutcome::Failed(err.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn isolated_store() -> (tempfile::TempDir, ConfigStore) {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = ConfigStore::isolated(dir.path().to_path_buf(), "test keychain");
        (dir, store)
    }

    #[test]
    fn without_credentials_nothing_is_sent() {
        let (_dir, store) = isolated_store();
        let transport = Arc::new(Transport::new());

        let outcome = change_password(&store, &transport, "Secret-123");

        assert!(matches!(outcome, PasswordChangeOutcome::NoCredentials));
    }

    #[test]
    fn the_current_password_is_refused_as_the_new_one() {
        let (_dir, store) = isolated_store();
        store.set_session_credentials("user", "Secret-123");
        let transport = Arc::new(Transport::new());

        let outcome = change_password(&store, &transport, "Secret-123");

        assert!(matches!(outcome, PasswordChangeOutcome::Invalid(_)));
    }
}
