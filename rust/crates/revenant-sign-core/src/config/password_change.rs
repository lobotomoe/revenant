//! Bringing stored credentials in line with a password the server has just
//! accepted.

use crate::constants::ENV_PASS;
use crate::error::RevenantError;

use super::secret::Secret;
use super::ConfigStore;

/// What [`ConfigStore::apply_password_change`] did with the new password.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoredPasswordUpdate {
    /// The saved password (keychain or config file) was replaced.
    pub saved: bool,
    /// The `REVENANT_PASS` environment variable is set. It outranks every
    /// stored password and still holds the old one; only the user can change it.
    pub env_override: bool,
}

impl ConfigStore {
    /// Replace every stored copy of `username`'s password with `new_password`.
    ///
    /// Call this once the server is known to accept the new password. The
    /// in-memory session copy is replaced if it belongs to `username`. The
    /// saved copy is replaced only if a password was saved for `username`
    /// before: a user who chose not to save one keeps that choice.
    ///
    /// # Errors
    /// [`RevenantError::Config`] if the config file cannot be written.
    pub fn apply_password_change(
        &self,
        username: &str,
        new_password: &str,
    ) -> Result<StoredPasswordUpdate, RevenantError> {
        {
            let mut session = self
                .session
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(credentials) = session.as_mut() {
                if credentials.username == username {
                    credentials.password = Secret::new(new_password.to_owned());
                }
            }
        }

        let stored = self.get_credentials();
        let saved_for_user =
            stored.username.as_deref() == Some(username) && stored.password.is_some();
        if saved_for_user {
            self.save_credentials(username, new_password)?;
        }

        Ok(StoredPasswordUpdate {
            saved: saved_for_user,
            env_override: self.env_nonempty(ENV_PASS).is_some(),
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::config::{test_store, test_store_with_env};

    #[test]
    fn a_saved_password_is_replaced() {
        let (_dir, store) = test_store();
        store.save_credentials("user", "old").unwrap();

        let update = store.apply_password_change("user", "new").unwrap();

        assert!(update.saved);
        assert!(!update.env_override);
        let saved = store.get_credentials();
        assert_eq!(saved.password.unwrap().expose(), "new");
    }

    #[test]
    fn nothing_is_saved_for_a_user_who_saved_no_password() {
        let (_dir, store) = test_store();

        let update = store.apply_password_change("user", "new").unwrap();

        assert!(!update.saved);
        assert_eq!(store.get_credentials().username, None);
    }

    #[test]
    fn another_account_s_saved_password_is_left_alone() {
        let (_dir, store) = test_store();
        store.save_credentials("someone-else", "theirs").unwrap();

        let update = store.apply_password_change("user", "new").unwrap();

        assert!(!update.saved);
        let saved = store.get_credentials();
        assert_eq!(saved.username.as_deref(), Some("someone-else"));
        assert_eq!(saved.password.unwrap().expose(), "theirs");
    }

    #[test]
    fn the_session_password_follows_the_change() {
        let (_dir, store) = test_store();
        store.set_session_credentials("user", "old");

        store.apply_password_change("user", "new").unwrap();

        let resolved = store.resolve_credentials();
        assert_eq!(resolved.password.unwrap().expose(), "new");
    }

    #[test]
    fn another_account_s_session_password_is_left_alone() {
        let (_dir, store) = test_store();
        store.set_session_credentials("someone-else", "theirs");

        store.apply_password_change("user", "new").unwrap();

        let resolved = store.resolve_credentials();
        assert_eq!(resolved.password.unwrap().expose(), "theirs");
    }

    #[test]
    fn an_environment_password_is_reported_as_still_overriding() {
        let (_dir, store) = test_store_with_env(&[("REVENANT_PASS", "old")]);

        let update = store.apply_password_change("user", "new").unwrap();

        assert!(update.env_override);
    }
}
