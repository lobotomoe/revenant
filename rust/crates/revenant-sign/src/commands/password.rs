// SPDX-License-Identifier: Apache-2.0
//! `password` — change the account password on the signing server.

use revenant_sign_core::api::{self, ServerChoice};
use revenant_sign_core::config::Secret;
use revenant_sign_core::password::{
    check_new_password, shorter_than_observed_minimum, PasswordChange,
};
use revenant_sign_core::RevenantError;

use crate::app::App;
use crate::exit::{CliError, CliResult};
use crate::prompt::{print_auth_failure, prompt_credentials, prompt_new_password};

/// `password` — ask for a new password, change it on the server, and bring the
/// saved credentials in line.
pub(crate) fn password(app: &App) -> CliResult {
    let Some(config) = app.store.server_config() else {
        return Err(CliError::new(
            "no server configured. Run 'revenant setup' first.",
        ));
    };
    let profile = app.store.active_profile();

    let resolved = app.store.resolve_credentials();
    let known_password = resolved.password.as_ref().map(Secret::expose);
    let (username, current) = prompt_credentials(resolved.username.as_deref(), known_password)?;

    println!("Changing the password for {username} on {}", config.url);
    let new_password = prompt_new_password()?;
    let ascii_only = profile
        .as_ref()
        .is_some_and(|profile| profile.ascii_credentials_only);
    check_new_password(&current, &new_password, ascii_only)
        .map_err(|problem| CliError::new(problem.to_string()))?;

    let outcome = api::change_password(
        &app.store,
        &app.transport,
        &username,
        &current,
        &new_password,
        &ServerChoice::default(),
    );
    match outcome {
        Ok(PasswordChange::Changed) => report_changed(app, &username, &new_password),
        Ok(PasswordChange::Unconfirmed { reason }) => {
            eprintln!("The connection failed before the change could be confirmed:");
            eprintln!("  {reason}");
            eprintln!("Either password may be the valid one now. Saved credentials were not");
            eprintln!("touched. Run 'revenant setup' and try the new password first.");
            Err(CliError::silent())
        }
        Err(RevenantError::Auth(message)) => {
            print_auth_failure(&message, profile.as_ref());
            Err(CliError::silent())
        }
        Err(RevenantError::Server(message)) => {
            let observed_minimum = profile
                .as_ref()
                .and_then(|profile| profile.observed_min_password_length);
            let hint = match shorter_than_observed_minimum(&new_password, observed_minimum) {
                Some(minimum) => format!(
                    "It is shorter than {minimum} characters, the shortest this server is known to accept."
                ),
                None => "It may not meet the server's password rules.".to_owned(),
            };
            Err(CliError::new(format!(
                "{message}\nThe password was not changed. {hint}"
            )))
        }
        Err(RevenantError::Tls { message, .. }) => {
            Err(CliError::new(format!("connection failed: {message}")))
        }
        Err(error) => Err(CliError::new(error.to_string())),
    }
}

/// The server accepts the new password: update what is stored and say what was
/// and was not updated.
fn report_changed(app: &App, username: &str, new_password: &str) -> CliResult {
    println!("Password changed.");
    let update = app
        .store
        .apply_password_change(username, new_password)
        .map_err(|error| {
            CliError::new(format!(
                "the password was changed on the server, but the saved copy could not be \
                 updated: {error}. Run 'revenant setup' to save the new password."
            ))
        })?;
    if update.saved {
        println!(
            "Saved credentials updated: {}",
            app.store.credential_storage_info()
        );
    }
    if update.env_override {
        println!("REVENANT_PASS is set and still holds the old password. Update it.");
    }
    Ok(())
}
