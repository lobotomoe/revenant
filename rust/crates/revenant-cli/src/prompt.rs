// SPDX-License-Identifier: Apache-2.0
//! Interactive terminal prompts.
//!
//! Line input that treats EOF/interrupt as a cancel, a yes/no confirmation,
//! credential entry with a hidden password field, the "save credentials?" offer,
//! and the authentication-failure message with its account-lockout warning.

use std::io::{self, Write};

use revenant_core::config::{ConfigStore, ServerProfile};

use crate::exit::CliError;

/// Read one trimmed line from stdin after writing `prompt` (no trailing
/// newline). Returns `None` on end-of-input or a read error, printing a newline
/// first so the terminal is left tidy.
#[must_use]
pub(crate) fn read_line(prompt: &str) -> Option<String> {
    print!("{prompt}");
    let _ = io::stdout().flush();

    let mut line = String::new();
    match io::stdin().read_line(&mut line) {
        Ok(0) => {
            // EOF (Ctrl-D): no data at all.
            println!();
            None
        }
        Ok(_) => Some(line.trim().to_owned()),
        Err(_) => {
            println!();
            None
        }
    }
}

/// Read a password without echoing it, returning `None` on cancel/error.
fn read_password(prompt: &str) -> Option<String> {
    let Ok(password) = rpassword::prompt_password(prompt) else {
        println!();
        return None;
    };
    Some(password.trim().to_owned())
}

/// Ask a yes/no question. `default_yes` selects what an empty answer means.
///
/// Cancelling (EOF/interrupt) counts as "no".
#[must_use]
pub(crate) fn confirm_choice(message: &str, default_yes: bool) -> bool {
    let suffix = if default_yes { "[Y/n]" } else { "[y/N]" };
    let Some(answer) = read_line(&format!("{message} {suffix} ")) else {
        return false;
    };
    let answer = answer.to_lowercase();
    if default_yes {
        matches!(answer.as_str(), "" | "y" | "yes")
    } else {
        matches!(answer.as_str(), "y" | "yes")
    }
}

/// Prompt for a username and/or password, pre-filling any provided value.
///
/// # Errors
///
/// Returns [`CliError::silent`] if the user cancels (the terminating newline is
/// already printed), or [`CliError::new`] if either field ends up empty.
pub(crate) fn prompt_credentials(
    username: Option<&str>,
    password: Option<&str>,
) -> Result<(String, String), CliError> {
    let username = match username.filter(|u| !u.is_empty()) {
        Some(user) => user.to_owned(),
        None => read_line("Revenant username: ").ok_or_else(CliError::silent)?,
    };

    let password = match password.filter(|p| !p.is_empty()) {
        Some(pass) => pass.to_owned(),
        None => read_password("Revenant password: ").ok_or_else(CliError::silent)?,
    };

    if username.is_empty() || password.is_empty() {
        return Err(CliError::new("username and password are required."));
    }
    Ok((username, password))
}

/// Print an authentication-failure message with the lockout warning, to stderr.
pub(crate) fn print_auth_failure(message: &str, profile: Option<&ServerProfile>) {
    eprintln!("AUTH FAILED");
    eprintln!("  {message}");
    if let Some(profile) = profile {
        if profile.max_auth_attempts > 0 {
            eprintln!(
                "  WARNING: account locks after {} failed attempts!",
                profile.max_auth_attempts
            );
        }
    }
}

/// Offer to persist credentials, saving on confirmation and reporting where.
pub(crate) fn offer_save_credentials(store: &ConfigStore, username: &str, password: &str) {
    if !confirm_choice("\nSave credentials for future use?", true) {
        println!("Credentials not saved.");
        return;
    }

    match store.save_credentials(username, password) {
        Ok(_) => {
            println!("Credentials saved to: {}", store.credential_storage_info());
            if !store.is_keyring_available() {
                println!("  For secure storage, enable a system keychain backend");
            }
            println!("  (env vars REVENANT_USER/REVENANT_PASS always take priority)");
        }
        Err(e) => eprintln!("Error saving credentials: {e}"),
    }
}
