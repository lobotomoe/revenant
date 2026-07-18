// SPDX-License-Identifier: Apache-2.0
//! Command failure and process-exit handling.
//!
//! Command handlers return [`CliResult`]. A returned [`CliError`] maps to a
//! non-zero exit code; if it carries a message, `main` prints it to stderr as
//! `Error: <message>`. A handler that has already printed its own formatted
//! failure (per-file signing results, a verification summary) returns
//! [`CliError::silent`] so nothing is printed twice.

use revenant_core::RevenantError;

/// A command failure that should terminate the process with a non-zero status.
#[derive(Debug)]
pub(crate) struct CliError {
    /// Printed to stderr as `Error: <message>`; `None` when the handler already
    /// printed its own diagnostics.
    message: Option<String>,
}

/// The result type every command handler returns.
pub(crate) type CliResult = Result<(), CliError>;

impl CliError {
    /// A failure that prints `Error: <message>` to stderr before exiting.
    pub(crate) fn new(message: impl Into<String>) -> Self {
        CliError {
            message: Some(message.into()),
        }
    }

    /// A failure whose diagnostics were already printed by the handler; exit
    /// non-zero without printing anything further.
    #[must_use]
    pub(crate) fn silent() -> Self {
        CliError { message: None }
    }

    /// Print the error message to stderr, if any.
    pub(crate) fn report(&self) {
        if let Some(message) = &self.message {
            eprintln!("Error: {message}");
        }
    }
}

/// A [`RevenantError`] surfaces as `Error: <its message>` on stderr.
impl From<RevenantError> for CliError {
    fn from(error: RevenantError) -> Self {
        CliError::new(error.to_string())
    }
}
