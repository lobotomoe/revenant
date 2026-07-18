// SPDX-License-Identifier: Apache-2.0
//! `logout` and `reset` — clearing saved state.

use crate::app::App;
use crate::exit::CliResult;

/// `logout` — clear credentials and identity, keeping server configuration.
pub(crate) fn logout(app: &App) -> CliResult {
    app.store.logout()?;
    println!("Logged out. Server configuration preserved.");
    println!("Run 'revenant setup' to log in again.");
    Ok(())
}

/// `reset` — clear all configuration: credentials, identity, and server profile.
pub(crate) fn reset(app: &App) -> CliResult {
    app.store.reset_all()?;
    println!("All configuration cleared.");
    println!("Run 'revenant setup' to reconfigure.");
    Ok(())
}
