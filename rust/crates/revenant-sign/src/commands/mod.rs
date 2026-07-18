// SPDX-License-Identifier: Apache-2.0
//! Command handlers.
//!
//! One module per subcommand family; each handler takes the parsed arguments
//! (and the [`App`](crate::app::App) context where it needs config or the
//! network) and returns a [`CliResult`](crate::exit::CliResult).

mod account;
mod cert;
mod check;
mod setup;
mod sign;
mod verify;

pub(crate) use account::{logout, reset};
pub(crate) use cert::cert;
pub(crate) use check::check;
pub(crate) use setup::setup;
pub(crate) use sign::sign;
pub(crate) use verify::{info, verify};
