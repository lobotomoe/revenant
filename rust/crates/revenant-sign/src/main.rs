// SPDX-License-Identifier: Apache-2.0
//! The `revenant` command-line interface.
//!
//! A thin front-end over `revenant-sign-core`: it parses arguments, builds the shared
//! [`App`] context (one config store, one transport), dispatches to a command
//! handler, and maps the handler's [`CliResult`] to a process exit code. All
//! signing, verification, and configuration logic lives in the library.

mod app;
mod cli;
mod commands;
mod exit;
mod output;
mod prompt;

use std::process::ExitCode;

use clap::{CommandFactory, Parser};

use app::App;
use cli::{Cli, Command};
use exit::{CliError, CliResult};

fn main() -> ExitCode {
    env_logger::init();

    match dispatch(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            error.report();
            ExitCode::FAILURE
        }
    }
}

/// Route a parsed command line to its handler.
fn dispatch(cli: Cli) -> CliResult {
    let Some(command) = cli.command else {
        // No subcommand: print help and exit non-zero.
        let _ = Cli::command().print_help();
        println!();
        return Err(CliError::silent());
    };

    let app = App::new();
    match command {
        Command::Sign(args) => commands::sign(&app, &args),
        Command::Verify(args) => commands::verify(&app, &args),
        Command::Check(args) => commands::check(&app, &args),
        Command::Info(args) => commands::info(&args),
        Command::Cert(args) => commands::cert(&app, &args),
        Command::Setup(args) => commands::setup(&app, &args),
        Command::Logout => commands::logout(&app),
        Command::Reset => commands::reset(&app),
    }
}
