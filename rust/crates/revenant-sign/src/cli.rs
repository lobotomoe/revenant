// SPDX-License-Identifier: Apache-2.0
//! Command-line argument definitions.
//!
//! `--position` and `--page` are accepted as free-form strings and validated in
//! the command handlers rather than by clap value-parsers, so a bad value
//! produces the domain validator's error message (with its preset list) instead
//! of a generic clap usage error.

use clap::{Args, Parser, Subcommand};

/// The environment-variable reference shown at the end of `--help`.
const AFTER_HELP: &str = "\
Environment variables:
  REVENANT_USER     Revenant username
  REVENANT_PASS     Revenant password
  REVENANT_URL      SOAP endpoint
  REVENANT_TIMEOUT  Timeout in seconds (default: 120)
  REVENANT_NAME     Signer display name (overrides config from setup)

Project:
  https://github.com/lobotomoe/revenant
  Bug reports: https://github.com/lobotomoe/revenant/issues";

/// Cross-platform CLI for ARX CoSign electronic signatures.
#[derive(Debug, Parser)]
#[command(
    name = "revenant",
    version,
    about = "Cross-platform CLI for ARX CoSign electronic signatures.",
    after_help = AFTER_HELP,
    disable_help_subcommand = true
)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Option<Command>,
}

/// The available subcommands.
#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Sign PDF document(s)
    Sign(SignArgs),
    /// Verify a detached CMS signature
    Verify(VerifyArgs),
    /// Check an embedded PDF signature
    Check(CheckArgs),
    /// Show signature file details
    Info(InfoArgs),
    /// Show certificate details and expiration
    Cert(CertArgs),
    /// Configure server, credentials, and signer identity
    Setup(SetupArgs),
    /// Log out (clear credentials and identity, keep server)
    Logout,
    /// Clear all configuration (server, credentials, identity)
    Reset,
}

/// `sign` — sign one or more PDFs (embedded by default, or detached `.p7s`).
#[derive(Debug, Args)]
pub(crate) struct SignArgs {
    /// PDF file(s) to sign
    #[arg(required = true)]
    pub(crate) files: Vec<String>,

    /// Output file path (single file only)
    #[arg(short, long)]
    pub(crate) output: Option<String>,

    /// Save detached .p7s signature instead of embedded PDF
    #[arg(short, long)]
    pub(crate) detached: bool,

    /// Signature position preset: bottom-right (br), top-right (tr),
    /// bottom-left (bl), top-left (tl), bottom-center (bc)
    #[arg(short, long, default_value = "bottom-right")]
    pub(crate) position: String,

    /// Page for the signature field: 'first', 'last', or a 1-based page number
    #[arg(long, default_value = "last")]
    pub(crate) page: String,

    /// Signature image file (PNG or JPEG) shown in the signature field
    #[arg(long)]
    pub(crate) image: Option<String>,

    /// Create an invisible signature (no visual appearance on the page)
    #[arg(long)]
    pub(crate) invisible: bool,

    /// Font for signature appearance (default: from profile)
    #[arg(long, value_parser = ["noto-sans", "ghea-mariam", "ghea-grapalat"])]
    pub(crate) font: Option<String>,

    /// Signature reason string (optional)
    #[arg(long)]
    pub(crate) reason: Option<String>,

    /// Show what would be done without actually signing
    #[arg(long)]
    pub(crate) dry_run: bool,
}

/// `verify` — verify a detached CMS signature against its PDF.
#[derive(Debug, Args)]
pub(crate) struct VerifyArgs {
    /// PDF file
    pub(crate) pdf: String,

    /// Signature file (default: <pdf>.p7s)
    #[arg(short, long)]
    pub(crate) signature: Option<String>,
}

/// `check` — check the embedded signature(s) of a signed PDF.
#[derive(Debug, Args)]
pub(crate) struct CheckArgs {
    /// Signed PDF file
    pub(crate) pdf: String,

    /// Also run server-side verification (DssVerify) if a server is configured
    #[arg(long)]
    pub(crate) server: bool,
}

/// `info` — show the certificates in a CMS signature file.
#[derive(Debug, Args)]
pub(crate) struct InfoArgs {
    /// CMS signature file (.p7s)
    pub(crate) signature: String,
}

/// `cert` — show signer certificate details from the server or a signed PDF.
#[derive(Debug, Args)]
pub(crate) struct CertArgs {
    /// Extract certificate info from a signed PDF (offline, no server needed)
    #[arg(long)]
    pub(crate) pdf: Option<String>,
}

/// `setup` — interactive configuration wizard.
#[derive(Debug, Args)]
pub(crate) struct SetupArgs {
    /// Use a built-in server profile
    #[arg(long)]
    pub(crate) profile: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::Cli;
    use clap::CommandFactory;

    #[test]
    fn command_definition_is_valid() {
        // clap's own consistency check: catches conflicting args, bad defaults,
        // duplicate short/long flags, etc. at test time rather than at runtime.
        Cli::command().debug_assert();
    }
}
