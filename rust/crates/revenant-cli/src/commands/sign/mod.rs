// SPDX-License-Identifier: Apache-2.0
//! `sign` — sign one or more PDFs (embedded by default, or detached `.p7s`).
//!
//! This module handles orchestration: resolving credentials (env > saved >
//! prompt) and the server endpoint (offering the setup wizard when nothing is
//! configured), resolving appearance defaults, printing the run header and
//! summary, and offering to save prompted credentials. The per-file signing
//! mechanics live in [`run`]. A batch stops on the first authentication failure
//! to avoid burning the appliance's limited login attempts and locking the
//! account.

mod run;

use std::time::Duration;

use revenant_core::constants::{DEFAULT_TIMEOUT_SOAP, ENV_NAME, ENV_PASS, ENV_USER, VERSION};
use revenant_core::pdf::{PageSpec, Position};

use crate::app::App;
use crate::cli::{SetupArgs, SignArgs};
use crate::exit::{CliError, CliResult};
use crate::prompt::{confirm_choice, offer_save_credentials, prompt_credentials};

use run::{run_batch, EmbeddedSelectors, SignContext};

/// Where credentials came from, driving the header label and the save offer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CredSource {
    Env,
    Config,
    Prompt,
    DryRun,
}

impl CredSource {
    fn label(self) -> &'static str {
        match self {
            CredSource::Env => "environment",
            CredSource::Config => "saved config",
            CredSource::Prompt => "interactive",
            CredSource::DryRun => "dry run",
        }
    }
}

/// The resolved inputs for a signing run: credentials and where they came from,
/// plus the endpoint and timeout. In dry-run mode the credentials are empty
/// placeholders and no network access happens.
struct Session {
    username: String,
    password: String,
    cred_source: CredSource,
    url: String,
    timeout: Duration,
}

/// `sign` — the command entry point.
pub(crate) fn sign(app: &App, args: &SignArgs) -> CliResult {
    let detached = args.detached;
    let output = args.output.as_deref();

    if output.is_some() && args.files.len() > 1 {
        return Err(CliError::new(
            "-o/--output can only be used with a single input file.",
        ));
    }

    // Resolve appearance selectors up front (shared by the whole batch): an
    // invalid position or page fails fast rather than per file.
    let position: Position = args.position.parse()?;
    let page: PageSpec = args.page.parse()?;

    let Session {
        username,
        password,
        cred_source,
        url,
        timeout,
    } = resolve_session(app, args.dry_run)?;
    let name = resolve_signer_name(app, detached);

    let font = args
        .font
        .clone()
        .or_else(|| app.store.active_profile().map(|p| p.font));
    let fields = if detached || args.dry_run {
        None
    } else {
        revenant_core::api::resolve_signature_fields(&app.store)
    };

    print_header(&url, cred_source, detached, args);

    let ctx = SignContext {
        app,
        username: &username,
        password: &password,
        url: &url,
        timeout,
        output,
    };
    let params = EmbeddedSelectors {
        name: name.as_deref(),
        position,
        position_label: &args.position,
        page,
        image: args.image.as_deref(),
        visible: !args.invisible,
        font: font.as_deref(),
        reason: args.reason.as_deref().unwrap_or(""),
        fields: fields.as_deref(),
        dry_run: args.dry_run,
    };

    let (success, failed) = run_batch(&ctx, &params, &args.files, detached);
    finish(
        app,
        args.dry_run,
        cred_source,
        success,
        failed,
        &username,
        &password,
    )
}

/// Print the run summary and offer to save prompted credentials.
fn finish(
    app: &App,
    dry_run: bool,
    cred_source: CredSource,
    success: usize,
    failed: usize,
    username: &str,
    password: &str,
) -> CliResult {
    println!();
    if dry_run {
        println!("Dry run complete: {success} file(s) would be signed.");
    } else if failed > 0 {
        println!("Done: {success} signed, {failed} failed.");
        return Err(CliError::silent());
    } else {
        println!("Done: {success} signed.");
    }

    if success > 0 && cred_source == CredSource::Prompt {
        offer_save_credentials(&app.store, username, password);
    }
    Ok(())
}

/// Resolve the signing [`Session`], using placeholders in dry-run mode where no
/// network access happens.
fn resolve_session(app: &App, dry_run: bool) -> Result<Session, CliError> {
    if dry_run {
        let (url, timeout) = match app.store.server_config() {
            Some(config) => {
                let timeout = config.timeout_duration();
                (config.url, timeout)
            }
            None => ("(not configured)".to_owned(), DEFAULT_TIMEOUT_SOAP),
        };
        return Ok(Session {
            username: String::new(),
            password: String::new(),
            cred_source: CredSource::DryRun,
            url,
            timeout,
        });
    }

    let cred_source = resolve_cred_source(app);
    let (username, password) = get_credentials(app)?;
    let (url, timeout) = require_server_config(app)?;
    Ok(Session {
        username,
        password,
        cred_source,
        url,
        timeout,
    })
}

/// Determine where credentials will come from, touching no secrets.
fn resolve_cred_source(app: &App) -> CredSource {
    if env_nonempty(ENV_USER).is_some() && env_nonempty(ENV_PASS).is_some() {
        return CredSource::Env;
    }
    if app.store.get_credentials().is_complete() {
        CredSource::Config
    } else {
        CredSource::Prompt
    }
}

/// Get credentials: environment > saved config > interactive prompt.
fn get_credentials(app: &App) -> Result<(String, String), CliError> {
    if let (Some(user), Some(pass)) = (env_nonempty(ENV_USER), env_nonempty(ENV_PASS)) {
        return Ok((user, pass));
    }

    let saved = app.store.get_credentials();
    if let (Some(user), Some(pass)) = (saved.username, saved.password) {
        return Ok((user, pass.expose().to_owned()));
    }

    let resolved = app.store.resolve_credentials();
    prompt_credentials(
        resolved.username.as_deref(),
        resolved
            .password
            .as_ref()
            .map(revenant_core::config::Secret::expose),
    )
}

/// Resolve the server config, offering the setup wizard when nothing is saved.
fn require_server_config(app: &App) -> Result<(String, Duration), CliError> {
    if let Some(config) = app.store.server_config() {
        let timeout = config.timeout_duration();
        return Ok((config.url, timeout));
    }

    println!("No saved configuration found.");
    // EOF/cancel declines the wizard and falls through to the guidance below,
    // rather than exiting silently.
    if confirm_choice("Run setup wizard?", true) {
        super::setup(app, &SetupArgs { profile: None })?;
        if let Some(config) = app.store.server_config() {
            println!();
            let timeout = config.timeout_duration();
            return Ok((config.url, timeout));
        }
    }

    eprintln!("No server configured.");
    eprintln!("Set REVENANT_URL env var or run `revenant setup`.");
    Err(CliError::silent())
}

/// The signer display name: `REVENANT_NAME` env > saved config (embedded only).
fn resolve_signer_name(app: &App, detached: bool) -> Option<String> {
    if detached {
        return None;
    }
    if let Some(env_name) = env_nonempty(ENV_NAME) {
        return Some(env_name);
    }
    let name = app.store.signer_name();
    if let Some(name) = &name {
        println!("Using signer name from config: {name}");
        println!("  (override with REVENANT_NAME env, reconfigure with: revenant setup)");
    }
    name
}

/// Print the run header.
fn print_header(url: &str, cred_source: CredSource, detached: bool, args: &SignArgs) {
    let mode_label = if detached {
        "detached .p7s"
    } else {
        "embedded PDF"
    };
    println!("Revenant CLI v{VERSION}");
    println!("Endpoint: {url}");
    if args.dry_run {
        println!("Mode: DRY RUN (no actual signing)");
    } else {
        println!("Credentials: {}", cred_source.label());
        println!("Mode: {mode_label}");
    }
    if !detached {
        println!("Position: {}, Page: {}", args.position, args.page);
    }
    println!();
}

/// A trimmed, non-empty environment variable value, or `None`.
fn env_nonempty(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}
