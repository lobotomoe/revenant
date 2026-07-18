// SPDX-License-Identifier: Apache-2.0
//! `cert` — show signer certificate details and expiration.
//!
//! With `--pdf`, extracts the signer certificate(s) from a signed PDF offline.
//! Otherwise fetches the caller's certificate from the configured server via the
//! enum-certificates / dummy-hash discovery flow.

use std::fs;
use std::path::Path;
use std::sync::Arc;

use revenant_core::config::register_active_profile_tls;
use revenant_core::net::SoapSigningTransport;
use revenant_core::pki::{
    discover_identity_from_server, format_expiry_summary, format_validity_period, CertInfo,
};
use revenant_core::RevenantError;

use crate::app::App;
use crate::cli::CertArgs;
use crate::exit::{CliError, CliResult};
use crate::output::{file_name, format_size_kb};
use crate::prompt::prompt_credentials;

/// `cert` — dispatch to the PDF or server source.
pub(crate) fn cert(app: &App, args: &CertArgs) -> CliResult {
    match &args.pdf {
        Some(pdf) => cert_from_pdf(Path::new(pdf)),
        None => cert_from_server(app),
    }
}

/// Extract and print signer certificate info from a signed PDF.
fn cert_from_pdf(pdf_path: &Path) -> CliResult {
    if !pdf_path.exists() {
        return Err(CliError::new(format!("{} not found", pdf_path.display())));
    }
    let pdf_bytes = fs::read(pdf_path)
        .map_err(|e| CliError::new(format!("cannot read {}: {e}", pdf_path.display())))?;

    println!(
        "Reading {} ({})...",
        file_name(pdf_path),
        format_size_kb(pdf_bytes.len())
    );

    let certs = CertInfo::all_from_pdf(&pdf_bytes)?;
    let count = certs.len();
    for (index, info) in certs.iter().enumerate() {
        if count > 1 {
            println!("\nCertificate [{}/{count}]:", index + 1);
        } else {
            println!("\nCertificate:");
        }
        print_cert_info(info, "  ");
    }
    Ok(())
}

/// Fetch and print the caller's certificate from the configured server.
fn cert_from_server(app: &App) -> CliResult {
    let Some(config) = app.store.server_config() else {
        return Err(CliError::new(
            "no server configured. Run 'revenant setup' first.",
        ));
    };
    let timeout = config.timeout_duration();
    let url = config.url;

    let (username, password) = resolve_or_prompt_credentials(app)?;

    register_active_profile_tls(&app.transport, &app.store);
    let soap = SoapSigningTransport::new(Arc::clone(&app.transport), &url);

    println!("Fetching certificate from {url}...");
    let info = match discover_identity_from_server(&soap, &username, &password, timeout) {
        Ok(info) => info,
        Err(RevenantError::Auth(message)) => {
            return Err(CliError::new(format!("authentication failed: {message}")));
        }
        Err(RevenantError::Tls { message, .. }) => {
            return Err(CliError::new(format!("connection failed: {message}")));
        }
        Err(e) => return Err(CliError::new(e.to_string())),
    };

    println!("\nCertificate:");
    print_cert_info(&info, "  ");
    Ok(())
}

/// Resolve credentials from env/session/config; if either is missing, prompt for
/// both without pre-filling the one we do have.
fn resolve_or_prompt_credentials(app: &App) -> Result<(String, String), CliError> {
    let resolved = app.store.resolve_credentials();
    let username = resolved.username.filter(|u| !u.is_empty());
    let password = resolved.password.filter(|p| !p.is_empty());
    if let (Some(username), Some(password)) = (username, password) {
        return Ok((username, password.expose().to_owned()));
    }
    prompt_credentials(None, None)
}

/// Print the identity fields, validity window, and expiry status.
fn print_cert_info(info: &CertInfo, indent: &str) {
    if let Some(name) = info.name.as_deref().filter(|s| !s.is_empty()) {
        println!("{indent}Subject:      {name}");
    }
    if let Some(org) = info.organization.as_deref().filter(|s| !s.is_empty()) {
        println!("{indent}Organization: {org}");
    }
    if let Some(email) = info.email.as_deref().filter(|s| !s.is_empty()) {
        println!("{indent}Email:        {email}");
    }
    if let Some(dn) = info.dn.as_deref().filter(|s| !s.is_empty()) {
        println!("{indent}DN:           {dn}");
    }

    let validity = format_validity_period(info.not_before.as_deref(), info.not_after.as_deref());
    println!("{indent}Valid:        {validity}");
    println!(
        "{indent}Status:       {}",
        format_expiry_summary(info.not_after.as_deref())
    );
}
