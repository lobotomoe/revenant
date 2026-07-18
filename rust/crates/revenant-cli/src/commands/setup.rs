// SPDX-License-Identifier: Apache-2.0
//! `setup` — the interactive configuration wizard.
//!
//! Walks the user through choosing a server profile (built-in or a custom URL),
//! pinging it, entering credentials, discovering the signer identity (from the
//! server, or manually), and saving everything.

use std::io::{self, Write};
use std::sync::Arc;
use std::time::Duration;

use revenant_core::config::{
    register_profile_tls_mode, IdentityMethod, ServerProfile, SignerInfo, BUILTIN_PROFILES,
};
use revenant_core::constants::{DEFAULT_TIMEOUT_HTTP_GET, ENV_NAME, ENV_URL};
use revenant_core::net::{ping_server, PingOutcome, SoapSigningTransport};
use revenant_core::pki::{discover_identity_from_server, CertInfo};
use revenant_core::RevenantError;

use crate::app::App;
use crate::cli::SetupArgs;
use crate::exit::{CliError, CliResult};
use crate::prompt::{
    confirm_choice, offer_save_credentials, print_auth_failure, prompt_credentials, read_line,
};

/// `setup` — configure server, credentials, and signer identity.
pub(crate) fn setup(app: &App, args: &SetupArgs) -> CliResult {
    println!("Revenant Setup Wizard");
    println!("{}", "=".repeat(40));
    println!();

    print_current_config(app);

    // Step 1: choose a server profile.
    let profile = choose_profile(args.profile.as_deref())?;
    // Pre-register the TLS mode so every request uses the right strategy.
    register_profile_tls_mode(app.transport.as_ref(), &profile);

    // Step 2: ping the server.
    ping(app, &profile)?;

    // Step 3: credentials.
    let (username, password) = get_setup_credentials(&profile)?;

    // Step 4: discover the signer identity.
    let timeout = Duration::from_secs(u64::from(profile.timeout));
    let Some(info) = discover_identity(app, &profile, &username, &password, timeout) else {
        println!("\nSetup cancelled (no signer identity configured).");
        return Err(CliError::silent());
    };

    // Step 5: save everything, then offer to persist the credentials.
    save_config(app, &profile, &info)?;
    offer_save_credentials(&app.store, &username, &password);
    Ok(())
}

/// Show the current configuration, if any identity or credentials are saved.
fn print_current_config(app: &App) {
    let current = app.store.signer_info();
    let saved_user = app.store.saved_username();
    let Some(profile) = app.store.active_profile() else {
        return;
    };
    let has_name = current.name.as_deref().is_some_and(|n| !n.is_empty());
    if !has_name && saved_user.is_none() {
        return;
    }

    println!("Current configuration:");
    println!("  Profile:      {}", profile.display_name);
    println!("  URL:          {}", profile.url);
    if let Some(name) = current.name.as_deref().filter(|n| !n.is_empty()) {
        println!("  Name:         {name}");
    }
    if let Some(email) = current.email.as_deref().filter(|s| !s.is_empty()) {
        println!("  Email:        {email}");
    }
    if let Some(org) = current.organization.as_deref().filter(|s| !s.is_empty()) {
        println!("  Organization: {org}");
    }
    if let Some(user) = &saved_user {
        println!("  Credentials:  saved (user: {user})");
    }
    println!("  Config file:  {}", app.store.config_file().display());
    println!();
}

/// Step 1: choose a built-in profile or enter a custom server URL.
fn choose_profile(preset: Option<&str>) -> Result<ServerProfile, CliError> {
    if let Some(name) = preset {
        let profile = ServerProfile::builtin(name)?;
        println!("Using profile: {}", profile.display_name);
        println!("  URL: {}", profile.url);
        return Ok(profile);
    }

    println!("Choose a CoSign server:\n");
    let profiles: Vec<&ServerProfile> = BUILTIN_PROFILES.values().collect();
    for (index, profile) in profiles.iter().enumerate() {
        println!("  {}. {}", index + 1, profile.display_name);
    }
    println!("  {}. Custom server (enter URL)", profiles.len() + 1);
    println!();

    let Some(choice) = read_line(&format!("Your choice [1-{}]: ", profiles.len() + 1)) else {
        return Err(CliError::silent());
    };
    let index = match choice.parse::<usize>() {
        Ok(n) if n >= 1 && n <= profiles.len() + 1 => n - 1,
        _ => {
            eprintln!("Invalid choice.");
            return Err(CliError::silent());
        }
    };

    if let Some(profile) = profiles.get(index) {
        let profile = (*profile).clone();
        println!("\nSelected: {}", profile.display_name);
        println!("  URL: {}", profile.url);
        return Ok(profile);
    }

    // The last option: a custom server URL.
    let Some(url) = read_line("\nServer SOAP URL (e.g. https://host:port/SAPIWS/DSS.asmx): ")
    else {
        return Err(CliError::silent());
    };
    if url.is_empty() {
        return Err(CliError::new("URL is required."));
    }
    Ok(ServerProfile::custom_default(&url)?)
}

/// Step 2: ping the server (WSDL fetch) and show its TLS mode.
fn ping(app: &App, profile: &ServerProfile) -> Result<(), CliError> {
    print!("\nContacting {}... ", profile.url);
    let _ = io::stdout().flush();

    let info = match ping_server(
        app.transport.as_ref(),
        &profile.url,
        DEFAULT_TIMEOUT_HTTP_GET,
    ) {
        PingOutcome::Failed(info) => {
            println!("FAILED");
            eprintln!("  {info}");
            eprintln!("\nCheck the URL and try again.");
            return Err(CliError::silent());
        }
        PingOutcome::Ok(info) => info,
    };

    println!("OK ({info})");
    if let Some(host) = url::Url::parse(&profile.url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_owned))
    {
        if let Some(tls_info) = app.transport.host_tls_info(&host) {
            println!("  TLS: {tls_info}");
        }
    }
    Ok(())
}

/// Step 3: get credentials, warning about the account-lockout threshold.
fn get_setup_credentials(profile: &ServerProfile) -> Result<(String, String), CliError> {
    println!();
    if profile.max_auth_attempts > 0 {
        println!(
            "WARNING: account locks after {} failed attempts!",
            profile.max_auth_attempts
        );
        println!();
    }
    prompt_credentials(None, None)
}

/// Step 4: try each identity-discovery method the profile supports, in order.
fn discover_identity(
    app: &App,
    profile: &ServerProfile,
    username: &str,
    password: &str,
    timeout: Duration,
) -> Option<CertInfo> {
    profile
        .identity_methods
        .iter()
        .find_map(|method| match method {
            IdentityMethod::Server => {
                try_identity_from_server(app, &profile.url, username, password, timeout)
            }
            IdentityMethod::Manual => try_identity_manual(),
        })
}

/// Discover identity by driving the signing service, confirming with the user.
fn try_identity_from_server(
    app: &App,
    url: &str,
    username: &str,
    password: &str,
    timeout: Duration,
) -> Option<CertInfo> {
    print!("\nDiscovering signer identity from server... ");
    let _ = io::stdout().flush();

    let soap = SoapSigningTransport::new(Arc::clone(&app.transport), url);
    let info = match discover_identity_from_server(&soap, username, password, timeout) {
        Ok(info) => info,
        Err(RevenantError::Auth(message)) => {
            println!("FAILED");
            print_auth_failure(&message, None);
            return None;
        }
        Err(e) => {
            println!("FAILED");
            eprintln!("  {e}");
            println!("  (will try other methods)");
            return None;
        }
    };

    if info.name.as_deref().is_none_or(str::is_empty) {
        println!("no signer name found");
        return None;
    }

    println!("OK");
    print_signer_info(&info);
    confirm_choice("\nIs this you?", true).then_some(info)
}

/// Prompt the user to enter their identity by hand.
fn try_identity_manual() -> Option<CertInfo> {
    println!("\nEnter signer identity manually:");

    // EOF/cancel at any prompt aborts identity entry; an empty Name line is the
    // one hard error.
    let name = read_line("  Name (CN): ")?;
    if name.is_empty() {
        eprintln!("  Name is required.");
        return None;
    }
    let email = read_line("  Email (optional): ")?;
    let organization = read_line("  Organization (optional): ")?;

    Some(CertInfo {
        name: Some(name),
        email: (!email.is_empty()).then_some(email),
        organization: (!organization.is_empty()).then_some(organization),
        dn: None,
        not_before: None,
        not_after: None,
    })
}

/// Display discovered signer certificate info.
fn print_signer_info(info: &CertInfo) {
    println!("\n  Name (CN):    {}", info.name.as_deref().unwrap_or(""));
    if let Some(email) = info.email.as_deref().filter(|s| !s.is_empty()) {
        println!("  Email:        {email}");
    }
    if let Some(org) = info.organization.as_deref().filter(|s| !s.is_empty()) {
        println!("  Organization: {org}");
    }
    if let Some(dn) = info.dn.as_deref().filter(|s| !s.is_empty()) {
        println!("  Full DN:      {dn}");
    }
}

/// Step 5: persist the server profile and signer identity.
fn save_config(app: &App, profile: &ServerProfile, info: &CertInfo) -> CliResult {
    app.store.save_server_config(profile)?;
    let signer = SignerInfo {
        name: Some(info.name.clone().unwrap_or_default()),
        email: info.email.clone(),
        organization: info.organization.clone(),
        dn: info.dn.clone(),
        not_before: info.not_before.clone(),
        not_after: info.not_after.clone(),
    };
    app.store.save_signer_info(&signer)?;

    println!("\nSaved to {}", app.store.config_file().display());
    println!("  Server:  {}", profile.display_name);
    println!("  Signer:  {}", info.name.as_deref().unwrap_or(""));
    println!("Override anytime with {ENV_URL} / {ENV_NAME} env variables.");
    Ok(())
}
