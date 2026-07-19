// SPDX-License-Identifier: Apache-2.0
//! `check` — verify the embedded signature(s) of a signed PDF.
//!
//! Runs the offline structural + hash checks (and, when the active profile has a
//! Trust Service List, chain validation) on every embedded signature, then
//! optionally a server-side `DssVerify`. Exits non-zero if any signature fails.

use std::fs;
use std::path::Path;

use revenant_sign_core::api::verify_pdf_all;
use revenant_sign_core::config::{register_active_profile_tls, TrustAnchors};
use revenant_sign_core::net::{verify_pdf_server, ServerVerifyResult};
use revenant_sign_core::pki::TrustStoreCache;

use crate::app::App;
use crate::cli::CheckArgs;
use crate::commands::report::{print_result_line, print_signature_details};
use crate::exit::{CliError, CliResult};
use crate::output::{file_name, format_size_kb};

/// `check` — verify embedded signatures and report the overall result.
pub(crate) fn check(app: &App, args: &CheckArgs) -> CliResult {
    let pdf_path = Path::new(&args.pdf);
    if !pdf_path.exists() {
        return Err(CliError::new(format!("{} not found", pdf_path.display())));
    }
    let pdf_bytes = fs::read(pdf_path)
        .map_err(|e| CliError::new(format!("cannot read {}: {e}", pdf_path.display())))?;

    println!(
        "Checking {} ({})...",
        file_name(pdf_path),
        format_size_kb(pdf_bytes.len())
    );

    // Chain validation uses the active profile's configured trust anchors
    // (pinned CAs or a TSL); an unconfigured profile leaves trust indeterminate.
    let trust = app
        .store
        .active_profile()
        .map_or(TrustAnchors::None, |p| p.trust);
    let cache = TrustStoreCache::new();
    let results = match verify_pdf_all(app.transport.as_ref(), &cache, &pdf_bytes, &trust) {
        Ok(results) => results,
        Err(e) => {
            eprintln!("  ERROR: {e}");
            return Err(CliError::silent());
        }
    };

    print_signature_details(&results);

    if args.server {
        run_server_verification(app, &pdf_bytes);
    }

    print_result_line(&results)
}

/// Run the optional server-side verification and print its outcome.
fn run_server_verification(app: &App, pdf_bytes: &[u8]) {
    match app.store.server_config() {
        Some(config) => {
            println!("\n  Server verification...");
            register_active_profile_tls(app.transport.as_ref(), &app.store);
            let result = verify_pdf_server(
                app.transport.as_ref(),
                &config.url,
                pdf_bytes,
                config.timeout_duration(),
            );
            print_server_verify_result(&result);
        }
        None => println!("\n  Server verification skipped: no server configured."),
    }
}

/// Print the server verification result.
fn print_server_verify_result(result: &ServerVerifyResult) {
    match result {
        ServerVerifyResult::Failed(error) => {
            println!("  Server: unavailable ({error})");
        }
        ServerVerifyResult::Verified {
            signer_name,
            sign_time,
            certificate_status,
        } => {
            if let Some(signer) = signer_name {
                println!("  Server signer: {signer}");
            }
            if let Some(sign_time) = sign_time {
                println!("  Server sign time: {sign_time}");
            }
            if let Some(status) = certificate_status {
                println!("  Server certificate: {status}");
            }
            println!("  Server: VALID");
        }
    }
}
