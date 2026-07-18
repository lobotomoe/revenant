// SPDX-License-Identifier: Apache-2.0
//! `check` — verify the embedded signature(s) of a signed PDF.
//!
//! Runs the offline structural + hash checks (and, when the active profile has a
//! Trust Service List, chain validation) on every embedded signature, then
//! optionally a server-side `DssVerify`. Exits non-zero if any signature fails.

use std::fs;
use std::path::Path;

use revenant_core::api::verify_pdf_all;
use revenant_core::config::register_active_profile_tls;
use revenant_core::net::{verify_pdf_server, ServerVerifyResult};
use revenant_core::pdf::VerificationResult;
use revenant_core::pki::TrustStoreCache;

use crate::app::App;
use crate::cli::CheckArgs;
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

    // Chain validation uses the active profile's Trust Service List, if any.
    let tsl_url = app.store.active_profile().and_then(|p| p.tsl_url);
    let cache = TrustStoreCache::new();
    let results = match verify_pdf_all(
        app.transport.as_ref(),
        &cache,
        &pdf_bytes,
        tsl_url.as_deref(),
    ) {
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

/// Print each signature's diagnostic lines, prefixed and numbered when several.
fn print_signature_details(results: &[VerificationResult]) {
    let total = results.len();
    for (index, result) in results.iter().enumerate() {
        let indent = if total > 1 {
            let signer_name = result
                .signer
                .as_ref()
                .and_then(|s| s.name.as_deref())
                .unwrap_or("Unknown");
            println!("\n  Signature {}/{total} ({signer_name}):", index + 1);
            "    "
        } else {
            "  "
        };
        for detail in &result.details {
            for line in detail.split('\n') {
                println!("{indent}{line}");
            }
        }
    }
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

/// Print the final RESULT line and return the process outcome.
fn print_result_line(results: &[VerificationResult]) -> CliResult {
    let total = results.len();
    let failed = results.iter().filter(|r| !r.valid()).count();

    println!();
    if failed == 0 {
        let sig_word = if total == 1 {
            "Signature".to_owned()
        } else {
            format!("All {total} signatures")
        };
        println!("  RESULT: {sig_word} VALID");
        Ok(())
    } else {
        println!("  RESULT: {failed} of {total} signature(s) FAILED");
        Err(CliError::silent())
    }
}
