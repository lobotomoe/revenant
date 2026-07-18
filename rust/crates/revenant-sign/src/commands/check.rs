// SPDX-License-Identifier: Apache-2.0
//! `check` — verify the embedded signature(s) of a signed PDF.
//!
//! Runs the offline structural + hash checks (and, when the active profile has a
//! Trust Service List, chain validation) on every embedded signature, then
//! optionally a server-side `DssVerify`. Exits non-zero if any signature fails.

use std::fs;
use std::path::Path;

use revenant_sign_core::api::verify_pdf_all;
use revenant_sign_core::cms::SignatureStatus;
use revenant_sign_core::config::{register_active_profile_tls, TrustAnchors};
use revenant_sign_core::net::{verify_pdf_server, ServerVerifyResult};
use revenant_sign_core::pdf::VerificationResult;
use revenant_sign_core::pki::{TrustStatus, TrustStoreCache};

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

/// Classify one signature into a display label and whether it counts as a pass.
///
/// The verdict reflects the full cryptographic result, not just structure: a
/// signature that does not verify, cannot be verified, or comes from a signer
/// outside the configured trust list does NOT pass. A genuine signature whose
/// trust was simply not checked (no Trust Service List configured) passes with a
/// note, so `check` without a TSL still works.
fn classify(result: &VerificationResult) -> (String, bool) {
    if !result.integrity_ok() {
        return (
            "FAILED -- document structure or hash is broken".to_owned(),
            false,
        );
    }
    match result.signature {
        SignatureStatus::Invalid => {
            return (
                "INVALID -- signature does not verify (document altered)".to_owned(),
                false,
            );
        }
        SignatureStatus::Unverifiable(why) => {
            return (
                format!("UNVERIFIED -- signature could not be checked ({why})"),
                false,
            );
        }
        SignatureStatus::Valid => {}
    }
    match result.trust_status {
        Some(TrustStatus::Untrusted) => (
            "VALID signature, but the signer is NOT in the trusted list".to_owned(),
            false,
        ),
        Some(TrustStatus::Trusted) => ("VALID and trusted".to_owned(), true),
        // Indeterminate / None: the signature is genuine; trust was not established.
        _ => ("VALID (signer trust not checked)".to_owned(), true),
    }
}

/// Print the final RESULT line(s) and return the process outcome.
fn print_result_line(results: &[VerificationResult]) -> CliResult {
    let total = results.len();
    let verdicts: Vec<(String, bool)> = results.iter().map(classify).collect();
    let passed = verdicts.iter().filter(|(_, ok)| *ok).count();

    println!();
    if total == 1 {
        let (label, ok) = &verdicts[0];
        println!("  RESULT: {label}");
        return if *ok { Ok(()) } else { Err(CliError::silent()) };
    }
    for (index, (label, _)) in verdicts.iter().enumerate() {
        println!("  Signature {}/{total}: {label}", index + 1);
    }
    if passed == total {
        println!("  RESULT: all {total} signatures VALID");
        Ok(())
    } else {
        println!(
            "  RESULT: {} of {total} signature(s) did not pass",
            total - passed
        );
        Err(CliError::silent())
    }
}
