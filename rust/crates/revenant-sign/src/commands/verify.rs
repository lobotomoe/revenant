// SPDX-License-Identifier: Apache-2.0
//! `verify` and `info` — offline signature checking and inspection.
//!
//! `verify` checks a detached CMS signature against its PDF entirely in-crate:
//! it verifies the CMS signature and message digest, then validates the signer
//! chain against the active profile's pinned trust anchors (the same in-crate
//! path `check` uses for embedded signatures -- no external `openssl`, and the
//! bundled anchors mean a genuine signature is recognised as trusted). `info`
//! lists the certificates in a CMS file using the in-crate ASN.1 reader.

use std::fs;
use std::path::{Path, PathBuf};

use revenant_sign_core::api::verify_detached;
use revenant_sign_core::config::TrustAnchors;
use revenant_sign_core::pki::{format_expiry_summary, summarize_cms_certificates, TrustStoreCache};

use crate::app::App;
use crate::cli::{InfoArgs, VerifyArgs};
use crate::commands::report::{print_result_line, print_signature_details};
use crate::exit::{CliError, CliResult};
use crate::output::{default_detached_output_path, file_name};

/// Verify a detached CMS signature against its PDF, entirely in-crate.
pub(crate) fn verify(app: &App, args: &VerifyArgs) -> CliResult {
    let pdf_path = Path::new(&args.pdf);
    let sig_path: PathBuf = match &args.signature {
        Some(sig) => PathBuf::from(sig),
        None => default_detached_output_path(pdf_path),
    };

    if !pdf_path.exists() {
        return Err(CliError::new(format!("{} not found", pdf_path.display())));
    }
    if !sig_path.exists() {
        return Err(CliError::new(format!("{} not found", sig_path.display())));
    }

    let pdf_bytes = fs::read(pdf_path)
        .map_err(|e| CliError::new(format!("cannot read {}: {e}", pdf_path.display())))?;
    let cms_der = fs::read(&sig_path)
        .map_err(|e| CliError::new(format!("cannot read {}: {e}", sig_path.display())))?;

    println!(
        "Verifying {} against {}...",
        file_name(pdf_path),
        file_name(&sig_path)
    );

    // Chain validation uses the active profile's trust anchors (pinned CAs or a
    // TSL). An unconfigured profile leaves trust indeterminate, but the
    // signature's cryptographic validity and content digest are still checked.
    let trust = app
        .store
        .active_profile()
        .map_or(TrustAnchors::None, |p| p.trust);
    let cache = TrustStoreCache::new();
    let result = verify_detached(app.transport.as_ref(), &cache, &pdf_bytes, &cms_der, &trust);

    print_signature_details(std::slice::from_ref(&result));
    print_result_line(std::slice::from_ref(&result))
}

/// Show the certificates in a CMS signature file.
pub(crate) fn info(args: &InfoArgs) -> CliResult {
    let sig_path = Path::new(&args.signature);
    if !sig_path.exists() {
        return Err(CliError::new(format!("{} not found", sig_path.display())));
    }

    let metadata = fs::metadata(sig_path)
        .map_err(|e| CliError::new(format!("cannot access {}: {e}", sig_path.display())))?;
    println!(
        "Signature: {} ({} bytes)",
        file_name(sig_path),
        metadata.len()
    );

    let sig_bytes = fs::read(sig_path)
        .map_err(|e| CliError::new(format!("reading {}: {e}", sig_path.display())))?;

    let summaries = match summarize_cms_certificates(&sig_bytes) {
        Ok(summaries) => summaries,
        Err(e) => {
            // Report the parse error but exit 0: `info` is best-effort inspection.
            eprintln!("  Error parsing signature: {e}");
            return Ok(());
        }
    };

    if summaries.is_empty() {
        println!("  No certificates found in signature.");
        return Ok(());
    }

    let count = summaries.len();
    println!("\nCertificates ({count}):");
    for (index, cert) in summaries.iter().enumerate() {
        if count > 1 {
            println!("\n  [{}]", index + 1);
        }
        println!("  Subject: {}", cert.subject);
        println!("  Issuer:  {}", cert.issuer);
        println!("  Serial:  {}", cert.serial);
        println!(
            "  Valid:   {} - {}",
            cert.not_before.as_deref().unwrap_or("?"),
            cert.not_after.as_deref().unwrap_or("?")
        );
        if cert.not_after.is_some() {
            println!(
                "  Status:  {}",
                format_expiry_summary(cert.not_after.as_deref())
            );
        }
    }
    Ok(())
}
