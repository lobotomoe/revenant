// SPDX-License-Identifier: Apache-2.0
//! `verify` and `info` — offline signature checking and inspection.
//!
//! `verify` checks a detached CMS signature against its PDF by shelling out to
//! `openssl cms -verify`: this reuses the system trust store for chain
//! verification and degrades gracefully when OpenSSL is absent. `info` lists the
//! certificates embedded in a CMS file using the in-crate ASN.1 reader -- no
//! external tools.

use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use revenant_sign_core::pki::{format_expiry_summary, summarize_cms_certificates};
use wait_timeout::ChildExt;

use crate::cli::{InfoArgs, VerifyArgs};
use crate::exit::{CliError, CliResult};
use crate::output::{default_detached_output_path, file_name};

/// How long to wait for `openssl` before giving up.
const OPENSSL_TIMEOUT: Duration = Duration::from_secs(15);

/// Verify a detached CMS signature against its PDF via `openssl cms -verify`.
pub(crate) fn verify(args: &VerifyArgs) -> CliResult {
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

    println!(
        "Verifying {} against {}...",
        file_name(pdf_path),
        file_name(&sig_path)
    );
    println!("  Using system trust store for chain verification");

    run_openssl_verify(pdf_path, &sig_path)
}

/// Spawn `openssl`, wait with a timeout, and interpret the result.
fn run_openssl_verify(pdf_path: &Path, sig_path: &Path) -> CliResult {
    // openssl writes the recovered content to stdout; discard it (we only care
    // about the exit status and the diagnostics on stderr). Discarding rather
    // than capturing also avoids a pipe-buffer deadlock on large content.
    let spawn = Command::new("openssl")
        .arg("cms")
        .arg("-verify")
        .arg("-inform")
        .arg("DER")
        .arg("-in")
        .arg(sig_path)
        .arg("-content")
        .arg(pdf_path)
        .arg("-binary")
        .arg("-purpose")
        .arg("any")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn();

    let mut child = match spawn {
        Ok(child) => child,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Err(CliError::new(
                "openssl not found. Install OpenSSL to verify signatures.",
            ));
        }
        Err(e) => return Err(CliError::new(format!("failed to run openssl: {e}"))),
    };

    match child.wait_timeout(OPENSSL_TIMEOUT) {
        Ok(Some(status)) => {
            let stderr = read_stderr(&mut child);
            let stderr = stderr.trim();
            if status.success() {
                println!("  VALID: Signature verification succeeded.");
                if stderr.contains("Verification successful") {
                    println!("  {stderr}");
                }
                Ok(())
            } else {
                println!("  INVALID: {stderr}");
                Err(CliError::silent())
            }
        }
        Ok(None) => {
            let _ = child.kill();
            let _ = child.wait();
            Err(CliError::new("openssl timed out after 15 seconds."))
        }
        Err(e) => Err(CliError::new(format!("failed to wait for openssl: {e}"))),
    }
}

/// Drain the child's stderr pipe to a string (best effort).
fn read_stderr(child: &mut std::process::Child) -> String {
    let mut buf = String::new();
    if let Some(mut stderr) = child.stderr.take() {
        let _ = stderr.read_to_string(&mut buf);
    }
    buf
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
