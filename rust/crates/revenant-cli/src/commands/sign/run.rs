// SPDX-License-Identifier: Apache-2.0
//! Per-file signing execution: the batch loop and the single-file signers.
//!
//! The orchestration layer ([`super`]) resolves credentials, the server, and
//! appearance defaults, then hands a [`SignContext`] and [`EmbeddedSelectors`]
//! here to run. Each file prints its own progress and produces a [`SignOutcome`]
//! the batch loop uses to count successes and to stop on an authentication
//! failure.

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use revenant_core::config::register_active_profile_tls;
use revenant_core::constants::{BYTES_PER_MB, PDF_WARN_SIZE};
use revenant_core::net::SoapSigningTransport;
use revenant_core::pdf::{PageSpec, Position};
use revenant_core::signing::{sign_pdf_detached, sign_pdf_embedded, EmbeddedSignatureOptions};
use revenant_core::RevenantError;

use crate::app::App;
use crate::output::{
    atomic_write, default_detached_output_path, default_output_path, file_name, format_size_kb,
};
use crate::prompt::print_auth_failure;

/// The outcome of signing one file, carrying just what the batch loop and the
/// completion messages need.
enum SignOutcome {
    Ok { size: usize },
    AuthFailed(String),
    TlsError(String),
    Failed(String),
}

/// Server, credential, and timeout context shared across every file in a batch.
pub(super) struct SignContext<'a> {
    pub(super) app: &'a App,
    pub(super) username: &'a str,
    pub(super) password: &'a str,
    pub(super) url: &'a str,
    pub(super) timeout: Duration,
    pub(super) output: Option<&'a str>,
}

/// Embedded-signature appearance selectors shared across a batch.
pub(super) struct EmbeddedSelectors<'a> {
    pub(super) name: Option<&'a str>,
    pub(super) position: Position,
    pub(super) position_label: &'a str,
    pub(super) page: PageSpec,
    pub(super) image: Option<&'a str>,
    pub(super) visible: bool,
    pub(super) font: Option<&'a str>,
    pub(super) reason: &'a str,
    pub(super) fields: Option<&'a [String]>,
    pub(super) dry_run: bool,
}

/// Run each file through the appropriate signer, stopping the batch on the first
/// authentication failure. Returns `(success, failed)` counts.
pub(super) fn run_batch(
    ctx: &SignContext<'_>,
    params: &EmbeddedSelectors<'_>,
    files: &[String],
    detached: bool,
) -> (usize, usize) {
    let mut success = 0usize;
    let mut failed = 0usize;

    for pdf_file in files {
        let outcome = if detached {
            if params.dry_run {
                println!(
                    "  Would sign: {} (detached .p7s)",
                    file_name(Path::new(pdf_file))
                );
                SignOutcome::Ok { size: 0 }
            } else {
                sign_one_detached(ctx, pdf_file)
            }
        } else {
            sign_one_embedded(ctx, params, pdf_file)
        };

        match outcome {
            SignOutcome::Ok { .. } => success += 1,
            SignOutcome::AuthFailed(_) => {
                failed += 1;
                let remaining = files.len() - success - failed;
                if remaining > 0 {
                    eprintln!(
                        "\n  Stopping: {remaining} file(s) skipped to prevent account lockout."
                    );
                }
                break;
            }
            SignOutcome::TlsError(_) | SignOutcome::Failed(_) => failed += 1,
        }
    }
    (success, failed)
}

/// Sign one file with an embedded signature, printing progress.
fn sign_one_embedded(
    ctx: &SignContext<'_>,
    params: &EmbeddedSelectors<'_>,
    pdf_file: &str,
) -> SignOutcome {
    let pdf_path = Path::new(pdf_file);
    let pdf_bytes = match read_pdf(pdf_path) {
        Ok(bytes) => bytes,
        // Report read failures uniformly, like every other per-file failure.
        Err(message) => {
            print_failed(&message);
            return SignOutcome::Failed(message);
        }
    };
    warn_if_large(pdf_path, pdf_bytes.len());

    let out = ctx
        .output
        .map_or_else(|| default_output_path(pdf_path), PathBuf::from);

    if params.dry_run {
        print_dry_run(pdf_path, pdf_bytes.len(), &out, params);
        return SignOutcome::Ok { size: 0 };
    }

    print!(
        "  Signing {} ({})... ",
        file_name(pdf_path),
        format_size_kb(pdf_bytes.len())
    );
    let _ = io::stdout().flush();

    let opts = EmbeddedSignatureOptions {
        page: params.page,
        position: params.position,
        name: params.name.map(str::to_owned),
        image_path: params.image.map(str::to_owned),
        fields: params.fields.map(<[String]>::to_vec),
        visible: params.visible,
        font: params.font.map(str::to_owned),
        reason: params.reason.to_owned(),
        ..EmbeddedSignatureOptions::default()
    };
    let soap = build_soap(ctx.app, ctx.url);
    let outcome = match sign_pdf_embedded(
        &pdf_bytes,
        &soap,
        ctx.username,
        ctx.password,
        ctx.timeout,
        &opts,
    ) {
        Ok(signed) => write_output(&out, &signed),
        Err(e) => classify(e),
    };
    report(&outcome, &out, ctx.app, false);
    outcome
}

/// Sign one file with a detached `.p7s`, printing progress.
fn sign_one_detached(ctx: &SignContext<'_>, pdf_file: &str) -> SignOutcome {
    let pdf_path = Path::new(pdf_file);
    let pdf_bytes = match read_pdf(pdf_path) {
        Ok(bytes) => bytes,
        // Report read failures uniformly, like every other per-file failure.
        Err(message) => {
            print_failed(&message);
            return SignOutcome::Failed(message);
        }
    };
    warn_if_large(pdf_path, pdf_bytes.len());

    let sig_path = ctx
        .output
        .map_or_else(|| default_detached_output_path(pdf_path), PathBuf::from);

    print!(
        "  Signing {} ({})... ",
        file_name(pdf_path),
        format_size_kb(pdf_bytes.len())
    );
    let _ = io::stdout().flush();

    let soap = build_soap(ctx.app, ctx.url);
    let outcome =
        match sign_pdf_detached(&pdf_bytes, &soap, ctx.username, ctx.password, ctx.timeout) {
            Ok(cms) => write_output(&sig_path, &cms),
            Err(e) => classify(e),
        };
    report(&outcome, &sig_path, ctx.app, true);
    outcome
}

/// Write signed output atomically, mapping I/O failures to an outcome.
fn write_output(path: &Path, data: &[u8]) -> SignOutcome {
    match atomic_write(path, data) {
        Ok(()) => SignOutcome::Ok { size: data.len() },
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
            SignOutcome::Failed(format!("Permission denied: {}", path.display()))
        }
        Err(e) => SignOutcome::Failed(format!("cannot write {}: {e}", path.display())),
    }
}

/// Print the completion line for one file. `detached` selects the byte-count
/// form of the success message.
fn report(outcome: &SignOutcome, out: &Path, app: &App, detached: bool) {
    match outcome {
        SignOutcome::Ok { size } if detached => {
            println!("OK -> {} ({size} bytes)", file_name(out));
        }
        SignOutcome::Ok { size } => {
            println!("OK -> {} ({})", file_name(out), format_size_kb(*size));
        }
        SignOutcome::AuthFailed(message) => {
            print_auth_failure(message, app.store.active_profile().as_ref());
        }
        SignOutcome::TlsError(message) => {
            eprintln!("TLS ERROR");
            eprintln!("  {message}");
        }
        SignOutcome::Failed(message) => print_failed(message),
    }
}

/// Print the dry-run description for an embedded signature.
fn print_dry_run(pdf_path: &Path, size: usize, out: &Path, params: &EmbeddedSelectors<'_>) {
    println!(
        "  Would sign: {} ({})",
        file_name(pdf_path),
        format_size_kb(size)
    );
    println!("    -> Output: {}", file_name(out));
    println!(
        "    -> Position: {}, Page: {}",
        params.position_label,
        page_display(params.page)
    );
    if let Some(image) = params.image {
        println!("    -> Image: {image}");
    }
}

/// A 1-based, human-friendly page label for the dry-run output.
fn page_display(page: PageSpec) -> String {
    match page {
        PageSpec::First => "first".to_owned(),
        PageSpec::Last => "last".to_owned(),
        PageSpec::Index(index) => (index + 1).to_string(),
    }
}

/// Register the active profile's TLS mode and build the SOAP transport.
fn build_soap(app: &App, url: &str) -> SoapSigningTransport {
    register_active_profile_tls(app.transport.as_ref(), &app.store);
    SoapSigningTransport::new(Arc::clone(&app.transport), url)
}

/// Classify a signing error into an outcome for messaging + batch control.
fn classify(error: RevenantError) -> SignOutcome {
    match error {
        RevenantError::Auth(message) => SignOutcome::AuthFailed(message),
        RevenantError::Tls { message, .. } => SignOutcome::TlsError(message),
        other => SignOutcome::Failed(other.to_string()),
    }
}

/// Read a PDF for signing, returning a descriptive message on failure.
fn read_pdf(pdf_path: &Path) -> Result<Vec<u8>, String> {
    if !pdf_path.exists() {
        return Err(format!("PDF not found: {}", pdf_path.display()));
    }
    std::fs::read(pdf_path).map_err(|e| format!("cannot read {}: {e}", pdf_path.display()))
}

/// Print the standard two-line failure block to stderr.
fn print_failed(message: &str) {
    eprintln!("FAILED");
    eprintln!("  {message}");
}

/// Warn (to stderr) when a file exceeds the reliable-size threshold.
fn warn_if_large(pdf_path: &Path, size: usize) {
    if size > PDF_WARN_SIZE {
        let size_mb = (size + BYTES_PER_MB / 2) / BYTES_PER_MB;
        let warn_mb = PDF_WARN_SIZE / BYTES_PER_MB;
        eprintln!(
            "  Warning: {} is {size_mb} MB. Files over {warn_mb} MB may be slow or fail.",
            file_name(pdf_path)
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_display_labels() {
        assert_eq!(page_display(PageSpec::First), "first");
        assert_eq!(page_display(PageSpec::Last), "last");
        // Index is 0-based internally; the label is 1-based.
        assert_eq!(page_display(PageSpec::Index(0)), "1");
        assert_eq!(page_display(PageSpec::Index(41)), "42");
    }
}
