//! Background work executed on the [`crate::worker::Worker`] thread.
//!
//! These functions are the blocking, networked half of each flow: signing,
//! batch signing, and verification. They take only owned/borrowed data (never
//! `&App`), so they are pure with respect to the UI and easy to test. The app
//! collects their results as [`crate::worker::WorkerMsg`]s and folds them back
//! into the UI state on the main thread.

use std::collections::{HashMap, HashSet};
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use revenant_sign_core::api::{self, ServerChoice};
use revenant_sign_core::config::{ConfigStore, ResolvedServerConfig, SignerInfo, TrustAnchors};
use revenant_sign_core::net::{verify_pdf_server, Transport};
use revenant_sign_core::pki::{CertInfo, TrustStoreCache};
use revenant_sign_core::signing::EmbeddedSignatureOptions;
use revenant_sign_core::RevenantError;

use crate::views;
use crate::worker::{Emit, IdentityOutcome, SignedOutcome, VerifyOutcome, WorkerMsg};

/// Sign `pdf_path` and write the result to `output`, resolving credentials from
/// the store.
pub(crate) fn sign(
    store: &ConfigStore,
    transport: &Arc<Transport>,
    pdf_path: &Path,
    output: &Path,
    detached: bool,
    options: EmbeddedSignatureOptions,
    no_credentials_message: String,
) -> SignedOutcome {
    let creds = store.resolve_credentials();
    let (Some(username), Some(password)) = (creds.username, creds.password) else {
        return SignedOutcome::Failed(no_credentials_message);
    };
    let pdf = match std::fs::read(pdf_path) {
        Ok(bytes) => bytes,
        Err(err) => return SignedOutcome::Failed(err.to_string()),
    };
    let server = ServerChoice::default();
    let result = if detached {
        api::sign_detached(
            store,
            transport,
            &pdf,
            &username,
            password.expose(),
            &server,
        )
    } else {
        api::sign(
            store,
            transport,
            &pdf,
            &username,
            password.expose(),
            &server,
            options,
        )
    };
    match result {
        Ok(bytes) => {
            if let Err(err) = std::fs::write(output, &bytes) {
                return SignedOutcome::Failed(err.to_string());
            }
            let size = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
            SignedOutcome::Ok {
                path: output.to_path_buf(),
                size,
            }
        }
        Err(err) => SignedOutcome::Failed(err.to_string()),
    }
}

/// The signing configuration shared across a batch's files.
pub(crate) struct BatchContext<'a> {
    pub(crate) store: &'a ConfigStore,
    pub(crate) transport: &'a Arc<Transport>,
    pub(crate) detached: bool,
    pub(crate) options: &'a EmbeddedSignatureOptions,
    /// User-selected folder every signed file is written into. Its selection is
    /// what grants write access under the macOS sandbox.
    pub(crate) output_dir: &'a Path,
    /// Localized message for the "no saved credentials" case.
    pub(crate) no_credentials_message: &'a str,
}

/// Sign every file in `files` sequentially, emitting progress before each and a
/// final tally. A fatal error (bad credentials, TLS failure) aborts the whole
/// batch; per-file read/write errors are counted and the run continues.
/// Cancellation is honored between files.
pub(crate) fn batch_sign(
    emit: &Emit<'_>,
    ctx: &BatchContext<'_>,
    files: &[PathBuf],
    cancel: &AtomicBool,
) {
    let creds = ctx.store.resolve_credentials();
    let (Some(username), Some(password)) = (creds.username, creds.password) else {
        emit(WorkerMsg::BatchDone {
            succeeded: 0,
            failed: 0,
            aborted: Some(ctx.no_credentials_message.to_owned()),
        });
        return;
    };
    let total = files.len();
    let server = ServerChoice::default();
    let outputs = batch_output_paths(files, ctx.output_dir, ctx.detached);
    let mut succeeded = 0;
    let mut failed = 0;
    for (index, (path, output)) in files.iter().zip(outputs).enumerate() {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        let filename = path
            .file_name()
            .map_or_else(String::new, |name| name.to_string_lossy().into_owned());
        emit(WorkerMsg::BatchProgress {
            current: index + 1,
            total,
            filename,
        });
        let Ok(pdf) = std::fs::read(path) else {
            failed += 1;
            continue;
        };
        let Some(output) = output else {
            failed += 1;
            continue;
        };
        let result = if ctx.detached {
            api::sign_detached(
                ctx.store,
                ctx.transport,
                &pdf,
                &username,
                password.expose(),
                &server,
            )
        } else {
            api::sign(
                ctx.store,
                ctx.transport,
                &pdf,
                &username,
                password.expose(),
                &server,
                ctx.options.clone(),
            )
        };
        match result {
            Err(err) if is_fatal_batch_error(&err) => {
                emit(WorkerMsg::BatchDone {
                    succeeded,
                    failed,
                    aborted: Some(err.to_string()),
                });
                return;
            }
            Ok(bytes) if write_unique_file(&output, &bytes).is_ok() => succeeded += 1,
            // A non-fatal signing error or a failed write: count it and continue.
            _ => failed += 1,
        }
    }
    emit(WorkerMsg::BatchDone {
        succeeded,
        failed,
        aborted: None,
    });
}

/// Reserve a distinct, currently-unused destination for every batch input.
///
/// File names are derived before any signing request is made. Collisions within
/// the batch, and files already present in the selected directory, receive a
/// numeric suffix rather than being overwritten.
fn batch_output_paths(
    files: &[PathBuf],
    output_dir: &Path,
    detached: bool,
) -> Vec<Option<PathBuf>> {
    let mut reserved = HashSet::with_capacity(files.len());
    let mut next_suffixes = HashMap::new();
    files
        .iter()
        .map(|path| {
            let output = views::sign::default_output(path, detached)
                .file_name()
                .map(|name| output_dir.join(name))?;
            let output = unique_output_path(&output, &reserved, &mut next_suffixes);
            reserved.insert(output.clone());
            Some(output)
        })
        .collect()
}

/// Pick the requested path when available, otherwise add `_2`, `_3`, ...
/// before its final extension until both the filesystem and this batch agree
/// that the name is unused.
fn unique_output_path(
    output: &Path,
    reserved: &HashSet<PathBuf>,
    next_suffixes: &mut HashMap<PathBuf, u64>,
) -> PathBuf {
    if !reserved.contains(output) && !output.exists() {
        return output.to_path_buf();
    }

    let next_suffix = next_suffixes.entry(output.to_path_buf()).or_insert(2);
    loop {
        let index = *next_suffix;
        *next_suffix += 1;
        let candidate = numbered_output_path(output, index);
        if !reserved.contains(&candidate) && !candidate.exists() {
            return candidate;
        }
    }
}

fn numbered_output_path(path: &Path, index: u64) -> PathBuf {
    let mut name = path.file_stem().unwrap_or_default().to_os_string();
    name.push(format!("_{index}"));
    if let Some(extension) = path.extension() {
        name.push(".");
        name.push(extension);
    }
    path.with_file_name(name)
}

/// Persist a batch output without replacing an existing filesystem entry.
///
/// The filesystem is the final authority on whether two names collide: this
/// also covers case-insensitive aliases and files created after planning.
fn write_unique_file(path: &Path, data: &[u8]) -> io::Result<PathBuf> {
    let mut candidate = path.to_path_buf();
    for index in 2_u64.. {
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(mut file) => {
                file.write_all(data)?;
                return Ok(candidate);
            }
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
                candidate = numbered_output_path(path, index);
            }
            Err(err) => return Err(err),
        }
    }
    unreachable!("an unused numeric output suffix must exist")
}

/// Whether an error should abort the whole batch rather than just fail one file.
fn is_fatal_batch_error(err: &RevenantError) -> bool {
    matches!(err, RevenantError::Auth(_) | RevenantError::Tls { .. })
}

/// Verify `pdf_path` offline (per signature) and, when `server` is set, against
/// the appliance.
pub(crate) fn verify(
    transport: &Transport,
    pdf_path: &Path,
    trust: &TrustAnchors,
    server: Option<&ResolvedServerConfig>,
) -> VerifyOutcome {
    let pdf = match std::fs::read(pdf_path) {
        Ok(bytes) => bytes,
        Err(err) => return VerifyOutcome::ReadError(err.to_string()),
    };
    let cache = TrustStoreCache::new();
    let local = api::verify_pdf_all(transport, &cache, &pdf, trust).map_err(|err| err.to_string());
    let server =
        server.map(|cfg| verify_pdf_server(transport, &cfg.url, &pdf, cfg.timeout_duration()));
    VerifyOutcome::Done { local, server }
}

/// Classify a discovery error so the UI thread can pick the localized message.
pub(crate) fn categorize_identity_error(err: &RevenantError) -> IdentityOutcome {
    let detail = err.to_string();
    match err {
        RevenantError::Auth(_) => IdentityOutcome::AuthFailed(detail),
        RevenantError::Tls { .. } => IdentityOutcome::ServerError(detail),
        _ => IdentityOutcome::OtherError(detail),
    }
}

/// Adapt a discovered certificate into the config store's signer record. Both
/// carry the same fields; the store owns the persisted view.
pub(crate) fn signer_info_from_cert(info: &CertInfo) -> SignerInfo {
    SignerInfo {
        name: info.name.clone(),
        email: info.email.clone(),
        organization: info.organization.clone(),
        dn: info.dn.clone(),
        not_before: info.not_before.clone(),
        not_after: info.not_after.clone(),
    }
}

/// The inverse of [`signer_info_from_cert`]: view the saved signer record as a
/// [`CertInfo`] so the appearance field extractor can read from it. The core's
/// own converter is private to its signing path, so the GUI keeps both
/// directions of this identical-shape mapping here.
pub(crate) fn cert_info_from_signer(info: &SignerInfo) -> CertInfo {
    CertInfo {
        name: info.name.clone(),
        email: info.email.clone(),
        organization: info.organization.clone(),
        dn: info.dn.clone(),
        not_before: info.not_before.clone(),
        not_after: info.not_after.clone(),
    }
}

/// Human-readable byte size (integer math to avoid lossy float casts).
pub(crate) fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    if bytes >= MB {
        format!("{}.{} MB", bytes / MB, (bytes % MB) * 10 / MB)
    } else if bytes >= KB {
        format!("{}.{} KB", bytes / KB, (bytes % KB) * 10 / KB)
    } else {
        format!("{bytes} B")
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{batch_output_paths, format_bytes, write_unique_file};

    #[test]
    fn format_bytes_scales_units() {
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1024), "1.0 KB");
        assert_eq!(format_bytes(1536), "1.5 KB");
        assert_eq!(format_bytes(1024 * 1024), "1.0 MB");
    }

    #[test]
    fn batch_outputs_disambiguate_same_named_inputs() {
        let dir = tempfile::tempdir().unwrap();
        let files = vec![
            PathBuf::from("first").join("contract.pdf"),
            PathBuf::from("second").join("contract.pdf"),
            PathBuf::from("third").join("contract.pdf"),
        ];

        assert_eq!(
            batch_output_paths(&files, dir.path(), false),
            vec![
                Some(dir.path().join("contract_signed.pdf")),
                Some(dir.path().join("contract_signed_2.pdf")),
                Some(dir.path().join("contract_signed_3.pdf")),
            ]
        );
    }

    #[test]
    fn batch_outputs_skip_existing_and_reserved_detached_names() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("contract.pdf.p7s"), b"existing").unwrap();
        let files = vec![
            PathBuf::from("first").join("contract.pdf"),
            PathBuf::from("second").join("contract.pdf"),
        ];

        assert_eq!(
            batch_output_paths(&files, dir.path(), true),
            vec![
                Some(dir.path().join("contract.pdf_2.p7s")),
                Some(dir.path().join("contract.pdf_3.p7s")),
            ]
        );
    }

    #[test]
    fn batch_write_uses_a_suffix_instead_of_replacing_an_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("contract_signed.pdf");
        let first = write_unique_file(&output, b"first signature").unwrap();

        let second = write_unique_file(&output, b"second signature").unwrap();

        assert_eq!(first, output);
        assert_eq!(second, dir.path().join("contract_signed_2.pdf"));
        assert_eq!(std::fs::read(first).unwrap(), b"first signature");
        assert_eq!(std::fs::read(second).unwrap(), b"second signature");
    }
}
