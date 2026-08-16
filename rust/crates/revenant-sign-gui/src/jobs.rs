//! Background work executed on the [`crate::worker::Worker`] thread.
//!
//! These functions are the blocking, networked half of each flow: signing,
//! batch signing, and verification. They take only owned/borrowed data (never
//! `&App`), so they are pure with respect to the UI and easy to test. The app
//! collects their results as [`crate::worker::WorkerMsg`]s and folds them back
//! into the UI state on the main thread.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use revenant_sign_core::api::{self, ServerChoice};
use revenant_sign_core::config::{ConfigStore, ResolvedServerConfig, SignerInfo, TrustAnchors};
use revenant_sign_core::net::{verify_pdf_server, Transport};
use revenant_sign_core::pki::{CertInfo, TrustStoreCache};
use revenant_sign_core::signing::EmbeddedSignatureOptions;
use revenant_sign_core::RevenantError;

use crate::worker::{Emit, IdentityOutcome, SignedOutcome, VerifyOutcome, WorkerMsg};

mod output;

use output::{batch_output_paths, write_unique_file};

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

#[cfg(test)]
pub(crate) type BatchSignOverride<'a> = dyn Fn(&[u8]) -> revenant_sign_core::Result<Vec<u8>> + 'a;

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
    #[cfg(test)]
    pub(crate) sign_override: Option<&'a BatchSignOverride<'a>>,
}

impl BatchContext<'_> {
    fn sign_pdf(
        &self,
        pdf: &[u8],
        username: &str,
        password: &str,
        server: &ServerChoice<'_>,
    ) -> revenant_sign_core::Result<Vec<u8>> {
        #[cfg(test)]
        if let Some(sign) = self.sign_override {
            return sign(pdf);
        }

        if self.detached {
            api::sign_detached(self.store, self.transport, pdf, username, password, server)
        } else {
            api::sign(
                self.store,
                self.transport,
                pdf,
                username,
                password,
                server,
                self.options.clone(),
            )
        }
    }
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
            renamed: Vec::new(),
        });
        return;
    };
    let total = files.len();
    let server = ServerChoice::default();
    let outputs = batch_output_paths(files, ctx.output_dir, ctx.detached);
    let mut succeeded = 0;
    let mut failed = 0;
    let mut renamed = Vec::new();
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
        let result = ctx.sign_pdf(&pdf, &username, password.expose(), &server);
        match result {
            Err(err) if is_fatal_batch_error(&err) => {
                emit(WorkerMsg::BatchDone {
                    succeeded,
                    failed,
                    aborted: Some(err.to_string()),
                    renamed,
                });
                return;
            }
            Ok(bytes) => match write_unique_file(&output, &bytes) {
                Ok(written) => {
                    succeeded += 1;
                    // Only a name the user would not have predicted is worth
                    // reporting; the derived one speaks for itself. The input is
                    // named by its full path: a collision usually means two
                    // inputs share a file name, and the directory is the only
                    // thing that tells them apart.
                    if written != output.base {
                        renamed.push((path.display().to_string(), file_name_of(&written)));
                    }
                }
                Err(_) => failed += 1,
            },
            // A non-fatal signing error: count it and continue.
            Err(_) => failed += 1,
        }
    }
    emit(WorkerMsg::BatchDone {
        succeeded,
        failed,
        aborted: None,
        renamed,
    });
}

/// The final component of `path`, or the whole thing when it has none.
fn file_name_of(path: &Path) -> String {
    path.file_name()
        .unwrap_or(path.as_os_str())
        .to_string_lossy()
        .into_owned()
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
    use std::cell::RefCell;
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;

    use revenant_sign_core::config::ConfigStore;
    use revenant_sign_core::net::Transport;
    use revenant_sign_core::signing::EmbeddedSignatureOptions;

    use super::{batch_sign, format_bytes, BatchContext};
    use crate::worker::WorkerMsg;

    #[test]
    fn format_bytes_scales_units() {
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1024), "1.0 KB");
        assert_eq!(format_bytes(1536), "1.5 KB");
        assert_eq!(format_bytes(1024 * 1024), "1.0 MB");
    }

    #[test]
    fn batch_sign_counts_each_distinct_output_as_successful() {
        let inputs = tempfile::tempdir().unwrap();
        let output = tempfile::tempdir().unwrap();
        let first_dir = inputs.path().join("first");
        let second_dir = inputs.path().join("second");
        std::fs::create_dir_all(&first_dir).unwrap();
        std::fs::create_dir_all(&second_dir).unwrap();
        let first = first_dir.join("contract.pdf");
        let second = second_dir.join("contract.pdf");
        std::fs::write(&first, b"first pdf").unwrap();
        std::fs::write(&second, b"second pdf").unwrap();

        let store = ConfigStore::new();
        store.set_session_credentials("test-user", "test-password");
        let transport = Arc::new(Transport::new());
        let options = EmbeddedSignatureOptions::default();
        let sign = |pdf: &[u8]| {
            let mut signed = b"signed:".to_vec();
            signed.extend_from_slice(pdf);
            Ok(signed)
        };
        let ctx = BatchContext {
            store: &store,
            transport: &transport,
            detached: false,
            options: &options,
            output_dir: output.path(),
            no_credentials_message: "missing credentials",
            sign_override: Some(&sign),
        };
        let messages = RefCell::new(Vec::new());

        batch_sign(
            &|message| messages.borrow_mut().push(message),
            &ctx,
            &[first, second],
            &AtomicBool::new(false),
        );

        let messages = messages.into_inner();
        let Some(WorkerMsg::BatchDone {
            succeeded,
            failed,
            aborted,
            renamed,
        }) = messages.last()
        else {
            panic!("batch must emit a final tally");
        };
        assert_eq!((*succeeded, *failed), (2, 0));
        assert!(aborted.is_none());
        // The second input's derived name was taken by the first, so its result
        // is reported under the name it actually got. Both inputs are called
        // contract.pdf, which is exactly why the full path has to be the label.
        assert_eq!(
            renamed.as_slice(),
            [(
                second_dir.join("contract.pdf").display().to_string(),
                "contract_signed_2.pdf".to_owned()
            )]
        );
        assert_eq!(
            std::fs::read(output.path().join("contract_signed.pdf")).unwrap(),
            b"signed:first pdf"
        );
        assert_eq!(
            std::fs::read(output.path().join("contract_signed_2.pdf")).unwrap(),
            b"signed:second pdf"
        );
        assert_eq!(std::fs::read_dir(output.path()).unwrap().count(), 2);
    }

    #[test]
    fn an_earlier_output_never_consumes_a_later_queued_input() {
        // The reported case, end to end: the queue holds contract.pdf followed by
        // contract_signed.pdf and the user picks their own directory as the
        // output, so the first file's derived name is the second file's input.
        // Signing the first must not replace the second, and the second must be
        // signed as itself rather than as the first one's result.
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("contract.pdf");
        let second = dir.path().join("contract_signed.pdf");
        std::fs::write(&first, b"first pdf").unwrap();
        std::fs::write(&second, b"second pdf").unwrap();

        let store = ConfigStore::new();
        store.set_session_credentials("test-user", "test-password");
        let transport = Arc::new(Transport::new());
        let options = EmbeddedSignatureOptions::default();
        let sign = |pdf: &[u8]| {
            let mut signed = b"signed:".to_vec();
            signed.extend_from_slice(pdf);
            Ok(signed)
        };
        let ctx = BatchContext {
            store: &store,
            transport: &transport,
            detached: false,
            options: &options,
            output_dir: dir.path(),
            no_credentials_message: "missing credentials",
            sign_override: Some(&sign),
        };
        let messages = RefCell::new(Vec::new());

        batch_sign(
            &|message| messages.borrow_mut().push(message),
            &ctx,
            &[first, second.clone()],
            &AtomicBool::new(false),
        );

        assert_eq!(
            std::fs::read(&second).unwrap(),
            b"second pdf",
            "an earlier output overwrote a later queued input"
        );
        assert_eq!(
            std::fs::read(dir.path().join("contract_signed_2.pdf")).unwrap(),
            b"signed:first pdf"
        );
        assert_eq!(
            std::fs::read(dir.path().join("contract_signed_signed.pdf")).unwrap(),
            b"signed:second pdf"
        );
    }
}
