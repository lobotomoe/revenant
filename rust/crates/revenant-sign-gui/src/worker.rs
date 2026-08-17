//! Background job runner.
//!
//! egui renders on a single thread, so any blocking work (network pings,
//! signing, verification) runs on a spawned thread and returns its result
//! through a channel the UI polls each frame. Finishing a job requests a
//! repaint so the result is shown promptly rather than on the next input event.

use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;

use eframe::egui;
use revenant_sign_core::net::ServerVerifyResult;
use revenant_sign_core::pdf::VerificationResult;
use revenant_sign_core::pki::CertInfo;

/// Identifies one background request so its result can be matched back to the
/// state that asked for it.
///
/// The UI polls the worker channel each frame, so a result can arrive long after
/// whoever asked for it was cancelled or replaced. Untagged, a handler cannot
/// tell "this is my answer" from "this is someone else's answer" and applies it
/// to whatever state happens to be live -- which is how a cancelled server got
/// persisted (GHSA-285g) and one account's saved password reached another's
/// login (GHSA-53v5).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct RequestId(u64);

/// Issues [`RequestId`]s. One per app; ids are never reused within a run, so a
/// stale result can never collide with a later request.
#[derive(Default)]
pub(crate) struct RequestIds {
    issued: u64,
}

impl RequestIds {
    /// Issue the next id.
    pub(crate) fn issue(&mut self) -> RequestId {
        self.issued += 1;
        RequestId(self.issued)
    }
}

/// Outcome of a background signer-identity discovery. Errors are pre-classified
/// on the worker thread so the UI thread only has to pick the localized message;
/// the detail string is the raw error text to interpolate.
pub(crate) enum IdentityOutcome {
    /// A certificate was retrieved. Boxed because [`CertInfo`] dwarfs the other
    /// variants.
    Ok(Box<CertInfo>),
    /// Wrong username or password.
    AuthFailed(String),
    /// A transport/TLS-level failure talking to the server.
    ServerError(String),
    /// Any other failure (bad certificate, malformed response, ...).
    OtherError(String),
}

/// Outcome of a background signing job.
pub(crate) enum SignedOutcome {
    /// The signed document was written; `size` is the output size in bytes.
    Ok { path: PathBuf, size: u64 },
    /// Signing failed; the string is the raw (not yet localized) error text.
    Failed(String),
}

/// Outcome of a background verification job.
pub(crate) enum VerifyOutcome {
    /// The input file could not be read.
    ReadError(String),
    /// Verification ran. `local` holds the offline per-signature results (or an
    /// error such as "no embedded signatures"); `server` holds the server-side
    /// verdict when a server is configured.
    Done {
        local: Result<Vec<VerificationResult>, String>,
        server: Option<ServerVerifyResult>,
    },
}

/// Result of a completed background job, tagged so the UI thread can route it.
pub(crate) enum WorkerMsg {
    /// A server ping finished: whether it succeeded and a human-readable detail.
    Ping {
        request: RequestId,
        ok: bool,
        detail: String,
    },
    /// A signer-identity discovery finished.
    Identity {
        request: RequestId,
        outcome: IdentityOutcome,
    },
    /// A background read of the saved password finished, for login pre-fill.
    /// `None` when nothing is stored. The password is never logged.
    SavedPassword {
        request: RequestId,
        /// The username the read was issued for. Carried so the result cannot be
        /// applied to a login that has since switched accounts -- the request id
        /// alone would not catch a username edited within the same wizard.
        username: String,
        password: Option<String>,
    },
    /// A signing job finished.
    Signed(SignedOutcome),
    /// A verification job finished.
    Verified(VerifyOutcome),
    /// A batch job is about to sign file `current` of `total`.
    BatchProgress {
        current: usize,
        total: usize,
        filename: String,
    },
    /// A batch job finished. `aborted` carries the reason when a fatal error
    /// (bad credentials, TLS failure) stopped the whole batch early.
    ///
    /// `renamed` lists the inputs whose result could not take its derived name
    /// because something already held it, as `(input, written)` file names. The
    /// batch never overwrites, so without this the user is left guessing which
    /// `_2` belongs to which document.
    BatchDone {
        succeeded: usize,
        failed: usize,
        aborted: Option<String>,
        renamed: Vec<(String, String)>,
    },
}

/// A sink a streaming (batch) job uses to push progress messages to the UI
/// thread, waking it with a repaint after each one.
pub(crate) type Emit<'a> = dyn Fn(WorkerMsg) + 'a;

/// Owns the channel between background jobs and the UI thread.
pub(crate) struct Worker {
    ctx: egui::Context,
    tx: Sender<WorkerMsg>,
    rx: Receiver<WorkerMsg>,
}

impl Worker {
    pub(crate) fn new(ctx: egui::Context) -> Self {
        let (tx, rx) = mpsc::channel();
        Self { ctx, tx, rx }
    }

    /// Run `job` on a background thread, delivering its result to the UI thread
    /// and waking it with a repaint request.
    pub(crate) fn spawn<F>(&self, job: F)
    where
        F: FnOnce() -> WorkerMsg + Send + 'static,
    {
        let tx = self.tx.clone();
        let ctx = self.ctx.clone();
        thread::spawn(move || {
            let msg = job();
            // A send error only means the app is shutting down (receiver gone),
            // so there is nothing to recover.
            let _ = tx.send(msg);
            ctx.request_repaint();
        });
    }

    /// Run a streaming `job` on a background thread. The job is handed an
    /// [`Emit`] sink to push progress messages; each send wakes the UI thread.
    pub(crate) fn spawn_batch<F>(&self, job: F)
    where
        F: FnOnce(&Emit<'_>) + Send + 'static,
    {
        let tx = self.tx.clone();
        let ctx = self.ctx.clone();
        thread::spawn(move || {
            let emit = |msg: WorkerMsg| {
                let _ = tx.send(msg);
                ctx.request_repaint();
            };
            job(&emit);
        });
    }

    /// Drain all finished jobs without blocking.
    pub(crate) fn drain(&self) -> Vec<WorkerMsg> {
        self.rx.try_iter().collect()
    }
}
