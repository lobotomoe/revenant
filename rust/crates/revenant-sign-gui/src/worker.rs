//! Background job runner.
//!
//! egui renders on a single thread, so any blocking work (network pings,
//! signing, verification) runs on a spawned thread and returns its result
//! through a channel the UI polls each frame. Finishing a job requests a
//! repaint so the result is shown promptly rather than on the next input event.

use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;

use eframe::egui;

/// Result of a completed background job, tagged so the UI thread can route it.
pub(crate) enum WorkerMsg {
    /// A server ping finished: whether it succeeded and a human-readable detail.
    Ping { ok: bool, detail: String },
}

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

    /// Drain all finished jobs without blocking.
    pub(crate) fn drain(&self) -> Vec<WorkerMsg> {
        self.rx.try_iter().collect()
    }
}
