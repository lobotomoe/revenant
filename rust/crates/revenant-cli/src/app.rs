// SPDX-License-Identifier: Apache-2.0
//! The shared application context.
//!
//! A single [`App`] is threaded through every command: one [`ConfigStore`] and
//! one shared [`Transport`], whose per-host TLS cache is reused across requests
//! within a run.

use std::sync::Arc;

use revenant_core::config::ConfigStore;
use revenant_core::net::Transport;

/// Configuration store and shared transport for a single CLI invocation.
pub(crate) struct App {
    /// Persisted settings, credentials, and the session credential cache.
    pub(crate) store: ConfigStore,
    /// The HTTP/SOAP transport, shared so its TLS-mode cache survives between
    /// requests (e.g. across a batch of files).
    pub(crate) transport: Arc<Transport>,
}

impl App {
    /// Build the production context: the real `~/.revenant` store and a fresh
    /// transport.
    #[must_use]
    pub(crate) fn new() -> Self {
        App {
            store: ConfigStore::new(),
            transport: Arc::new(Transport::new()),
        }
    }
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}
