//! Server discovery: confirm a URL is a CoSign DSS endpoint by fetching its WSDL.
//!
//! TLS mode is auto-detected by the [`Transport`]; no authentication is needed.

use std::time::Duration;

use crate::constants::DEFAULT_MAX_RETRIES;
use crate::net::transport::Transport;

/// Outcome of a [`ping_server`] probe.
#[derive(Debug, Clone)]
pub enum PingOutcome {
    /// The endpoint looks like a usable CoSign/WSDL service; carries a
    /// human-readable status detail.
    Ok(String),
    /// The probe failed; carries a human-readable reason.
    Failed(String),
}

/// Probe `url` for a CoSign DSS endpoint by fetching its WSDL.
///
/// Returns a [`PingOutcome`]; connection failures are reported, not raised.
#[must_use]
pub fn ping_server(transport: &Transport, url: &str, timeout: Duration) -> PingOutcome {
    let mut wsdl_url = url.trim_end_matches('/').to_owned();
    if !wsdl_url.contains('?') {
        wsdl_url.push_str("?WSDL");
    }

    let raw = match transport.get(&wsdl_url, timeout, DEFAULT_MAX_RETRIES) {
        Ok(bytes) => bytes,
        Err(e) if e.is_tls() => return PingOutcome::Failed(e.to_string()),
        Err(e) => return PingOutcome::Failed(format!("Connection failed: {e}")),
    };

    let body = String::from_utf8_lossy(&raw);

    if body.contains("DssSign") && body.contains("SAPIWS") {
        return PingOutcome::Ok("CoSign DSS endpoint confirmed".to_owned());
    }
    if body.contains("<wsdl:") || body.contains("<definitions") {
        return PingOutcome::Ok("WSDL found (may not be CoSign)".to_owned());
    }
    PingOutcome::Failed("Not a recognized CoSign endpoint".to_owned())
}
