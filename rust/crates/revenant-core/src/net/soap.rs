//! `send_soap`: POST a SOAP envelope to a CoSign endpoint and return the
//! response body as text. TLS mode (standard or legacy) is chosen by the
//! [`Transport`] based on the target host.

use std::time::Duration;

use crate::net::transport::Transport;
use crate::Result;

/// Base of the `SOAPAction` header; the operation name is appended.
const SOAP_ACTION_BASE: &str = "http://arx.com/SAPIWS/DSS/1.0/";

/// Send a SOAP request and return the response body decoded as UTF-8.
///
/// `action` is the DSS operation (`"DssSign"`, `"DssVerify"`) used for the
/// `SOAPAction` header. `max_retries` bounds transport-level retries and MUST be
/// `0` for the non-idempotent `DssSign`: retrying a request whose response was
/// lost after the appliance already signed would produce a second, duplicate
/// signature (extra audit entries, quota). Idempotent operations (verify, cert
/// enumeration) may retry safely.
///
/// # Errors
///
/// Returns a [`RevenantError`](crate::RevenantError) on transport or HTTP
/// failure.
pub fn send_soap(
    transport: &Transport,
    url: &str,
    envelope: &str,
    action: &str,
    timeout: Duration,
    max_retries: u32,
) -> Result<String> {
    let soap_action = format!("{SOAP_ACTION_BASE}{action}");
    let headers = [
        ("Content-Type", "text/xml; charset=utf-8"),
        ("SOAPAction", soap_action.as_str()),
    ];
    let response = transport.post(url, envelope.as_bytes(), &headers, timeout, max_retries)?;
    Ok(String::from_utf8_lossy(&response).into_owned())
}
