//! The password-change request and its response.
//!
//! The appliance has no operation of its own for this. It changes the password
//! on a logon whose `ClaimedIdentity` carries `NewLogonPassword` next to
//! `LogonPassword` (`CoSignAuthDataType` in the WSDL), and answers the way it
//! answers that logon. Checked live against the EKENG appliance on 2026-11-16:
//! a success result means the new password is in force and the old one is
//! refused from then on; a new password the appliance will not take comes back
//! as a `ResponderError` reading `Error changing password err 90020150`, with
//! the old password still valid.

use std::time::Duration;

use crate::net::soap::send_soap;
use crate::net::soap_envelope::build_change_password_envelope;
use crate::net::soap_parsers::{failure_message, is_auth_error, parse_dom_or_error};
use crate::net::transport::Transport;
use crate::xml::find_value;
use crate::{Result, RevenantError};

const ACTION_SIGN: &str = "DssSign";

/// A password change is sent once. If the response to a request the appliance
/// already applied were lost, a retry would present the old password, which no
/// longer works: a failed logon counted toward the account lockout.
const CHANGE_PASSWORD_RETRIES: u32 = 0;

/// Ask the server to replace `password` with `new_password`.
///
/// One request, never retried. A transport failure leaves the outcome unknown:
/// the appliance may have applied the change before the connection dropped.
/// [`crate::password::change_password`] settles that case.
///
/// # Errors
///
/// Returns [`RevenantError::Auth`] when the current password is wrong,
/// [`RevenantError::Server`] when the server refuses the new one, or another
/// [`RevenantError`] on transport failure.
pub fn change_password(
    transport: &Transport,
    url: &str,
    username: &str,
    password: &str,
    new_password: &str,
    timeout: Duration,
) -> Result<()> {
    log::info!("Changing password: url={url}");
    let envelope = build_change_password_envelope(username, password, new_password);
    let response = send_soap(
        transport,
        url,
        &envelope,
        ACTION_SIGN,
        timeout,
        CHANGE_PASSWORD_RETRIES,
    )?;
    parse_change_password_response(&response)
}

/// Parse the response to a password-change request.
///
/// # Errors
///
/// Returns [`RevenantError::Auth`] when the current password was refused,
/// [`RevenantError::Server`] on any other rejection, and
/// [`RevenantError::Other`] on malformed XML.
pub fn parse_change_password_response(xml: &str) -> Result<()> {
    let root = parse_dom_or_error(xml)?;
    let result_major = find_value(&root, "ResultMajor");
    if result_major
        .as_deref()
        .is_some_and(|major| major.ends_with(":Success"))
    {
        return Ok(());
    }

    let result_minor = find_value(&root, "ResultMinor");
    let result_message = find_value(&root, "ResultMessage");
    let msg = failure_message(result_message, result_minor.as_deref(), result_major);
    if is_auth_error(result_minor.as_deref(), &msg) {
        return Err(RevenantError::Auth(format!("Authentication failed: {msg}")));
    }
    Err(RevenantError::Server(format!(
        "The server refused the new password: {msg}"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(major: &str, message: Option<&str>) -> String {
        let message = message.map_or_else(String::new, |text| {
            format!("<ResultMessage xml:lang=\"en\">{text}</ResultMessage>")
        });
        format!(
            concat!(
                r#"<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">"#,
                "<soap:Body><DssSignResponse><DssSignResult><Result>",
                "<ResultMajor>urn:oasis:names:tc:dss:1.0:resultmajor:{}</ResultMajor>",
                "<ResultMinor>urn:oasis:names:tc:dss:1.0:resultminor:GeneralError</ResultMinor>",
                "{}</Result></DssSignResult></DssSignResponse></soap:Body></soap:Envelope>"
            ),
            major, message
        )
    }

    #[test]
    fn success_is_ok() {
        parse_change_password_response(&response("Success", None)).unwrap();
    }

    /// The appliance's answer to a wrong current password, as captured live.
    #[test]
    fn wrong_current_password_is_an_auth_error() {
        let xml = response(
            "ResponderError",
            Some("Failed to verify user name and password"),
        );
        let err = parse_change_password_response(&xml).unwrap_err();
        assert!(matches!(err, RevenantError::Auth(_)), "got {err:?}");
    }

    /// The appliance's answer to a one-character new password, as captured live.
    /// It must not read as bad credentials: the logon itself succeeded.
    #[test]
    fn refused_new_password_is_a_server_error() {
        let xml = response(
            "ResponderError",
            Some("Error changing password err 90020150"),
        );
        let err = parse_change_password_response(&xml).unwrap_err();
        assert!(matches!(err, RevenantError::Server(_)), "got {err:?}");
        assert!(err.to_string().contains("90020150"), "got {err}");
    }

    #[test]
    fn malformed_xml_is_reported() {
        let err = parse_change_password_response("<not-closed").unwrap_err();
        assert!(matches!(err, RevenantError::Other(_)), "got {err:?}");
    }
}
