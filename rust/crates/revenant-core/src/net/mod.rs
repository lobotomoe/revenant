//! Networking: HTTP transport, SOAP envelope construction and parsing, the
//! signing-transport implementation, and server discovery.
//!
//! Submodules are private; the curated public surface is re-exported here so
//! consumers depend on `revenant_core::net::*`, not on the internal file layout.

mod discovery;
mod protocol;
mod soap;
mod soap_envelope;
mod soap_parsers;
mod soap_transport;
mod transport;

pub use discovery::{ping_server, PingOutcome};
pub use protocol::SigningTransport;
pub use soap::send_soap;
pub use soap_envelope::{
    build_enum_certificates_envelope, build_sign_envelope, build_sign_hash_envelope,
    build_verify_envelope, xml_escape, SIGNATURE_TYPE_CMS, SIGNATURE_TYPE_ENUM_CERTS,
    SIGNATURE_TYPE_FIELD_VERIFY, SIGNATURE_TYPE_XMLDSIG,
};
pub use soap_parsers::{
    parse_enum_certificates_response, parse_sign_response, parse_verify_response,
    ServerVerifyResult,
};
pub use soap_transport::{enum_certificates, verify_pdf_server, SoapSigningTransport};
pub use transport::{TlsMode, Transport};
