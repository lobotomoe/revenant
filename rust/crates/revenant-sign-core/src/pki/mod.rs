//! Public-key infrastructure: certificate parsing, signer-identity extraction,
//! expiry math, ETSI Trust Service List handling, and chain validation.
//!
//! Certificate and CMS parsing use the RustCrypto `x509-cert` / `cms` crates;
//! per-link chain signatures are checked with `x509-verify`. The submodules are
//! private; the curated public surface is re-exported here.

mod cert;
mod cert_info;
mod chain;
mod expiry;
mod tsl;

pub use cert_info::{
    discover_identity_from_server, summarize_cms_certificates, CertInfo, CmsCertSummary,
};
pub use chain::{validate_chain, validate_chain_for_profile, ChainResult, TrustStatus};
pub use expiry::{
    days_remaining, expiry_status, format_expiry_summary, format_validity_period, not_yet_valid,
    ExpiryStatus, EXPIRY_WARNING_DAYS,
};
pub use tsl::{fetch_trust_store, parse_tsl, TrustAnchor, TrustStore, TrustStoreCache};
