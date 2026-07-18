//! Revenant: a cross-platform client for ARX CoSign / DocuSign Signature
//! Appliance electronic signatures over the OASIS DSS SOAP API.
//!
//! The library surface -- prepare and embed PDF signatures, produce detached
//! CMS/PKCS#7 signatures, verify signed documents, and validate certificate
//! chains against ETSI Trust Service Lists -- matches the sibling `revenant`
//! (Python) and `revenant-sign` (npm) packages.

#![forbid(unsafe_code)]

pub mod api;
pub mod appearance;
pub mod cms;
pub mod config;
pub mod constants;
pub mod error;
pub mod net;
pub mod pdf;
pub mod pki;
pub mod signing;

mod xml;

pub use error::{Result, RevenantError};
