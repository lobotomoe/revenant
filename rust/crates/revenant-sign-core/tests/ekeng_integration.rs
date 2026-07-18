// SPDX-License-Identifier: Apache-2.0
//! Live integration tests against the real EKENG CoSign appliance.
//!
//! These are `#[ignore]` by default: they require network access to the EKENG
//! government endpoint and real credentials. Credentials are read from the
//! `REVENANT_USER` and `REVENANT_PASS` environment variables and are never
//! hard-coded here. Run with:
//!
//! ```sh
//! REVENANT_USER=... REVENANT_PASS=... \
//!     cargo test -p revenant-sign-core --test ekeng_integration -- --ignored --nocapture
//! ```
//!
//! Each test soft-skips (prints a note and passes) when the credentials are
//! absent, so an unconfigured `--ignored` run does not fail spuriously.

use std::sync::Arc;
use std::time::Duration;

use revenant_sign_core::api::{self, ServerChoice};
use revenant_sign_core::config::{register_profile_tls_mode, ConfigStore, ServerProfile, EKENG};
use revenant_sign_core::net::{SoapSigningTransport, Transport};
use revenant_sign_core::pdf::{verify_detached_signature, verify_embedded_signature};
use revenant_sign_core::pki::discover_identity_from_server;
use revenant_sign_core::signing::{sign_pdf_detached, sign_pdf_embedded, EmbeddedSignatureOptions};

/// A minimal single-page PDF (the committed unit-test fixture).
const BLANK_PDF: &[u8] = include_bytes!("../src/pdf/testdata/blank_letter.pdf");

/// Read live credentials from the environment, or `None` to soft-skip.
fn credentials() -> Option<(String, String)> {
    let user = std::env::var("REVENANT_USER").ok()?;
    let pass = std::env::var("REVENANT_PASS").ok()?;
    if user.trim().is_empty() || pass.is_empty() {
        return None;
    }
    Some((user, pass))
}

fn timeout() -> Duration {
    Duration::from_secs(120)
}

/// Build a SOAP signing transport for the EKENG appliance with legacy TLS
/// registered (the appliance only speaks TLS 1.0 + RC4).
fn ekeng_transport() -> (Arc<Transport>, SoapSigningTransport) {
    let transport = Arc::new(Transport::new());
    let ekeng = ServerProfile::builtin(EKENG).expect("ekeng profile is built in");
    register_profile_tls_mode(&transport, &ekeng);
    let soap = SoapSigningTransport::new(Arc::clone(&transport), &ekeng.url);
    (transport, soap)
}

#[test]
#[ignore = "requires network access to EKENG + REVENANT_USER/REVENANT_PASS"]
fn discover_identity_against_ekeng() {
    let Some((user, pass)) = credentials() else {
        eprintln!("skipping: REVENANT_USER/REVENANT_PASS not set");
        return;
    };
    let (_transport, soap) = ekeng_transport();

    let info = discover_identity_from_server(&soap, &user, &pass, timeout())
        .expect("identity discovery against EKENG should succeed");

    eprintln!(
        "Discovered identity: name={:?} org={:?} dn={:?}",
        info.name, info.organization, info.dn
    );
    assert!(info.name.is_some(), "expected a signer common name");
    assert!(info.dn.is_some(), "expected a subject DN");
}

#[test]
#[ignore = "requires network access to EKENG + REVENANT_USER/REVENANT_PASS"]
fn sign_pdf_embedded_against_ekeng() {
    let Some((user, pass)) = credentials() else {
        eprintln!("skipping: REVENANT_USER/REVENANT_PASS not set");
        return;
    };
    let (_transport, soap) = ekeng_transport();

    let opts = EmbeddedSignatureOptions {
        name: Some("Revenant Rust Integration".to_owned()),
        reason: "Phase 7 integration test".to_owned(),
        ..Default::default()
    };
    let signed = sign_pdf_embedded(BLANK_PDF, &soap, &user, &pass, timeout(), &opts)
        .expect("embedded signing against EKENG should succeed");

    // Independently re-verify the returned PDF offline against the CMS-declared
    // digest (the signing call already verified against the exact hash).
    let result = verify_embedded_signature(&signed, None, None);
    eprintln!(
        "Signed PDF: {} bytes, structure_ok={} hash_ok={} signer={:?}",
        signed.len(),
        result.structure_ok,
        result.hash_ok,
        result.signer.as_ref().and_then(|s| s.name.as_ref())
    );
    assert!(result.structure_ok, "{:?}", result.details);
    assert!(result.hash_ok, "{:?}", result.details);
    assert!(
        signed.len() > BLANK_PDF.len(),
        "signed PDF should be larger"
    );
}

#[test]
#[ignore = "requires network access to EKENG + REVENANT_USER/REVENANT_PASS"]
fn sign_pdf_detached_against_ekeng() {
    let Some((user, pass)) = credentials() else {
        eprintln!("skipping: REVENANT_USER/REVENANT_PASS not set");
        return;
    };
    let (_transport, soap) = ekeng_transport();

    let cms = sign_pdf_detached(BLANK_PDF, &soap, &user, &pass, timeout())
        .expect("detached signing against EKENG should succeed");
    eprintln!("Detached CMS: {} bytes", cms.len());
    assert!(!cms.is_empty(), "expected a non-empty CMS");
    assert_eq!(cms.first(), Some(&0x30), "CMS should be a DER SEQUENCE");

    // The detached signature covers the whole PDF; verify against the source.
    let result = verify_detached_signature(BLANK_PDF, &cms, None);
    assert!(result.structure_ok, "{:?}", result.details);
    assert!(result.hash_ok, "{:?}", result.details);
}

#[test]
#[ignore = "requires network access to EKENG + REVENANT_USER/REVENANT_PASS"]
fn high_level_api_sign_against_ekeng() {
    let Some((user, pass)) = credentials() else {
        eprintln!("skipping: REVENANT_USER/REVENANT_PASS not set");
        return;
    };
    let store = ConfigStore::new();
    let transport = Arc::new(Transport::new());
    let server = ServerChoice {
        profile: Some(EKENG),
        ..Default::default()
    };
    // Explicit name + fields keep the flow independent of any saved config,
    // so this exercises only the api layer's server/TLS wiring.
    let options = EmbeddedSignatureOptions {
        name: Some("Revenant API Integration".to_owned()),
        fields: Some(vec!["Revenant API Integration".to_owned()]),
        ..Default::default()
    };
    let signed = api::sign(
        &store, &transport, BLANK_PDF, &user, &pass, &server, options,
    )
    .expect("high-level api::sign against EKENG should succeed");

    let result = verify_embedded_signature(&signed, None, None);
    assert!(result.valid(), "{:?}", result.details);
    eprintln!("api::sign produced {} bytes", signed.len());
}
