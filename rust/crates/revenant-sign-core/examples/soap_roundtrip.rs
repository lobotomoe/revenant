//! Manual Phase 2 interop check: drive the full SOAP-over-legacy-TLS stack
//! against the tlslite-ng harness (`scratchpad/tlsharness/soap_server.py`),
//! the same TLS 1.0 + RC4 stack the EKENG appliance uses.
//!
//! ```text
//! python/.venv/bin/python scratchpad/tlsharness/soap_server.py 18444 &
//! cargo run -p revenant-sign-core --example soap_roundtrip -- \
//!     https://127.0.0.1:18444/SAPIWS/DSS.asmx
//! ```
//!
//! Exercises `sign_hash`, `sign_data`, and `verify_pdf_server` against one
//! canned DssSign *Success* envelope, asserting the decoded CMS round-trips.

use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use revenant_sign_core::net::{
    verify_pdf_server, ServerVerifyResult, SigningTransport, SoapSigningTransport, TlsMode,
    Transport,
};

/// Must match `CMS_PLAINTEXT` in `soap_server.py`.
const EXPECTED_CMS: &[u8] = b"REVENANT-PHASE2-CMS-END-TO-END-INTEROP-PROOF-0123456789";
const EXPECTED_SIGNER: &str = "Test Signer 12345";
const TIMEOUT: Duration = Duration::from_secs(10);

fn main() -> ExitCode {
    let url = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "https://127.0.0.1:18444/SAPIWS/DSS.asmx".to_owned());
    let host = url::Url::parse(&url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_owned))
        .unwrap_or_else(|| "127.0.0.1".to_owned());

    // Pin the harness host to the legacy (TLS 1.0 + RC4) path.
    let transport = Arc::new(Transport::new());
    transport.register_host_tls(&host, TlsMode::Legacy);
    let signer = SoapSigningTransport::new(Arc::clone(&transport), url.clone());

    let mut failures = 0u32;

    match signer.sign_hash(&[0u8; 20], "user", "pass", TIMEOUT) {
        Ok(cms) if cms.as_slice() == EXPECTED_CMS => {
            println!("PASS sign_hash  -> {} byte CMS decoded", cms.len());
        }
        Ok(cms) => {
            failures += 1;
            println!("FAIL sign_hash  -> unexpected CMS: {cms:?}");
        }
        Err(e) => {
            failures += 1;
            println!("FAIL sign_hash  -> {e}");
        }
    }

    match signer.sign_data(b"hello phase 2", "user", "pass", TIMEOUT) {
        Ok(cms) if cms.as_slice() == EXPECTED_CMS => {
            println!("PASS sign_data  -> {} byte CMS decoded", cms.len());
        }
        Ok(_) => {
            failures += 1;
            println!("FAIL sign_data  -> unexpected CMS");
        }
        Err(e) => {
            failures += 1;
            println!("FAIL sign_data  -> {e}");
        }
    }

    let verdict = verify_pdf_server(transport.as_ref(), &url, b"%PDF-1.4 fake", TIMEOUT);
    match &verdict {
        ServerVerifyResult::Verified {
            signer_name,
            certificate_status,
            ..
        } if signer_name.as_deref() == Some(EXPECTED_SIGNER) => {
            println!(
                "PASS verify     -> valid, signer={signer_name:?} status={certificate_status:?}"
            );
        }
        _ => {
            failures += 1;
            println!("FAIL verify     -> {verdict:?}");
        }
    }

    if failures == 0 {
        println!("ALL PHASE 2 CHECKS PASSED");
        ExitCode::SUCCESS
    } else {
        println!("{failures} check(s) FAILED");
        ExitCode::FAILURE
    }
}
