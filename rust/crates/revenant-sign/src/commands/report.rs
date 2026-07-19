// SPDX-License-Identifier: Apache-2.0
//! Shared rendering of signature-verification results.
//!
//! Both `check` (embedded signatures) and `verify` (detached `.p7s`) produce a
//! [`VerificationResult`] and must classify and print it identically -- a
//! detached signature and an embedded one earn the same verdict for the same
//! cryptographic facts. Keeping the logic here prevents the two commands from
//! drifting apart.

use revenant_sign_core::cms::SignatureStatus;
use revenant_sign_core::pdf::VerificationResult;
use revenant_sign_core::pki::TrustStatus;

use crate::exit::{CliError, CliResult};

/// Print each signature's diagnostic lines, prefixed and numbered when several.
pub(crate) fn print_signature_details(results: &[VerificationResult]) {
    let total = results.len();
    for (index, result) in results.iter().enumerate() {
        let indent = if total > 1 {
            let signer_name = result
                .signer
                .as_ref()
                .and_then(|s| s.name.as_deref())
                .unwrap_or("Unknown");
            println!("\n  Signature {}/{total} ({signer_name}):", index + 1);
            "    "
        } else {
            "  "
        };
        for detail in &result.details {
            for line in detail.split('\n') {
                println!("{indent}{line}");
            }
        }
    }
}

/// Classify one signature into a display label and whether it counts as a pass.
///
/// The verdict reflects the full cryptographic result, not just structure: a
/// signature that does not verify, cannot be verified, or comes from a signer
/// outside the configured trust list does NOT pass. A genuine signature whose
/// trust was simply not checked (no Trust Service List configured) passes with a
/// note, so verification without a TSL still works.
fn classify(result: &VerificationResult) -> (String, bool) {
    if !result.integrity_ok() {
        return (
            "FAILED -- document structure or hash is broken".to_owned(),
            false,
        );
    }
    match result.signature {
        SignatureStatus::Invalid => {
            return (
                "INVALID -- signature does not verify (document altered)".to_owned(),
                false,
            );
        }
        SignatureStatus::Unverifiable(why) => {
            return (
                format!("UNVERIFIED -- signature could not be checked ({why})"),
                false,
            );
        }
        SignatureStatus::Valid => {}
    }
    match result.trust_status {
        Some(TrustStatus::Untrusted) => (
            "VALID signature, but the signer is NOT in the trusted list".to_owned(),
            false,
        ),
        Some(TrustStatus::Trusted) => ("VALID and trusted".to_owned(), true),
        // Indeterminate / None: the signature is genuine; trust was not established.
        _ => ("VALID (signer trust not checked)".to_owned(), true),
    }
}

/// Print the final RESULT line(s) and return the process outcome.
pub(crate) fn print_result_line(results: &[VerificationResult]) -> CliResult {
    let total = results.len();
    let verdicts: Vec<(String, bool)> = results.iter().map(classify).collect();
    let passed = verdicts.iter().filter(|(_, ok)| *ok).count();

    println!();
    if total == 1 {
        let (label, ok) = &verdicts[0];
        println!("  RESULT: {label}");
        return if *ok { Ok(()) } else { Err(CliError::silent()) };
    }
    for (index, (label, _)) in verdicts.iter().enumerate() {
        println!("  Signature {}/{total}: {label}", index + 1);
    }
    if passed == total {
        println!("  RESULT: all {total} signatures VALID");
        Ok(())
    } else {
        println!(
            "  RESULT: {} of {total} signature(s) did not pass",
            total - passed
        );
        Err(CliError::silent())
    }
}
