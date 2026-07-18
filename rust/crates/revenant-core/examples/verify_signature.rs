// SPDX-License-Identifier: Apache-2.0
//! Verify the embedded signature(s) in a PDF and print the outcome.
//!
//! Usage:
//!     cargo run -p revenant-core --example verify_signature -- SIGNED.pdf [HEX_SHA1]
//!
//! When the optional SHA-1 (hex) sent to the appliance is given, the ByteRange
//! is checked against it; otherwise the CMS-declared digest is used. Exits 0 iff
//! the last signature is valid.

use std::process::ExitCode;

use revenant_core::pdf::verify_embedded_signature;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let Some(path) = args.get(1) else {
        eprintln!("usage: verify_signature <signed.pdf> [hex_sha1]");
        return ExitCode::FAILURE;
    };

    let pdf = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("cannot read {path}: {e}");
            return ExitCode::FAILURE;
        }
    };

    let expected = match args.get(2) {
        Some(hex_str) => match hex::decode(hex_str) {
            Ok(bytes) => Some(bytes),
            Err(e) => {
                eprintln!("invalid hex hash: {e}");
                return ExitCode::FAILURE;
            }
        },
        None => None,
    };

    let result = verify_embedded_signature(&pdf, expected.as_deref(), None);
    for line in &result.details {
        println!("{line}");
    }
    println!(
        "valid={} structure_ok={} hash_ok={}",
        result.valid(),
        result.structure_ok,
        result.hash_ok
    );

    if result.valid() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
