// SPDX-License-Identifier: Apache-2.0
//! Prepare a PDF signature field and demonstrate the hash-then-sign cycle.
//!
//! This mirrors what the signing flow does around the appliance call: prepare an
//! empty signature field, hash the ByteRange (the value sent to the appliance),
//! and splice a CMS into the reserved `/Contents`. Here the CMS is a synthetic
//! placeholder so the output can be validated by an external PDF parser.
//!
//! Usage:
//!     cargo run -p revenant-core --example prepare_signature -- IN.pdf OUT.pdf
//!
//! It prints the ByteRange SHA-1 (hex) on stdout, then cross-checks against a
//! mature parser, e.g.:
//!     python -c "import pikepdf; pikepdf.open('OUT.pdf'); print('pikepdf OK')"

use std::process::ExitCode;

use revenant_core::pdf::{
    compute_byterange_hash, insert_cms, prepare_pdf_with_sig_field, PrepareOptions, PreparedPdf,
};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let (Some(input), Some(output)) = (args.get(1), args.get(2)) else {
        eprintln!("usage: prepare_signature <input.pdf> <output.pdf>");
        return ExitCode::FAILURE;
    };

    let pdf = match std::fs::read(input) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("cannot read {input}: {e}");
            return ExitCode::FAILURE;
        }
    };

    let opts = PrepareOptions {
        name: Some("Test Signer"),
        reason: "Cross-check",
        ..Default::default()
    };

    let PreparedPdf {
        bytes: prepared,
        contents_hex_offset: hex_start,
        contents_hex_len: hex_len,
    } = match prepare_pdf_with_sig_field(&pdf, &opts) {
        Ok(prepared) => prepared,
        Err(e) => {
            eprintln!("prepare failed: {e}");
            return ExitCode::FAILURE;
        }
    };

    let hash = compute_byterange_hash(&prepared, hex_start, hex_len).expect("byterange hash");

    // A synthetic CMS (well-formed DER SEQUENCE) standing in for the appliance's
    // response, so the output is a structurally complete signed PDF.
    let mut cms = vec![0x30, 0x81, 0xC8];
    cms.extend(std::iter::repeat_n(0xAB, 200));
    let signed = insert_cms(&prepared, hex_start, hex_len, &cms).expect("insert cms");

    if let Err(e) = std::fs::write(output, &signed) {
        eprintln!("cannot write {output}: {e}");
        return ExitCode::FAILURE;
    }

    println!("{}", hex::encode(hash));
    ExitCode::SUCCESS
}
