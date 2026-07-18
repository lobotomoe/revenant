//! Manual interop check: perform one legacy-TLS request against a server.
//!
//! Run against the tlslite-ng harness (see the workspace test notes):
//!
//! ```text
//! cargo run -p revenant-legacy-tls --example roundtrip -- https://127.0.0.1:18443/
//! ```

use std::time::Duration;

use revenant_legacy_tls::{request, Method};

fn main() {
    let url = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "https://127.0.0.1:18443/".to_string());

    // Optional second arg: body size in bytes, to exercise record fragmentation.
    let body: Vec<u8> = match std::env::args()
        .nth(2)
        .and_then(|s| s.parse::<usize>().ok())
    {
        Some(n) => (0..n).map(|i| b"revenant"[i % 8]).collect(),
        None => b"revenant-legacy-tls interop probe".to_vec(),
    };

    match request(
        Method::Post,
        &url,
        Some(&body),
        &[("Content-Type", "text/plain")],
        Duration::from_secs(10),
    ) {
        Ok(resp) => {
            println!("STATUS {} {}", resp.status, resp.reason);
            for (k, v) in &resp.headers {
                println!("HEADER {k}: {v}");
            }
            println!("BODY {}", String::from_utf8_lossy(&resp.body));
            std::process::exit(i32::from(!resp.is_success()));
        }
        Err(err) => {
            eprintln!("ERROR {err}");
            std::process::exit(2);
        }
    }
}
