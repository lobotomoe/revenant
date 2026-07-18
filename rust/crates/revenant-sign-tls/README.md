# revenant-sign-tls

A from-scratch TLS 1.0 client speaking only `TLS_RSA_WITH_RC4_128_MD5` (and its
SHA-1 sibling `TLS_RSA_WITH_RC4_128_SHA`). It implements the minimal
[RFC 2246](https://www.rfc-editor.org/rfc/rfc2246) handshake and record layer
needed to reach legacy [ARX CoSign](https://github.com/lobotomoe/revenant)
signature appliances -- notably EKENG's `ca.gov.am` -- that negotiate nothing
newer than TLS 1.0 with RC4, a cipher suite removed from OpenSSL 3.x and
unsupported by rustls, native-tls, and every other maintained Rust TLS library.
It is the Rust equivalent of what `tlslite-ng` does for the Python client and
`node-forge` for the TypeScript one.

## Security warning

**This is not a general-purpose TLS library and must never be used as one.** It
implements only the RC4 cipher suites, does **not** verify the server
certificate (the target appliances present certs no modern chain would accept
and are reached over a government intranet), and supports only the RSA
key-exchange path. RC4 is cryptographically broken (RFC 7465); this code exists
solely for backward compatibility with legacy appliances that offer nothing
else.

## Usage

```rust
use std::time::Duration;
use revenant_sign_tls::{request, Method};

let resp = request(
    Method::Post,
    "https://ca.gov.am:8080/SAPIWS/DSS.asmx",
    Some(b"<soap:Envelope>...</soap:Envelope>"),
    &[("Content-Type", "text/xml; charset=utf-8")],
    Duration::from_secs(120),
)?;
assert_eq!(resp.status, 200);
# Ok::<(), revenant_sign_tls::TlsError>(())
```

Licensed under [Apache-2.0](LICENSE).
