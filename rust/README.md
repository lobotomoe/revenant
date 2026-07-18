# Revenant (Rust)

A Rust port of the [Revenant](../README.md) client for ARX CoSign / DocuSign
Signature Appliance electronic signatures over the OASIS DSS SOAP API. Targets
the same surface as the [TypeScript port](../typescript): a library plus a
`revenant` CLI (no GUI).

## Workspace layout

```
rust/
├── Cargo.toml                    # workspace: shared dep catalog + strict lints
└── crates/
    ├── revenant-sign-tls/      # from-scratch TLS 1.0 + RC4-MD5 client
    ├── revenant-sign-core/            # library: config, PKI, CMS, PDF, SOAP, signing
    └── revenant-sign/             # `revenant` binary (clap)
```

### `revenant-sign-tls`

Some CoSign appliances -- notably EKENG's `ca.gov.am` -- only accept TLS 1.0
with RC4, a cipher suite removed from OpenSSL 3.x and unsupported by rustls,
native-tls, and every other maintained Rust TLS library. This crate implements
the minimal [RFC 2246](https://www.rfc-editor.org/rfc/rfc2246) handshake and
record layer needed to talk to them, mirroring what `tlslite-ng` does for the
Python client and `node-forge` for the TypeScript one.

It is deliberately self-contained (zero Revenant knowledge), implements only the
RC4 cipher suites and RSA key exchange, and does not verify the server
certificate -- the appliances present certs no modern chain would accept and are
reached over a government intranet. RC4 is broken (RFC 7465); this exists solely
for backward compatibility.

## Development

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
```

Or via the repo `Makefile`: `make rs-lint rs-test rs-build`.

### Legacy-TLS interop check

The unit tests cover the crypto primitives (RC4 against RFC 6229, HMAC against
RFC 2202, the TLS 1.0 PRF). A full handshake is verified end-to-end against
`tlslite-ng` -- the same stack the Python client uses -- restricted to TLS 1.0 +
RC4:

```bash
cargo run -p revenant-sign-tls --example roundtrip -- https://127.0.0.1:18443/
```

against a `tlslite-ng` server configured with `cipherNames=["rc4"]`,
`minVersion=maxVersion=(3,1)`. Both `TLS_RSA_WITH_RC4_128_MD5` (EKENG's cipher)
and `TLS_RSA_WITH_RC4_128_SHA` are exercised.

### SOAP-over-legacy-TLS interop check

`revenant-sign-core` layers the CoSign DSS SOAP client (envelope builders, XML
parsers, the auto-detecting HTTP transport, and `SoapSigningTransport`) on top
of the legacy-TLS crate. The full stack -- envelope -> transport -> TLS 1.0 +
RC4 -> HTTP -> XML parse -- is verified against a SOAP variant of the same
harness, which answers with a canned `DssSign` *Success* envelope:

```bash
python/.venv/bin/python scratchpad/tlsharness/soap_server.py 18444 &
cargo run -p revenant-sign-core --example soap_roundtrip -- \
    https://127.0.0.1:18444/SAPIWS/DSS.asmx
```

The example drives `sign_hash`, `sign_data`, and `verify_pdf_server` and asserts
the decoded CMS round-trips. Unit tests cover the envelope byte-layout, the
response parsers (success / auth error / server error / verify / redaction), the
retry and error-classification logic, and the HTTPS-only guard.

## Configuration, credentials, and profiles

`revenant-sign-core::config` persists signer identity, the active server profile, and
preferences under `~/.revenant/config.json` (written atomically, `0600`). It is a
port of the Python `revenant.config` package: the same two-tier config model
(unknown keys preserved on rewrite, known keys validated on read), the same
`ekeng` built-in profile and https-only custom-profile validation, the same
env > config > profile resolution precedence, and the same credential handling.

Where the Python client uses process-global state, the Rust port centralizes it
in an injectable `ConfigStore`, so the whole layer is unit-tested against a temp
directory and an in-memory secret backend -- the real OS keychain is never
touched by the normal test run.

Passwords go to the OS keychain via the [`keyring`](https://crates.io/crates/keyring)
crate (macOS Keychain, Windows Credential Manager, Linux Secret Service), with a
plaintext-in-config fallback and one-time migration when the keychain is
unavailable, matching the Python client and the TS port's `keytar`. In-memory
secrets are wrapped so they never appear in logs or `Debug` output. That the
configured backend is a real keychain (not the crate's no-features in-memory
mock) is proven by an ignored end-to-end test:

```bash
cargo test -p revenant-sign-core --lib keyring_store_roundtrips -- --ignored
```

## CMS signatures: extraction and inspection

`revenant-sign-core::cms` is the read side of signing -- the ASN.1/CMS layer the
Python client keeps in its `asn1`, `cms_extraction`, `cms_info`, and `ltv`
modules. Given a signed PDF (or a bare `.p7s`) it finds the signature, extracts
the exact CMS DER, and reports the digest algorithm, signer identity, and LTV
status. It is entirely read-only and best-effort: inspection helpers return
`None`/all-false rather than aborting.

- **Exact-length extraction from a padded placeholder.** A signed PDF reserves
  the signature as a fixed-size zero-padded hex `/Contents`. `cms::asn1` walks
  the ASN.1 TLV header to find where the real blob ends -- handling both DER
  (definite length) and the BER indefinite encoding (`30 80 ... 00 00`) the
  original EKENG tool emits -- instead of a fragile trailing-zero strip.
- **ByteRange discovery scans raw bytes.** `cms::extraction` finds
  `/ByteRange` arrays with a byte-level regex, mirroring the Python client:
  a structural PDF parser would not preserve the absolute offsets the byte
  range refers to. Offsets and lengths surface as a domain `ByteRange` type,
  never a leaked regex match.
- **The CoSign digest-algorithm quirk is handled.** CoSign puts the RSA
  signature OID (`sha256WithRSAEncryption`) in the `digestAlgorithm` field;
  `DigestAlgorithm::from_oid` maps both the bare-hash and RSA-with-hash OIDs
  onto the same hash.
- **LTV detection is a scan, not a verification.** `check_ltv_status` reports
  embedded CRLs and Adobe/CAdES revocation attributes. EKENG CoSign signatures
  carry none -- expected, not a defect. Its positive paths are covered by two
  committed fixtures (an embedded CRL and a RevocationInfoArchival attribute)
  built by the same `generate_fixtures.py`.

## PDF signatures: preparing, embedding, and verifying

`revenant-sign-core::pdf` and `revenant-sign-core::appearance` port the Python client's
`pdf` and `appearance` packages: reserve an empty signature field, hash the
ByteRange to send to the appliance, splice the returned CMS into the reserved
`/Contents`, and verify the result. The whole flow is hash-then-sign around a
server that holds the private key, so there is no client-side CMS construction.

- **True incremental updates.** `prepare_pdf_with_sig_field` never rewrites the
  original bytes: it appends the new objects, a matching xref (table *or*
  cross-reference stream, whichever the source PDF uses), and a trailer after the
  existing `%%EOF`. That keeps the signed byte range covering the original
  document unchanged -- what strict validators (and EKENG) require. The signature
  dictionary, appearance forms, embedded font chain, and the ByteRange /
  `/Contents` placeholders are all emitted as raw bytes so the offsets are exact.
- **`lopdf` replaces `pikepdf`, for reading only.** The Python client opens the
  PDF with `pikepdf` (QPDF) purely to *read* structure -- page object numbers and
  dimensions (resolving inherited MediaBox/CropBox/Rotate), the trailer `/Size`,
  the `/Info`+`/ID` carry-forward, and per-object entry enumeration for the
  page/catalog overrides. `pdf::reader::PdfReader` wraps `lopdf` for exactly that
  surface and contains it: the rest of the module depends on plain data, not on a
  PDF library. All writing is raw bytes, so a stricter or laxer parser never
  changes the signed output.
- **The appearance layer is self-contained.** `appearance` embeds the same subset
  TTFs (Noto Sans + two Armenian faces) and their metrics as *generated* Rust
  data (`generate_font_metrics.py` reads the committed Python `metrics.py`
  modules, so glyph widths, the `/W` array, and the ToUnicode CMap are
  byte-faithful -- a unit test cross-checks text measurement against Python
  reference values). Signature images are decoded and resized with the `image`
  crate (the decorative image lies outside the signed range, so its resampling
  need only be visually equivalent to Pillow, not bit-identical).
- **Verification is offline and pure; chain validation is injected.** Rust's
  chain validator needs a network `Transport` (to fetch the TSL and
  intermediates), so `verify_embedded_signature` / `verify_detached_signature`
  take an optional chain-validator *closure* rather than reaching for a global --
  the same injectable-seam pattern the PKI layer uses. Passing `None` runs the
  fully offline checks (ByteRange extraction, CMS structure, hash against the
  expected value or the CMS-declared digest, LTV scan, signer identity).

The pipeline is cross-validated against the Python source of truth in both
directions: a Rust-prepared, signed PDF is accepted by `pikepdf` and by Python's
own `verify_embedded_signature` with a byte-identical ByteRange hash, and a
Python-prepared PDF verifies under Rust's `verify_embedded_signature` -- also
byte-identical. Two runnable examples exercise the flow:

```bash
cargo run -p revenant-sign-core --example prepare_signature -- in.pdf out.pdf
cargo run -p revenant-sign-core --example verify_signature  -- out.pdf <hex-sha1>
```

## Signing: the end-to-end flow and the high-level API

`revenant-sign-core::signing` and `revenant-sign-core::api` port the Python client's
`core.signing` and `api` modules -- the orchestration that turns a raw PDF and a
set of credentials into a signed document.

- **`signing` is transport-agnostic.** `sign_hash`, `sign_data`,
  `sign_pdf_detached`, and `sign_pdf_embedded` take any
  [`SigningTransport`](crates/revenant-sign-core/src/net/protocol.rs); the appliance
  holds the private key and returns the CMS, so nothing is constructed
  client-side. `sign_pdf_embedded` runs the full hash-then-sign cycle -- prepare
  an empty field, hash the ByteRange, send it, splice the returned CMS in, and
  **re-verify before returning** -- so a corrupt signed PDF is an error, never an
  output. Placement and appearance are bundled in `EmbeddedSignatureOptions`,
  where an unset width/height auto-sizes to the display fields.
- **`api` resolves everything from config.** `api::sign` / `api::sign_detached`
  take an injected `ConfigStore` and a shared `Transport` (where the Python
  client reaches for module globals), then resolve the server (explicit profile,
  explicit URL, or the saved active profile), register the profile's TLS mode,
  create the SOAP transport, and fill in the signer name, font, and appearance
  fields from the saved identity and profile. The `SignerInfo` -> `CertInfo`
  bridge that feeds the appearance layer lives here, at the one seam that needs
  both, rather than coupling the config and PKI layers.
- **Identity discovery is a live probe.** `pki::discover_identity_from_server`
  prefers certificate enumeration (no signing side effect) and falls back to
  signing a dummy hash, reading the signer's name, organization, and DN from the
  returned certificate. A wrong password propagates immediately rather than being
  masked by the fallback.
- **Verification is wired to the network here.** The `pdf::verify` layer stays
  offline and pure (it takes an injected chain-validator closure); `api::verify_pdf`,
  `verify_pdf_all`, and `verify_detached` supply that closure, backed by a live
  `Transport` and a `TrustStoreCache`, so passing a profile's TSL URL validates
  the signer's chain while passing `None` runs the fully offline checks.

The whole stack is verified live against the real EKENG appliance (legacy TLS 1.0
+ RC4 -> SOAP -> CMS) by ignored, credential-gated integration tests -- discovery,
embedded signing, detached signing, and the high-level `api::sign`:

```sh
REVENANT_USER=... REVENANT_PASS=... \
    cargo test -p revenant-sign-core --test ekeng_integration -- --ignored --nocapture
```

Credentials are read from the environment only; none are hard-coded. Each test
soft-skips when the variables are unset.

## Command-line interface (`revenant`)

`revenant-sign` is the `revenant` binary -- a thin front-end over the library that
mirrors the Python client's subcommands, flags, and output. A single
`ConfigStore` and one shared `Transport` are threaded through an `App` context,
and every command returns a typed result that maps to the process exit code.

| Command | Purpose |
|---------|---------|
| `sign` | Sign one or more PDFs (embedded, or `--detached` `.p7s`). A batch stops on the first authentication failure to avoid account lockout; `--dry-run` prints the plan without signing. |
| `verify` | Verify a detached CMS against its PDF via `openssl cms -verify` (system trust store), matching the Python client. |
| `check` | Verify a PDF's embedded signature(s) offline (structure + hash, plus TSL chain validation when the active profile has one), with an optional `--server` `DssVerify`. |
| `info` | List the certificates in a CMS `.p7s`: subject, issuer, serial, validity, expiry. |
| `cert` | Show the signer certificate from the server, or `--pdf` from a signed document (offline). |
| `setup` | Interactive wizard: choose a profile, ping, enter credentials, discover identity, save. |
| `logout` / `reset` | Clear credentials + identity (keeping the server), or clear everything. |

Credentials resolve env (`REVENANT_USER` / `REVENANT_PASS`) > saved keychain >
interactive prompt (hidden), and the endpoint env (`REVENANT_URL`) > saved config
> built-in profile. Like the Python client, `verify` shells out to `openssl`
(with a bounded wait) rather than reimplementing system-trust-store CMS
verification -- so a certificate whose CA is not in the OS trust store reports
`INVALID`, exactly as OpenSSL would on the command line. The binary is exercised
end to end against the real EKENG appliance (`cert` / `sign` / `check` / `info`).

## Certificates, TSL, and chain validation

`revenant-sign-core::pki` ports the certificate / Trust Service List / chain modules
of the Python `revenant.core` package. It parses X.509 certificates and CMS
signatures with the RustCrypto `x509-cert` / `cms` crates, extracts signer
identity (`CertInfo`), computes expiry, parses ETSI TSL documents into trust
anchors, and validates a signature's certificate chain against those anchors.

Notable design points, all held to the behavior of the Python source of truth:

- **DER directory strings are decoded, including BMPString.** EKENG's CA encodes
  DN fields as BMPString (UCS-2), which `x509-cert`'s own `Display` renders as a
  hex dump; the `pki::cert` accessors decode it explicitly so names come out as
  text, matching `asn1crypto`'s leniency.
- **Chain validation is tri-state and best-effort.** `ChainResult::chain_valid`
  is `Some(true)` (a trusted anchor and every link's signature verifies),
  `Some(false)` (no trusted anchor found), or `None` (indeterminate -- the CMS
  did not parse, or an anchor matched by key id but the signatures could not be
  verified). It never aborts the surrounding signature verification.
- **The chain is built here, then verified per link.** The signer's chain is
  assembled by SKI/AKI matching (fetching missing intermediates via AIA), then
  each adjacent link's signature is checked with
  [`x509-verify`](https://crates.io/crates/x509-verify). A TLS-oriented path
  validator (webpki) would reject these document-signing certs for lacking a
  serverAuth EKU; per-link verification does not, so a legitimately-chained
  EKENG signature still validates.
- **Anchor matching keeps Python's two stages** -- Subject Key Identifier
  equality first, then an issuer-DN substring fallback that the TypeScript port
  silently drops.
- **The TSL cache is injected, not global.** A `TrustStoreCache` (24h TTL,
  stale-on-error, monotonic clock) replaces the Python module globals, so its
  fetch/hit/stale paths are unit-tested without the network.

Chain tests run against committed DER fixtures generated by the Python
`cryptography` library (`pki/testdata/`, regenerated by `generate_fixtures.py`),
so the Rust reader and verifier are checked against an independent, mature
implementation rather than themselves.
