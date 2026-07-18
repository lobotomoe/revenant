# revenant-sign-core

Cross-platform client library for ARX CoSign / DocuSign Signature Appliance
electronic signatures via the OASIS DSS SOAP API. It is the Rust port of the
[Revenant](https://github.com/lobotomoe/revenant) client library, exposing the
same surface as the Python and TypeScript ports (minus the GUI).

The crate covers the full hash-then-sign flow around an appliance that holds the
private key: config and credential storage, the CoSign DSS SOAP client (over the
standard or the [`revenant-sign-tls`](https://crates.io/crates/revenant-sign-tls)
TLS 1.0 + RC4 transport), CMS extraction and inspection, PDF signature
preparation / embedding / verification, X.509 and ETSI TSL certificate-chain
validation, and the high-level `api` orchestration that ties them together.

## Scope

- **`config`** -- signer identity, server profiles, and preferences persisted to
  `~/.revenant/config.json` (atomic, `0600`); passwords go to the OS keychain.
- **`net`** -- CoSign DSS SOAP envelopes, parsers, and an auto-detecting HTTP
  transport that falls back to legacy TLS 1.0 + RC4 for old appliances.
- **`cms` / `pki`** -- read-side ASN.1/CMS extraction, signer identity, LTV scan,
  and best-effort TSL-based certificate-chain validation.
- **`pdf` / `appearance`** -- incremental-update signature fields, ByteRange
  hashing, CMS splicing, offline verification, and the visual appearance layer.
- **`signing` / `api`** -- transport-agnostic signing primitives and the
  config-resolving high-level entry points.

The command-line front-end lives in the separate
[`revenant-sign`](https://crates.io/crates/revenant-sign) crate.

## Usage

```toml
[dependencies]
revenant-sign-core = "0.1"
```

Licensed under [Apache-2.0](LICENSE).
