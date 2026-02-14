# Documentation

Technical documentation for the Revenant project — protocol details, implementation notes, and server-specific behavior.

For installation and usage, see [`python/README.md`](../python/README.md).

## Contents

### Protocol & Implementation

These documents describe behavior common to any CoSign appliance:

| Document | Description |
|---|---|
| [soap-api.md](soap-api.md) | SOAP API reference: DssSign/DssVerify operations, authentication, SPML, identity discovery |
| [embedded-signing.md](embedded-signing.md) | Embedded PDF signature implementation: incremental updates, visual appearance, differences from CoSign desktop |
| [verification.md](verification.md) | Post-sign verification: hash checks, CMS quirks, openssl incompatibility |

### EKENG-specific

| Document | Description |
|---|---|
| [ekeng/](ekeng/) | Armenian Government EKENG appliance: server details, TLS, PKI, e-keng validator requirements |

EKENG is configured as a built-in server profile in [`python/src/revenant/config/profiles.py`](../python/src/revenant/config/profiles.py).

### Build & Release

| Document | Description |
|---|---|
| [macos-signing.md](macos-signing.md) | macOS code signing & notarization setup for CI |

### Reference

| File | Description |
|---|---|
| [wsdl_dss.xml](wsdl_dss.xml) | Saved WSDL from the CoSign appliance |

## Known limitations

Protocol and server-side limitations that affect all clients. For Python client-specific limitations, see [`python/README.md`](../python/README.md#known-limitations).

- **SHA-1 only** — the server rejects SHA-256. SHA-1 is cryptographically broken (collision attacks are practical since 2017), but remains widely supported by PDF validators for legacy compatibility. This is a server-side limitation.
- **Non-standard CMS OIDs** — the server returns `sha1WithRSAEncryption` as digestAlgorithm (wrong per RFC 5652). See [verification.md](verification.md).
- **No timestamp (TSA)** — the WSDL defines timestamp options but the server ignores them.
- **Document size limit** — 35 MB reliable, 36+ MB intermittent failures. See [soap-api.md](soap-api.md#document-size-limits).

## Dependencies

- `pikepdf` — PDF reading (not writing). Brings in `qpdf`, `Pillow`, `lxml`.
- `asn1crypto` — ASN.1/DER parsing for certificate extraction (PKCS#7, X.509). Pure Python.
- `tlslite-ng` — pure-Python TLS for legacy servers (TLS 1.0 / RC4). Standard servers use `urllib`.
- `defusedxml` — safe XML parsing (prevents XML bomb / billion laughs attacks on SOAP responses).
- `openssl` — `verify` CLI command (optional, for detached signature verification).
