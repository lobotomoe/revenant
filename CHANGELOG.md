# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **Python/TypeScript: signing a PDF that already has a form no longer
  destroys it.** The incremental update now merges the new signature field
  into the existing `/AcroForm` (preserving `/Fields`, `/DR`, `/DA`,
  `/NeedAppearances` and OR-ing `/SigFlags`) instead of replacing it
  wholesale -- the same fix the Rust port received in 2.1.0. Previously,
  signing a form-bearing PDF orphaned its fields, and counter-signing a
  server-pre-signed document (e.g. a tax-portal registration agreement)
  dropped the server's signature field from the form, so validators reported
  the document as tampered.

## [2.1.1] - 2026-07-20

### Fixed

- **macOS: the Dock icon is no longer overridden by a flat square at runtime.**
  The desktop GUI forwarded its embedded window icon to
  `NSApplication.setApplicationIconImage`, which replaced the app bundle's
  rounded `.icns` with a square, full-bleed PNG for as long as the app ran. The
  runtime window icon is now set only on Windows (taskbar) and Linux (window
  manager); on macOS the Dock tile comes from the bundle icon.

## [2.1.0] - 2026-07-20

### Added

- **Rust port: a library plus a `revenant` CLI, published as three crates.**
  A new idiomatic Rust implementation targeting the same surface as the Python
  and TypeScript ports (no GUI):
  - `revenant-sign-tls` — from-scratch TLS 1.0 + RC4-MD5 client for the
    legacy CoSign appliances (EKENG's `ca.gov.am`) that no maintained Rust TLS
    library can reach, mirroring `tlslite-ng` / `node-forge`.
  - `revenant-sign-core` — the client library: config and credential storage, the
    CoSign DSS SOAP client with auto-detecting transport, CMS extraction,
    PDF signature preparation / embedding / verification, and pinned/TSL
    certificate-chain validation.
  - `revenant-sign` — the `revenant` binary (`sign`, `verify`, `check`, `info`,
    `cert`, `setup`, `logout`, `reset`), a thin front-end over `revenant-sign-core`.
- **Three new GUI languages: Turkish (tr), Georgian (ka), and Persian (fa).**
  The desktop app now ships in six languages. Persian is right-to-left;
  text in labels, messages, and input fields is right-aligned automatically
  when a right-to-left locale is active.

### Changed

- **The Rust workspace now versions as one unit on the product line (2.1.0),
  continuing from the Python client rather than restarting at 0.1.x.** The
  library crates (`revenant-sign-core`, `revenant-sign-tls`) and the shipped
  binaries (`revenant-sign`, `revenant-sign-gui`) share a single version, so the
  CLI `--version`, the GUI About box, the store listings, and the signer version
  recorded in each signed PDF (`/Prop_Build /REx`) all report the same number --
  matching the single-version model the Python and TypeScript packages use.

### Fixed

- **Rust: signing a PDF that already has a form no longer destroys it.** The
  incremental update now merges the new signature field into the existing
  `/AcroForm` (preserving `/Fields`, `/DR`, `/DA`, `/NeedAppearances` and
  OR-ing `/SigFlags`) instead of replacing it wholesale. Previously, signing a
  form-bearing PDF orphaned its fields, and re-signing dropped the earlier
  signature from the form.
- **Rust: `revenant verify` now recognises genuine signatures as trusted.** It
  validates detached CMS signatures fully in-crate against the active profile's
  pinned trust anchors (the same path `check` uses), instead of shelling out to
  `openssl` with the system trust store — which lacks the EKENG root and
  reported every valid signature as `INVALID`. The external `openssl`
  dependency is gone.
- **Rust: the CMS verifier no longer reports a signature `Valid` when the
  mandatory `contentType` signed attribute is missing or disagrees with
  `eContentType`** (RFC 5652 §11.1). It also now verifies the ESS
  `signingCertificate` / `signingCertificateV2` binding when present (RFC 5035):
  a signature whose ESSCertID hash names a different certificate than the one
  that verified is no longer accepted. EKENG CoSign signatures carry the v1
  form and continue to verify.
- **Rust: a CMS whose signature could not be *checked* (unusable key,
  unsupported algorithm OID, DER decode failure) is now reported `Unverifiable`
  rather than `Invalid`** — the latter wrongly implied the signature was forged.
- **Rust: the legacy TLS handshake is now bounded by an overall deadline,** so a
  server that dribbles records (or empty handshake records) can no longer pin a
  client thread indefinitely past the per-read socket timeout.
- **Rust: smaller correctness and robustness fixes.**
  - LTV status no longer claims an OCSP response merely because an Adobe
    `RevocationInfoArchival` container is present (it may hold only CRLs).
  - `/Contents` hex extraction now ignores insignificant white space inside the
    hex string, per ISO 32000-1 §7.3.4.3, so signatures laid out by other tools
    are read correctly.
  - The trailer `/ID` is carried into the incremental update as a hex string,
    preserving binary `/ID` values byte-for-byte instead of mangling them
    through a lossy UTF-8 conversion.
  - Signing a document whose catalog is at a non-zero generation now fails with
    a clear message instead of producing a structurally inconsistent file.
  - Signing a document large enough that a cross-reference-stream byte offset
    would exceed the 4-byte xref field now fails loudly instead of silently
    truncating the offset into a corrupt xref stream.
  - The legacy TLS client rejects a ServerHello that selects a version other
    than TLS 1.0, parses IPv6 URL literals correctly, and fails loudly if the
    socket read/write timeout cannot be set (rather than silently blocking).

## [2.0.0] - 2026-05-16

### TypeScript SDK only — Python client is unchanged

### Breaking

- Low-level signing functions in `revenant-sign` are renamed with a
  `WithTransport` suffix to free their unsuffixed names for new
  high-level wrappers:
  - `signPdfEmbedded` → `signPdfEmbeddedWithTransport`
  - `signPdfDetached` → `signPdfDetachedWithTransport`
  - `signHash` → `signHashWithTransport`
  - `signData` → `signDataWithTransport`

  The `SigningTransport` interface method names (`transport.signHash`,
  `transport.signData`, `transport.signPdfDetached`) are unchanged.
  Migration: rename your imports; transport-handling code is untouched.

### Added

- **High-level `signHash(hashBytes, username, password, options?)`** —
  detached CMS over a precomputed 20-byte SHA-1 hash, with profile
  resolution, transport setup, and TLS registration handled internally.
  Production callers no longer need to construct a `SoapSigningTransport`
  to sign a hash.
- **High-level `signData(dataBytes, username, password, options?)`** —
  same shape, detached CMS over arbitrary bytes (server computes the
  hash).
- **High-level `getCertInfo(username, password, options?)`** — returns
  the signer's identity (`CertInfo`: CN, email, organization, DN,
  `notBefore`, `notAfter`) by trying the `enum-certificates` SAPI
  operation first, falling back to dummy-hash signing.
- **High-level `verifyCredentials(username, password, options?)`** —
  thin wrapper over `getCertInfo` that discards the result and surfaces
  `AuthError` on bad credentials. One round-trip against the appliance's
  5-attempt lockout counter; suitable for "test before persist"
  credential-entry flows.
- `CertInfo` type is re-exported from the top-level `revenant-sign`
  entry.

## [1.2.1] - 2026-04-16

### Fixed

- Completed Armenian (hy) locale -- 21 strings were showing English fallback

## [1.2.0] - 2026-04-14

### Added

- **PKI chain validation** against ETSI Trust Service Lists (TSL) -- verifies signer certificate chains to trusted CAs (Python and TypeScript)
- TSL parser and cache with configurable TTL (24h default)
- Per-profile `tsl_url` field; EKENG profile uses the Armenian TSL
- Trust status display in GUI verify panel (trusted / not publicly trusted / not checked)
- Improved verify result formatting -- human-readable summary above technical details

### Improved

- Test coverage expanded to 95%+ (740 tests)
- New test modules: chain validation, LTV, ASN.1 BER edge cases, i18n

### Fixed

- CVE-2026-40192 (pillow), CVE-2025-71176 (pytest)
- CI: added `cryptography` and Python 3.10 backports to dev requirements

## [1.1.1] - 2026-04-10

### Improved

- Updated Russian and Armenian translations
- Added English locale for i18n completeness
- Refined translatable strings across GUI modules

## [1.1.0] - 2026-04-09

### Added

- **Localization**: Russian and Armenian language support for the GUI (gettext-based i18n)
- **Signature position preview**: mini page diagram in the sign form showing stamp placement
- **Password visibility toggle** in the login dialog
- **Friendly error messages**: raw HTTP/TLS errors mapped to user-readable messages in the GUI
- **ASCII credential warning**: warn when credentials contain non-Latin characters
- **Universal macOS binaries** (arm64 + x86_64) -- Intel Mac users can now install from the Mac App Store, Homebrew, and DMG
- Mac App Store badge in README
- `merge_universal.py` script for lipo-merging .app bundles and CLI binaries
- Translation consistency checker (`check_translations.py`) and .po compiler (`compile_translations.py`)

### Changed

- Homebrew formula no longer requires `arch: :arm64`
- Release pipeline builds on both `macos-latest` (arm64) and `macos-15-intel` (x86_64), merges with `lipo`
- Release artifacts renamed from `*-macos-arm64` to `*-macos-universal`
- Credential resolution moved off main thread to prevent UI freeze on macOS keychain prompts
- Platform-specific helpers (macOS menu bar, Windows icon) extracted to dedicated module

### Fixed

- Support for original EKENG cosign BER-encoded PDF signatures (indefinite-length CMS blobs) in both Python and TypeScript
- BER parser guards against deeply nested structures (depth limit) and oversized length fields
- npm publish step in release pipeline no longer silently swallows errors
- macOS notarization step properly fails on command errors instead of silently continuing

## [1.0.0] - 2026-02-26

### Added

- **TypeScript/Node.js client** (`revenant-sign` on npm) -- full-featured port of the Python client with CLI, library API, and 662 tests at 97%+ coverage
  - Dual ESM + CJS build via tsup
  - Embedded and detached PDF signing
  - Signature verification (embedded and detached CMS/PKCS#7)
  - CMS blob inspection and certificate info extraction
  - Multi-profile configuration with keytar credential storage
  - Legacy TLS 1.0 + RC4 transport for EKENG (pure JS via node-forge)
  - Armenian font support (GHEA Grapalat, GHEA Mariam, Noto Sans)
  - Signature image embedding (PNG/JPEG) with alpha channel support
- Microsoft Store distribution (Revenant Sign) with Partner Center identity
- Release pipeline now includes MAS .pkg in GitHub Releases

### Changed

- MSIX package renamed to RevenantSign.msix, display name updated to "Revenant Sign"

### Fixed

- PDF incremental updates now use cross-reference streams for PDFs that use XRef streams (PDF 1.5+), per ISO 32000-1 S7.5.8.4 -- fixes compatibility with macOS Preview and strict PDF readers when signing pdf-lib or modern-tool-generated PDFs (both Python and TypeScript)

## [0.2.6] - 2026-02-26

### Changed

- GUI window title simplified to "Revenant" (version removed to avoid screenshot staleness)
- MAS minimum deployment target bumped from macOS 11.0 to 12.0 (required for arm64-only builds)

## [0.2.5] - 2026-02-26

### Added

- macOS menu bar with File (Close Window) and Edit (Undo, Cut, Copy, Paste, Select All) menus
- Cmd+W keyboard shortcut to close windows and dialogs on macOS
- Privacy policy URL in Info.plist (MAS Guideline 5.1.1)

### Changed

- PyPI classifier updated from Beta to Production/Stable (MAS Guideline 2.2)

### Fixed

- MAS build: switch from system Tk 8.6 to Homebrew Tk 9.0 to resolve private API rejection (Guideline 2.5.1 -- `_NSWindowDidOrderOnScreenNotification`)
- CI: extract Python+Tk setup and private API verification into reusable composite actions
- macOS Preferences menu item no longer shows default Tk behavior

## [0.2.4] - 2026-02-21

### Fixed

- MAS build: use separate entitlements for nested executables to avoid ITMS-90885

## [0.2.3] - 2026-02-21

### Fixed

- MAS build: add application identifier to sandbox entitlements (ITMS-90886)

## [0.2.2] - 2026-02-21

### Fixed

- MAS build: embed provisioning profile for TestFlight and App Store submission (ITMS-90889)

## [0.2.1] - 2026-02-20

### Added

- Linux ARM64 build support
- Automatic Homebrew tap update on release

## [0.2.0] - 2026-02-16

### Changed

- **BREAKING:** Position preset names renamed to Y-first (CSS/UI) convention: `right-bottom` -> `bottom-right`, `right-top` -> `top-right`, `left-bottom` -> `bottom-left`, `left-top` -> `top-left`, `center-bottom` -> `bottom-center`. Short aliases updated accordingly (`rb` -> `br`, `rt` -> `tr`, etc.)
- Windows release artifact renamed from `revenant-cli-windows-x64.zip` to `revenant-windows-x64.zip` (contains both CLI and GUI)

### Fixed

- MAS build: include sandbox entitlements when signing outer .app bundle
- Snap: use `adopt-info` for version instead of `git describe`
- Integration tests TLS setup for env-var-only credentials

## [0.1.0] - 2026-02-14

### Added

- PDF digital signing via CoSign SAPI Web Service (SOAP/DSS)
- Embedded visible and invisible signature support with customizable appearance
- Armenian font support (GHEA Grapalat, GHEA Mariam, Noto Sans)
- Signature image embedding (PNG/JPEG) with alpha channel support
- PDF signature verification (embedded and detached CMS/PKCS#7)
- CMS blob inspection: digest algorithm, signer info, certificate chain
- Certificate information extraction from X.509 and CMS blobs
- Multi-profile configuration with per-profile credentials (keyring or config file)
- Automatic CoSign server discovery via DNS SRV records
- Legacy TLS 1.0 + RC4-MD5 transport for EKENG (ca.gov.am)
- Cross-platform GUI (tkinter) with sign, verify, and setup dialogs
- CLI with `sign`, `verify`, and `setup` commands
- Incremental PDF updates preserving existing signatures (re-signing support)
- Cross-reference stream PDF support (modern PDF 1.5+ format)
- Page size detection with CropBox/MediaBox/Rotate handling
- CI/CD workflows for linting, testing, and release builds
- Multi-platform release builds: macOS (.dmg), Windows (.msix, .zip), Linux (AppImage)
- Pyright strict mode type checking with 0 errors
- 96%+ test coverage (600+ tests)

[Unreleased]: https://github.com/lobotomoe/revenant/compare/v2.1.1...HEAD
[2.1.1]: https://github.com/lobotomoe/revenant/compare/v2.1.0...v2.1.1
[2.1.0]: https://github.com/lobotomoe/revenant/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/lobotomoe/revenant/compare/v1.2.1...v2.0.0
[1.2.1]: https://github.com/lobotomoe/revenant/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/lobotomoe/revenant/compare/v1.1.1...v1.2.0
[1.1.1]: https://github.com/lobotomoe/revenant/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/lobotomoe/revenant/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/lobotomoe/revenant/compare/v0.2.6...v1.0.0
[0.2.6]: https://github.com/lobotomoe/revenant/compare/v0.2.5...v0.2.6
[0.2.5]: https://github.com/lobotomoe/revenant/compare/v0.2.4...v0.2.5
[0.2.4]: https://github.com/lobotomoe/revenant/compare/v0.2.3...v0.2.4
[0.2.3]: https://github.com/lobotomoe/revenant/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/lobotomoe/revenant/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/lobotomoe/revenant/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/lobotomoe/revenant/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/lobotomoe/revenant/releases/tag/v0.1.0
