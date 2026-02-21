# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/lobotomoe/revenant/compare/v0.2.4...HEAD
[0.2.4]: https://github.com/lobotomoe/revenant/compare/v0.2.3...v0.2.4
[0.2.3]: https://github.com/lobotomoe/revenant/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/lobotomoe/revenant/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/lobotomoe/revenant/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/lobotomoe/revenant/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/lobotomoe/revenant/releases/tag/v0.1.0
