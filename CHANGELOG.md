# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **TypeScript/Node.js client** (`revenant-sign` on npm) -- full-featured port of the Python client with CLI, library API, and 655 tests at 97%+ coverage
  - Dual ESM + CJS build via tsup
  - Embedded and detached PDF signing
  - Signature verification (embedded and detached CMS/PKCS#7)
  - CMS blob inspection and certificate info extraction
  - Multi-profile configuration with keytar credential storage
  - Legacy TLS 1.0 + RC4 transport for EKENG (pure JS via node-forge)
  - Armenian font support (GHEA Grapalat, GHEA Mariam, Noto Sans)
  - Signature image embedding (PNG/JPEG) with alpha channel support

### Fixed

- PDF incremental updates now use cross-reference streams for PDFs that use XRef streams (PDF 1.5+), per ISO 32000-1 S7.5.8.4 -- fixes compatibility with macOS Preview and strict PDF readers when signing pdf-lib or modern-tool-generated PDFs (both Python and TypeScript)

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

[Unreleased]: https://github.com/lobotomoe/revenant/compare/v0.2.5...HEAD
[0.2.5]: https://github.com/lobotomoe/revenant/compare/v0.2.4...v0.2.5
[0.2.4]: https://github.com/lobotomoe/revenant/compare/v0.2.3...v0.2.4
[0.2.3]: https://github.com/lobotomoe/revenant/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/lobotomoe/revenant/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/lobotomoe/revenant/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/lobotomoe/revenant/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/lobotomoe/revenant/releases/tag/v0.1.0
