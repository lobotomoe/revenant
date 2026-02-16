<p align="center">
  <img src="icons/revenant-readme.png" width="128" alt="Revenant">
</p>

# revenant (Python)

[![CI](https://github.com/lobotomoe/revenant/actions/workflows/ci.yml/badge.svg)](https://github.com/lobotomoe/revenant/actions/workflows/ci.yml)
[![pyright: strict](https://img.shields.io/badge/pyright-strict-blue)](https://github.com/microsoft/pyright)
[![coverage: 96%](https://img.shields.io/badge/coverage-96%25-brightgreen)](pyproject.toml)
[![code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://docs.astral.sh/ruff/)

Cross-platform Python client for ARX CoSign electronic signatures via SOAP API. No Windows required.

Server-specific settings (URL, TLS, identity discovery) are managed through **server profiles** — see [`src/revenant/config/profiles.py`](src/revenant/config/profiles.py). EKENG-specific details are documented in [`../docs/ekeng/`](../docs/ekeng/). For SOAP API technical details, see [`../docs/soap-api.md`](../docs/soap-api.md).

## Download

Pre-built binaries are available on the [Releases](https://github.com/lobotomoe/revenant/releases) page:

| Platform | CLI | GUI |
|----------|-----|-----|
| **macOS (Apple Silicon)** | `revenant-cli-macos-arm64` | `Revenant-gui-macos-arm64.dmg` |
| **Linux (x64)** | `revenant-cli-linux-x64` | `Revenant-x86_64.AppImage` |
| **Linux (ARM64)** | `revenant-cli-linux-arm64` | `Revenant-aarch64.AppImage` |
| **Windows (x64)** | `revenant-windows-x64.zip` | `Revenant.msix` |

### Quick start (macOS)

```bash
# Download and run CLI
curl -LO https://github.com/lobotomoe/revenant/releases/latest/download/revenant-cli-macos-arm64
chmod +x revenant-cli-macos-arm64
./revenant-cli-macos-arm64 setup
```

### Quick start (Linux x64)

```bash
# CLI
curl -LO https://github.com/lobotomoe/revenant/releases/latest/download/revenant-cli-linux-x64
chmod +x revenant-cli-linux-x64
./revenant-cli-linux-x64 setup

# GUI (AppImage)
curl -LO https://github.com/lobotomoe/revenant/releases/latest/download/Revenant-x86_64.AppImage
chmod +x Revenant-x86_64.AppImage
./Revenant-x86_64.AppImage
```

### Quick start (Linux ARM64)

```bash
# CLI
curl -LO https://github.com/lobotomoe/revenant/releases/latest/download/revenant-cli-linux-arm64
chmod +x revenant-cli-linux-arm64
./revenant-cli-linux-arm64 setup

# GUI (AppImage)
curl -LO https://github.com/lobotomoe/revenant/releases/latest/download/Revenant-aarch64.AppImage
chmod +x Revenant-aarch64.AppImage
./Revenant-aarch64.AppImage
```

### Quick start (Windows)

Download `revenant-windows-x64.zip` from [Releases](https://github.com/lobotomoe/revenant/releases), extract, and run:

```powershell
Expand-Archive revenant-windows-x64.zip -DestinationPath revenant
.\revenant\revenant.exe setup
```

Alternatively, install the GUI via `Revenant.msix` (double-click to install).

## Installation (pip)

```bash
# Install directly from GitHub
pip install "revenant @ git+https://github.com/lobotomoe/revenant.git#subdirectory=python"

# Or clone and install in editable mode (for development)
git clone https://github.com/lobotomoe/revenant
cd revenant/python
pip install -e "."                # core functionality (includes pikepdf)
pip install -e ".[secure]"        # + secure credential storage (keyring)
pip install -e ".[dev]"           # + development tools (pytest, ruff, pyright)
```

## Quick start (library)

```python
import revenant

# Sign with a built-in profile (handles URL, TLS, font automatically)
signed_pdf = revenant.sign(pdf_bytes, "user", "pass", profile="ekeng")

# Sign with a custom server URL
signed_pdf = revenant.sign(pdf_bytes, "user", "pass", url="https://server/SAPIWS/DSS.asmx")

# Use saved config (after `revenant setup`)
signed_pdf = revenant.sign(pdf_bytes, "user", "pass")

# Detached CMS/PKCS#7 signature
cms_der = revenant.sign_detached(pdf_bytes, "user", "pass", profile="ekeng")
```

All functions raise typed exceptions (`AuthError`, `ServerError`, `TLSError`). See [Library usage](#library-usage) for the full low-level API.

## Usage

### Initial setup

Configure your server, credentials, and signer identity:

```bash
revenant setup                    # interactive wizard
revenant setup --profile ekeng    # skip server selection
```

The setup wizard walks you through:
1. **Choose server** — pick a built-in profile (e.g. EKENG) or enter a custom URL
2. **Ping server** — verify the endpoint is reachable (WSDL fetch, no auth)
3. **Enter credentials** — with lockout warnings for profiles that have them
4. **Discover identity** — automatically extracts your name/email/org from the server's signing certificate. Falls back to signed PDF extraction or manual entry.
5. **Save** — writes everything to `~/.revenant/config.json`

You can re-run `revenant setup` at any time to reconfigure.

### GUI

A graphical interface is available via tkinter (Python stdlib):

```bash
revenant gui          # if installed via pip
revenant-gui          # alternative entry point
python -m revenant gui
```

The GUI provides file pickers for PDF/image/output, credential fields, position/page selectors, and a Sign button.

Requires `tkinter` — if missing, the tool shows platform-specific install instructions (e.g. `brew install python-tk@3.13` on macOS).

### Sign a PDF (embedded — default)

```bash
# Embedded signature — produces document_signed.pdf
revenant sign document.pdf

# Custom output path
revenant sign document.pdf -o signed.pdf

# Sign multiple files
revenant sign *.pdf

# Detached .p7s signature instead
revenant sign document.pdf --detached

# Preview what would be done (no actual signing)
revenant sign document.pdf --dry-run

# Specify page and position
revenant sign document.pdf --page 1 --position top-left
revenant sign document.pdf --page last --position bottom-center

# Add signature image (PNG or JPEG, scaled to fit field, left side)
revenant sign document.pdf --image signature.png

# Armenian-script signature appearance
revenant sign document.pdf --font ghea-grapalat
```

**Page numbering:** CLI uses 1-based pages (`--page 1` = first page). Use `first`, `last`, or a number.

**Fonts:** `noto-sans` (default, Latin/Cyrillic), `ghea-grapalat` (Armenian), `ghea-mariam` (Armenian serif). The EKENG profile defaults to `ghea-grapalat`.

**Signature image:** PNG or JPEG. The image is scaled proportionally to fit the left side of the signature field. Recommended: transparent PNG, around 200x100px.

### Verify a signature

```bash
# Verify using CA root cert (auto-detected from certs/ directory)
revenant verify document.pdf

# Specify signature file explicitly
revenant verify document.pdf -s document.pdf.p7s
```

### Check an embedded signature

```bash
revenant check signed.pdf
```

### Inspect a detached signature

```bash
revenant info document.pdf.p7s
```

### Manage configuration

```bash
revenant logout   # clear credentials + identity, keep server config
revenant reset    # clear everything (server, credentials, identity)
```

`logout` preserves the server URL and profile so you can re-authenticate with `revenant setup` without reconfiguring the server. `reset` removes all configuration from `~/.revenant/config.json`.

### Output modes

By default, the tool produces **embedded PDF signatures** (visible signature field in the PDF). Use `--detached` for detached CMS/PKCS#7 `.p7s` files.

Embedded signing uses a **true incremental update** — the original PDF bytes are preserved exactly, with signature objects appended after `%%EOF`. pikepdf is used read-only (page dimensions, object graph) and never rewrites the PDF.

Embedded signing includes **automatic post-sign verification** — after inserting the CMS, the tool re-reads the PDF and confirms the ByteRange hash matches what was sent to the server. If verification fails, the file is not saved.

Embedded signatures include a **visual appearance stream** — fields configured per server profile (name, ID, date, etc.) are stacked vertically. With an optional signature image, the image appears on the left. Configure signer identity via `revenant setup`.

The detached `.p7s` file can be verified with:
- `openssl cms -verify -inform DER -in doc.pdf.p7s -content doc.pdf -CAfile certs/ca_root.pem`
- Any PKCS#7/CMS-compatible verification tool

## Library usage

The package can be used as a Python library — the CLI is just a thin wrapper.

```python
import revenant
from revenant.network.soap_transport import SoapSigningTransport

transport = SoapSigningTransport("https://ca.gov.am:8080/SAPIWS/DSS.asmx")

# Embedded signature (visible field in the PDF, requires pikepdf)
# Library uses 0-based pages (page=0 = first page)
signed_pdf = revenant.sign_pdf_embedded(
    pdf_bytes, transport, "user", "pass", timeout=120,
    page=0, x=350, y=50, w=200, h=70,
    name="Signer Name", reason="Approved",
)

# Detached CMS/PKCS#7 signature
cms_der = revenant.sign_pdf_detached(pdf_bytes, transport, "user", "pass")

# Sign a raw SHA-1 hash (for custom workflows)
import hashlib
digest = hashlib.sha1(data).digest()
cms_der = revenant.sign_hash(digest, transport, "user", "pass")

# Sign arbitrary data (server computes the hash)
cms_der = revenant.sign_data(raw_bytes, transport, "user", "pass")
```

### Verification

```python
# Verify the last embedded signature
result = revenant.verify_embedded_signature(signed_pdf)
print(result.valid, result.details)

# Verify ALL signatures in a multi-signed PDF
results = revenant.verify_all_embedded_signatures(signed_pdf)
for r in results:
    print(r.signer, r.valid)
```

### Signature positioning

```python
# Available position presets
print(revenant.POSITION_PRESETS)
# {'bottom-right', 'top-right', 'bottom-left', 'top-left', 'bottom-center'}

# Resolve aliases (e.g. "br" -> "bottom-right")
pos = revenant.resolve_position("br")
```

### Signature options

`EmbeddedSignatureOptions` bundles all appearance and positioning parameters:

```python
from revenant import EmbeddedSignatureOptions

opts = EmbeddedSignatureOptions(
    page="last",                 # 0-based int, "first", or "last"
    position="bottom-right",     # preset name (ignored when x/y are set)
    x=350, y=50,                 # manual coordinates (PDF points, origin=bottom-left)
    w=200, h=70,                 # field dimensions in PDF points
    reason="Approved",           # signature reason string
    name="Signer Name",         # signer display name
    image_path="sig.png",        # optional PNG/JPEG signature image
    fields=["Name", "Date"],     # custom appearance field strings
    visible=True,                # False for invisible signatures
    font="noto-sans",            # "noto-sans", "ghea-grapalat", or "ghea-mariam"
)

signed = revenant.sign_pdf_embedded(pdf, transport, user, pw, options=opts)
```

### Utilities

```python
# Get configured signer name (from ~/.revenant/config.json)
name = revenant.get_signer_name()  # returns str | None
```

### Error handling

All functions raise typed exceptions from a hierarchy rooted at `RevenantError`:

```
RevenantError (base)
├── AuthError           -- wrong credentials, account locked
├── ServerError         -- server returned an error response
├── TLSError            -- connection/TLS issues (.retryable flag)
├── PDFError            -- invalid PDF structure, parse failures
├── ConfigError         -- missing or malformed configuration
└── CertificateError    -- certificate parsing/extraction errors
```

```python
from revenant import AuthError, ServerError, TLSError, PDFError

try:
    revenant.sign_pdf_embedded(pdf, transport, user, password)
except AuthError:
    print("Wrong credentials or account locked")
except TLSError as e:
    if e.retryable:
        print("Transient connection error, retry later")
    else:
        print(f"TLS configuration issue: {e}")
except ServerError as e:
    print(f"Server error: {e}")
except PDFError as e:
    print(f"Invalid PDF: {e}")
```

### API stability

This project follows semver. The public API (`revenant.__all__`) is stable from 1.0. Pre-1.0 releases may have breaking changes between minor versions.

## Server profiles

Server-specific settings are managed through `ServerProfile` objects. The EKENG profile is built-in; custom servers are created at setup time.

### Built-in profile: EKENG

- URL: `https://ca.gov.am:8080/SAPIWS/DSS.asmx`
- TLS: Legacy TLSv1.0 / RC4-MD5 (auto-detected)
- Account lockout: 5 failed attempts
- Font: `ghea-grapalat` (Armenian)
- Identity: extracted from signing certificate (name, SSN, email)

### Custom servers

Run `revenant setup` and choose "Custom URL" to configure any CoSign server. The tool auto-detects whether the server requires legacy TLS on first connection.

`ServerProfile` fields (defined in [`src/revenant/config/profiles.py`](src/revenant/config/profiles.py)):

| Field | Type | Description |
|-------|------|-------------|
| `name` | `str` | Profile identifier |
| `url` | `str` | SOAP endpoint URL (HTTPS only) |
| `timeout` | `int` | Request timeout in seconds (default: 120) |
| `legacy_tls` | `bool` | Force TLSv1.0/RC4 mode (default: auto-detect) |
| `identity_methods` | `tuple` | Discovery methods: `"server"`, `"manual"` |
| `ca_cert_markers` | `tuple` | Strings to identify CA certificates for filtering |
| `max_auth_attempts` | `int` | Lockout threshold (0 = no lockout warning) |
| `cert_fields` | `tuple` | Certificate fields for identity extraction |
| `sig_fields` | `tuple` | Fields for signature visual appearance |
| `font` | `str` | Default font for signatures |

## Prerequisites

- Python 3.10+
- `pikepdf` — for embedded PDF signatures (brings in `qpdf`, `Pillow`, `lxml`)
- `asn1crypto` — certificate parsing (PKCS#7, X.509)
- `tlslite-ng` — legacy TLS for servers requiring TLS 1.0 / RC4 (e.g. EKENG)
- `defusedxml` — safe XML parsing for SOAP responses
- `openssl` for the `verify` command (optional, for detached signature verification)
- CoSign credentials (username + password)
- Network access to the CoSign server

All Python dependencies are installed automatically via `pip install`.

### Platform notes

| | macOS | Linux | Windows |
|---|---|---|---|
| **Signing** (`sign`) | works out of the box | works out of the box | works out of the box |
| **Embedded PDF** | pikepdf | pikepdf | pikepdf |
| **GUI** (`revenant gui`) | `brew install python-tk` | `apt install python3-tk` | included with Python |
| **verify** | openssl included | openssl included | requires OpenSSL install |

The core Python code is fully cross-platform. TLS is handled transparently: standard servers use system HTTPS (`urllib`), while legacy servers (e.g. EKENG with TLSv1.0/RC4) are handled via `tlslite-ng` (pure Python, no native dependencies). The transport layer auto-detects TLS mode per host on first connection. See [`../docs/ekeng/`](../docs/ekeng/) for EKENG-specific details.

### Credentials

Credentials are resolved in this order (first match wins):

1. **Environment variables** `REVENANT_USER` / `REVENANT_PASS`
2. **System keychain** via `keyring` (if installed)
3. **Saved config** in `~/.revenant/config.json` (saved during `revenant setup` or after first successful sign)
4. **Interactive prompt** (if none of the above)

After a successful signing from an interactive prompt, the tool offers to save credentials for future use.

#### Secure storage (recommended)

Install with keyring support for secure credential storage:

```bash
pip install revenant[secure]
# or
pip install keyring
```

When `keyring` is installed, passwords are stored in your system's secure credential store:
- **macOS**: Keychain
- **Linux**: Secret Service (GNOME Keyring, KWallet)
- **Windows**: Windows Credential Manager

The username is still saved in `~/.revenant/config.json`, but the password is stored securely in the system keychain.

#### Fallback (plaintext)

If `keyring` is not installed, credentials are stored in `~/.revenant/config.json` (permissions `0600`). **You will see a warning** when saving credentials without keyring:

```
WARNING: Password is stored in PLAINTEXT (file is chmod 600)
For secure storage, install: pip install keyring
```

To clear saved credentials, remove `username`/`password` from the config file or delete it.

### Environment variables

| Variable           | Description                                                       |
| ------------------ | ----------------------------------------------------------------- |
| `REVENANT_USER`    | CoSign username (overrides saved config)                          |
| `REVENANT_PASS`    | CoSign password (overrides saved config)                          |
| `REVENANT_URL`     | SOAP endpoint (overrides profile URL from `revenant setup`)       |
| `REVENANT_TIMEOUT` | Request timeout in seconds (default: 120)                         |
| `REVENANT_NAME`    | Signer display name (overrides config from `revenant setup`)      |

## Development

```bash
cd python/
pip install -e ".[dev]"     # install with dev tools (pytest, ruff, pyright)
pytest                      # run unit tests (no server needed)
ruff check src/             # lint
ruff format src/            # format
pyright src/                # type check

# Integration tests (require live server + credentials)
REVENANT_USER=... REVENANT_PASS=... pytest -m integration
```

## Building from source

Build standalone binaries (CLI + GUI) from the Python source. Each platform uses a different toolchain.

### macOS (.app + DMG)

Uses [py2app](https://py2app.readthedocs.io/) for a sandbox-compatible `.app` bundle.

```bash
cd python/

# Install build dependencies
pip install -e ".[build-mac]"

# Optional: install create-dmg for a fancy DMG layout (Applications link, background image)
brew install create-dmg

# Build .app bundle + DMG
python scripts/build.py mac

# Build .app only (no DMG -- useful if you want to sign before creating the DMG)
python scripts/build.py mac --no-dmg

# Create DMG from an existing .app
python scripts/build.py dmg
```

**Requires:** Python 3.10+, tkinter (`brew install python-tk@3.13`), Xcode Command Line Tools.

**Output:** `dist/Revenant.app`, `dist/Revenant.dmg`

### Linux (CLI + GUI + AppImage)

Uses [PyInstaller](https://pyinstaller.org/) for standalone one-file binaries.

```bash
cd python/

# Install build dependencies
pip install -e ".[build]"

# Build GUI + CLI binaries (runs in parallel)
python scripts/build.py all

# Build only CLI or GUI
python scripts/build.py cli
python scripts/build.py gui

# Create AppImage from the GUI binary (requires Linux)
python scripts/build_appimage.py
```

**Requires:** Python 3.10+, tkinter (`apt install python3-tk` for GUI).

**Output:** `dist/revenant` (CLI), `dist/revenant-gui` (GUI), `dist/Revenant-{arch}.AppImage` (e.g. `Revenant-x86_64.AppImage`, `Revenant-aarch64.AppImage`)

### Windows (CLI + GUI + MSIX)

Uses [Nuitka](https://nuitka.net/) for standalone executables (avoids Windows Defender false positives from PyInstaller's extract-to-temp pattern).

```bash
cd python

# Install build dependencies
pip install -e ".[build-win]"

# Build GUI + CLI (sequential -- Nuitka shares a download cache)
python scripts/build.py all

# Build only CLI or GUI
python scripts/build.py cli
python scripts/build.py gui

# Create MSIX package (requires Windows SDK for makeappx.exe)
python scripts/build_msix.py
```

**Requires:** Python 3.10+, tkinter (included with Python on Windows), Windows SDK (for MSIX only).

**Output:** `dist/revenant-standalone/` (folder with `revenant.exe` + `revenant-gui.exe`), `dist/Revenant.msix`

## EKENG-specific notes

EKENG-specific behavior is documented in [`../docs/ekeng/`](../docs/ekeng/) and configured as the `ekeng` profile in [`src/revenant/config/profiles.py`](src/revenant/config/profiles.py).

Key points:
- Server: `ca.gov.am:8080` (TLSv1.0 / RC4-MD5)
- Account lockout after 5 failed attempts
- Signatures are accepted by the EKENG validator (`ekeng.am`) and e-request (`e-request.am`)

## Troubleshooting

**`AuthError: Authentication failed`** -- Wrong username or password. If using EKENG, the account locks after 5 failed attempts. Wait or contact your administrator.

**`TLSError: ...`** -- Server unreachable or TLS version mismatch. Check network access to the server. For EKENG, the server requires TLSv1.0/RC4 which is handled automatically by `tlslite-ng`.

**`ServerError: ...`** -- The server rejected the request. Common causes: expired certificate, server maintenance, or unsupported document format.

**`PDFError: ...`** -- The PDF is malformed, encrypted, or not a valid PDF file. Try re-saving the PDF from a different application.

**Signature appearance looks wrong** -- Run `revenant setup` to reconfigure your signer identity. The signature fields (name, ID, date) come from the server profile configuration.

**Validator rejects the signed PDF** -- See [`../docs/ekeng/`](../docs/ekeng/) for EKENG validator requirements. Common issues: missing `/Info` dictionary in the incremental update, or modified PDF bytes after signing.

## Known limitations

- **SHA-1 only** — the server rejects SHA-256. This is a server-side limitation.
- **Non-standard CMS OIDs** — the server returns `sha1WithRSAEncryption` as digestAlgorithm (wrong per RFC 5652). See [`../docs/verification.md`](../docs/verification.md).
- **No timestamp (TSA)** — the WSDL defines timestamp options but the server ignores them.
