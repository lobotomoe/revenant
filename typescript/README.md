# revenant (TypeScript)

[![CI](https://github.com/lobotomoe/revenant/actions/workflows/ci.yml/badge.svg)](https://github.com/lobotomoe/revenant/actions/workflows/ci.yml)
[![TypeScript: strict](https://img.shields.io/badge/TypeScript-strict-blue)](https://www.typescriptlang.org/)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](../LICENSE)

Cross-platform TypeScript/Node.js client for ARX CoSign electronic signatures via SOAP API. Library + CLI.

Server-specific settings (URL, TLS, identity discovery) are managed through **server profiles** -- see [`src/config/profiles.ts`](src/config/profiles.ts). For SOAP API technical details, see [`../docs/soap-api.md`](../docs/soap-api.md).

## Install

```bash
npm install revenant-sign
# or
pnpm add revenant-sign
```

Requires Node.js >= 18.0.0.

## CLI quick start

```bash
# Interactive setup (server, credentials, signer identity)
npx revenant setup
npx revenant setup --profile ekeng

# Sign a PDF (embedded signature)
npx revenant sign document.pdf

# Sign multiple files
npx revenant sign *.pdf

# Detached CMS/PKCS#7 signature
npx revenant sign document.pdf --detached

# Check an embedded signature
npx revenant check signed.pdf

# Inspect a detached signature
npx revenant info document.pdf.p7s

# Verify with openssl (detached)
npx revenant verify document.pdf
```

### CLI options

```
revenant sign <files...>
  -o, --output <path>    Output file path (single file only)
  -d, --detached         Save detached .p7s instead of embedded PDF
  -p, --position <preset>  Signature position (default: bottom-right)
  --page <page>          Page for signature (default: last)
  --image <path>         Signature image (PNG or JPEG)
  --invisible            Create invisible signature
  --font <name>          Font (noto-sans, ghea-mariam, ghea-grapalat)
  --reason <text>        Signature reason string
  --dry-run              Preview without signing
```

## Library usage

```typescript
import {
  sign,
  signDetached,
  signPdfEmbedded,
  signPdfDetached,
  verifyEmbeddedSignature,
  AuthError,
  TLSError,
} from "revenant-sign";

// High-level API (uses saved config or profile)
const signedPdf = await sign(pdfBytes, "user", "pass", {
  profile: "ekeng",
});

// Detached CMS/PKCS#7 signature
const cmsDer = await signDetached(pdfBytes, "user", "pass", {
  profile: "ekeng",
});

// Low-level API with explicit transport
import { SoapSigningTransport } from "revenant-sign/network/soap-transport";

const transport = new SoapSigningTransport(
  "https://ca.gov.am:8080/SAPIWS/DSS.asmx",
);
const signed = await signPdfEmbedded(pdfBytes, transport, "user", "pass", 120, {
  page: "last",
  position: "bottom-right",
  name: "Signer Name",
  reason: "Approved",
});

// Verify an embedded signature
const result = await verifyEmbeddedSignature(signedPdf);
console.log(result.valid, result.details);
```

### Error handling

All functions throw typed errors from a hierarchy rooted at `RevenantError`:

```
RevenantError (base)
  AuthError           -- wrong credentials, account locked
  ServerError         -- server returned an error response
  TLSError            -- connection/TLS issues (.retryable flag)
  PDFError            -- invalid PDF structure, parse failures
  ConfigError         -- missing or malformed configuration
  CertificateError    -- certificate parsing/extraction errors
```

```typescript
import { AuthError, TLSError, ServerError, PDFError } from "revenant-sign";

try {
  await sign(pdfBytes, user, password, { profile: "ekeng" });
} catch (e) {
  if (e instanceof AuthError) {
    console.error("Wrong credentials or account locked");
  } else if (e instanceof TLSError && e.retryable) {
    console.error("Transient connection error, retry later");
  } else if (e instanceof ServerError) {
    console.error(`Server error: ${e.message}`);
  } else if (e instanceof PDFError) {
    console.error(`Invalid PDF: ${e.message}`);
  }
}
```

## Environment variables

| Variable           | Description                                             |
| ------------------ | ------------------------------------------------------- |
| `REVENANT_USER`    | CoSign username (overrides saved config)                 |
| `REVENANT_PASS`    | CoSign password (overrides saved config)                 |
| `REVENANT_URL`     | SOAP endpoint (overrides profile URL from setup)         |
| `REVENANT_TIMEOUT` | Request timeout in seconds (default: 120)                |
| `REVENANT_NAME`    | Signer display name (overrides config from setup)        |

## Credentials

Credentials are resolved in this order:

1. **Environment variables** `REVENANT_USER` / `REVENANT_PASS`
2. **System keychain** via `keytar` (if installed)
3. **Saved config** in `~/.revenant/config.json`
4. **Interactive prompt**

Install `keytar` as an optional peer dependency for secure credential storage:

```bash
npm install keytar
```

## Development

```bash
cd typescript/
pnpm install
pnpm test              # run unit tests
pnpm typecheck         # strict TypeScript check
pnpm build             # dual ESM + CJS via tsup
```

## Documentation

Protocol, API, and server-specific docs are shared between implementations and live in [`../docs/`](../docs/README.md).

## License

Apache 2.0
