# revenant-sign

The `revenant` command-line client for ARX CoSign / DocuSign Signature Appliance
electronic signatures. It is a thin front-end over
[`revenant-sign-core`](https://crates.io/crates/revenant-sign-core) that mirrors the
Python and TypeScript [Revenant](https://github.com/lobotomoe/revenant) clients'
subcommands, flags, and output. A single config store and one shared transport
are threaded through the whole app; every command maps to a typed process exit
code.

## Install

```bash
cargo install revenant-sign
```

This installs the `revenant` binary.

## Commands

| Command | Purpose |
|---------|---------|
| `sign` | Sign one or more PDFs (embedded, or `--detached` `.p7s`). |
| `verify` | Verify a detached CMS against its PDF via `openssl cms -verify`. |
| `check` | Verify a PDF's embedded signature(s) offline, plus TSL chain validation. |
| `info` | List the certificates in a CMS `.p7s`. |
| `cert` | Show the signer certificate from the server, or `--pdf` from a document. |
| `setup` | Interactive wizard: choose a profile, ping, enter credentials, save. |
| `logout` / `reset` | Clear credentials + identity, or clear everything. |

Credentials resolve env (`REVENANT_USER` / `REVENANT_PASS`) > saved keychain >
interactive prompt (hidden); the endpoint resolves env (`REVENANT_URL`) > saved
config > built-in profile.

## Usage

```bash
revenant setup
revenant sign document.pdf
revenant check document.pdf
```

Licensed under [Apache-2.0](LICENSE).
