# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Revenant, please report it responsibly.

**Do not open a public issue.** Instead:
1. Use the [GitHub Security Advisory](https://github.com/lobotomoe/revenant/security/advisories/new) feature to report privately.
2. Or email **selfsurfer@gmail.com** if GitHub is inaccessible.

Please include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

## Response Timeline

- **Acknowledgment:** within 72 hours of report
- **Initial assessment:** within 1 week
- **Fix or mitigation:** depends on severity, but we aim for 30 days for critical issues

## Safe Harbor

We consider security research conducted in good faith to be authorized.
We will not pursue legal action against researchers who:
- Act in good faith to avoid privacy violations, data destruction, and service disruption
- Report vulnerabilities promptly and do not exploit them beyond what is necessary to demonstrate the issue
- Do not access or modify other users' data

## Scope

This project handles:
- User credentials (username/password) for CoSign SOAP API
- PDF documents and their cryptographic signatures
- TLS connections to signing servers
- Local credential storage (system keychain or config file with restricted permissions)

### Security controls

- **Credential storage:** System keychain via `keyring` (preferred), or `~/.revenant/config.json` with `0600` permissions (fallback with warning)
- **Credential lifetime:** In CLI mode, credentials are held in memory only for the duration of the process; each invocation starts fresh. In GUI mode, credentials are cached in memory for the session duration to avoid repeated prompts but are never written to disk unless the user explicitly saves them
- **Temporary files:** No temporary files are created during signing. PDF output is written atomically to the target path
- **Config file writes:** Atomic write (write to temp file, rename) with `0600` permissions to prevent partial writes or races
- **Network:** All connections use TLS. Legacy servers (TLSv1.0/RC4) are handled via `tlslite-ng` when required. Standard servers use system HTTPS via `urllib`
- **XML parsing:** SOAP responses are parsed with `defusedxml` to prevent XML bomb and billion laughs attacks
- **Logging:** Credentials are never logged. Only server URLs, status codes, and operation results appear in logs
- **Input validation:** PDF structure is validated before signing. ByteRange integrity is verified after signing. SOAP responses are validated for expected structure

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 0.2.x   | Yes       |
| 0.1.x   | No        |
