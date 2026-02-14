# Privacy Policy

**Revenant** is an open-source application developed by Aleksandr Kraiz.

*Last updated: February 14, 2026*

## Overview

Revenant is a client for signing PDF documents via the ARX CoSign SOAP API. The application operates locally on your device and communicates only with the CoSign server that you configure. Revenant does not collect, transmit, or share any personal data with the developer or any third party.

## Data Processing

### What Revenant processes

All data processing happens locally on your device:

- **PDF documents** you select for signing are read from disk, and a SHA-1 hash is computed locally. The hash (not the document) is sent to your configured CoSign server for signing. The signed document is saved to a location you choose.
- **Signer identity** (name, organization, email) is extracted from your signing certificate during setup and stored locally for signature appearance.

### What Revenant sends over the network

Revenant communicates exclusively with the CoSign server URL that you configure during setup. No other network connections are made. The following data is sent to your server:

- Your CoSign credentials (username and password) for authentication
- Document hashes (SHA-1) for signing
- SOAP protocol messages required by the signing process

All communication uses HTTPS. Revenant refuses to connect over unencrypted HTTP.

No data is sent to the developer, to analytics services, to advertising networks, or to any server other than the one you configure.

### What Revenant stores on your device

Revenant stores configuration data in `~/.revenant/config.json`:

- CoSign server URL and connection settings
- Your username
- Signer identity (name, organization, email) for signature appearance
- Your password (see Credential Storage below)

No other files are created or modified outside of the documents you explicitly sign.

## Credential Storage

Revenant offers two methods for storing your CoSign password:

1. **System keychain** (recommended) -- when the `keyring` package is installed, your password is stored in your operating system's secure credential store (macOS Keychain, Windows Credential Manager, or Linux Secret Service). The developer has no access to these credentials.

2. **Local configuration file** (fallback) -- if `keyring` is not available, your password is stored in `~/.revenant/config.json` with restricted file permissions (`0600`). Revenant warns you when this fallback is used.

You can clear stored credentials at any time by running `revenant logout` or by deleting the configuration file.

## Data Collection

Revenant does **not** collect any data. Specifically:

- No usage analytics or telemetry
- No crash reports
- No device identifiers
- No IP address logging
- No cookies or tracking technologies
- No advertising identifiers
- No location data
- No contact information beyond what you enter for signature appearance

The application contains no analytics SDKs, no tracking code, and no mechanism for transmitting data to the developer.

## Third-Party Services

Revenant does not integrate with any third-party services. The only network communication is with the CoSign server that you configure and control.

The application depends on open-source libraries for its functionality (listed in the project repository). These libraries operate locally and do not make independent network connections.

## Children's Privacy

Revenant is a professional document-signing tool. It is not directed at children under 13 and does not knowingly process data from children.

## Your Rights

Since Revenant does not collect or store any data on remote servers, there is no personal data held by the developer to access, modify, or delete. All data remains on your device under your full control.

To remove all locally stored data, delete the `~/.revenant/` directory or run `revenant reset`.

## Open Source

Revenant is open-source software licensed under the Apache License 2.0. The complete source code is available at [github.com/lobotomoe/revenant](https://github.com/lobotomoe/revenant), allowing independent verification of all privacy claims made in this policy.

## Changes to This Policy

If this privacy policy is updated, the changes will be published in the project repository. The "Last updated" date at the top of this document will be revised accordingly.

## Contact

If you have questions about this privacy policy, you can reach the developer through the project's GitHub repository:

- GitHub: [github.com/lobotomoe/revenant](https://github.com/lobotomoe/revenant)
- Issues: [github.com/lobotomoe/revenant/issues](https://github.com/lobotomoe/revenant/issues)
