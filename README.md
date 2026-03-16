<p align="center">
  <img src="python/icons/revenant-readme.png" width="128" alt="Revenant">
</p>

# Revenant

[![CI](https://github.com/lobotomoe/revenant/actions/workflows/ci.yml/badge.svg)](https://github.com/lobotomoe/revenant/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/revenant.svg)](https://pypi.org/project/revenant/)
[![npm](https://img.shields.io/npm/v/revenant-sign.svg)](https://www.npmjs.com/package/revenant-sign)
[![Snap Store](https://snapcraft.io/revenant/badge.svg)](https://snapcraft.io/revenant)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![Node.js 18+](https://img.shields.io/badge/node-18%2B-green.svg)](https://nodejs.org/)
[![TypeScript: strict](https://img.shields.io/badge/TypeScript-strict-blue)](https://www.typescriptlang.org/)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/lobotomoe/revenant/badge)](https://scorecard.dev/viewer/?uri=github.com/lobotomoe/revenant)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/12008/badge)](https://www.bestpractices.dev/projects/12008)

Cross-platform clients for [DocuSign Signature Appliance (DSA)](https://www.docusign.com/products/hybrid-cloud-appliances) (formerly ARX CoSign) electronic signatures via the SOAP API (OASIS DSS standard).

Originally built for the Armenian Government's EKENG CoSign appliance, but works with any CoSign / DSA server that exposes the DSS SOAP endpoint.

```
+-------------------+
|  Python client    |----+
+-------------------+    |    SOAP/TLS         +-------------------+
                         +------------------->  |  CoSign appliance |
+-------------------+    |                      |  (any server)     |
|  TypeScript client|----+  <-----------------  +-------------------+
+-------------------+         Signed PDF
```

## Wait, isn't this thing dead?

Yes. DocuSign [officially retired](https://www.docusign.com/blog/developers/docusign-signature-appliance-to-be-retired-july-2023) the Signature Appliance product line on July 31, 2023. And yes, I built a cross-platform client for it in 2026. The appliance is discontinued, the docs are archived, the cipher suites are from a bygone era, and the server still happily runs on `TLSv1.0 / RC4-MD5` like it's 2011. What are you going to do about it?

The Armenian Government's EKENG CoSign appliance doesn't care about DocuSign's product roadmap -- it's on-prem, it works, and thousands of documents get signed through it every day. Somebody had to write a proper cross-platform client for it. Might as well be me.

## Install

### Desktop app

**macOS**
```bash
brew install lobotomoe/revenant/revenant
```

<a href="https://apps.apple.com/app/revenant-pdf-signer/id6759206299" target="_blank" rel="noopener noreferrer">
  <img src="https://tools.applemediaservices.com/api/badges/download-on-the-mac-app-store/black/en-us" width="200" alt="Download on the Mac App Store"/>
</a>

**Linux**
```bash
snap install revenant
```

[![Get it from the Snap Store](https://snapcraft.io/en/dark/install.svg)](https://snapcraft.io/revenant)

**Windows**
```powershell
winget install --source msstore 9NVH62M20DS3    # WinGet
scoop bucket add revenant https://github.com/lobotomoe/scoop-revenant
scoop install revenant                           # Scoop
```

<a href="https://apps.microsoft.com/detail/9NVH62M20DS3?referrer=appbadge&mode=full" target="_blank" rel="noopener noreferrer">
  <img src="https://get.microsoft.com/images/en-us%20dark.svg" width="200" alt="Get it from Microsoft Store"/>
</a>

Or download binaries from [GitHub Releases](https://github.com/lobotomoe/revenant/releases).

### Libraries

**Python** ([docs](python/README.md))
```bash
pipx install revenant    # recommended
pip install revenant     # or inside a venv
```

**TypeScript / Node.js** ([docs](typescript/README.md))
```bash
npm install revenant-sign
```

## Compatibility

Signed PDFs verified against third-party services that accept EKENG digital signatures:

- [x] [ekeng.am/sign_check](https://www.ekeng.am/en/sec_sub/sign_check) — EKENG signature validator
- [x] [e-request.am](https://e-request.am/) — e-request.am document upload
- [ ] [self-portal.taxservice.am](https://self-portal.taxservice.am) — Tax Service self-portal
- [ ] [file-online.taxservice.am](https://file-online.taxservice.am) — Tax Service online filing

## Documentation

Protocol, API, and server-specific docs live in [`docs/`](docs/README.md) and are shared between clients.

## References

- [DocuSign Signature Appliance API Guide v8.0 (PDF)](https://www.docusign.com/sites/default/files/Signature_Appliance_API_Guide_8.0.pdf)
- [DocuSign Signature Appliance Admin Guide v8.0 (PDF)](https://www.docusign.com/sites/default/files/Signature_Appliance_Admin_Guide_8.0.pdf)
- [OASIS DSS Standard](https://docs.oasis-open.org/dss/v1.0/oasis-dss-core-spec-v1.0-os.pdf)
- [EKENG CoSign page](https://www.ekeng.am/en/third_sub/cosign)

## Disclaimer

This is an **unofficial**, independently developed client. It is not affiliated with, endorsed by, or supported by EKENG, ARX, or DocuSign.

- This software is provided "as is" without warranty of any kind
- Electronic signatures carry legal significance — verify that your use case complies with applicable laws and your organization's policies
- You are responsible for safeguarding your CoSign credentials and for all signatures made using this tool
- This tool communicates with CoSign servers using the documented [OASIS DSS](https://docs.oasis-open.org/dss/v1.0/oasis-dss-core-spec-v1.0-os.pdf) SOAP protocol — the same public API described in the [official API Guide](https://www.docusign.com/sites/default/files/Signature_Appliance_API_Guide_8.0.pdf). No proprietary software is reverse-engineered or redistributed

## Privacy

This program does not collect, transmit, or share any data with the developer or third parties. It communicates only with the CoSign server you configure. See [Privacy Policy](docs/privacy-policy.md).

## License

Apache 2.0
