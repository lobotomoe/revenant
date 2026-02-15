<p align="center">
  <img src="python/icons/revenant-readme.png" width="128" alt="Revenant">
</p>

# Revenant

[![CI](https://github.com/lobotomoe/revenant/actions/workflows/ci.yml/badge.svg)](https://github.com/lobotomoe/revenant/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/revenant.svg)](https://pypi.org/project/revenant/)
[![Snap Store](https://snapcraft.io/revenant/badge.svg)](https://snapcraft.io/revenant)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![pyright: strict](https://img.shields.io/badge/pyright-strict-blue)](https://github.com/microsoft/pyright)
[![coverage: 96%](https://img.shields.io/badge/coverage-96%25-brightgreen)](python/pyproject.toml)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://docs.astral.sh/ruff/)

Cross-platform clients for [DocuSign Signature Appliance (DSA)](https://www.docusign.com/products/hybrid-cloud-appliances) (formerly ARX CoSign) electronic signatures via the SOAP API (OASIS DSS standard).

Originally built for the Armenian Government's EKENG CoSign appliance, but works with any CoSign / DSA server that exposes the DSS SOAP endpoint.

```
+-------------------+         SOAP/TLS            +-------------------+
|  Client (Python)  | --------------------------> |  CoSign appliance |
|                   | <-------------------------- |  (any server)     |
+-------------------+      Signed PDF response    +-------------------+
```

## Wait, isn't this thing dead?

Yes. DocuSign [officially retired](https://www.docusign.com/blog/developers/docusign-signature-appliance-to-be-retired-july-2023) the Signature Appliance product line on July 31, 2023. And yes, I built a cross-platform client for it in 2026. The appliance is discontinued, the docs are archived, the cipher suites are from a bygone era, and the server still happily runs on `TLSv1.0 / RC4-MD5` like it's 2011. What are you going to do about it?

The Armenian Government's EKENG CoSign appliance doesn't care about DocuSign's product roadmap -- it's on-prem, it works, and thousands of documents get signed through it every day. Somebody had to write a proper cross-platform client for it. Might as well be me.

## Install

```bash
pip install revenant        # PyPI (all platforms)
snap install revenant       # Snap Store (Linux)
brew install lobotomoe/revenant/revenant  # Homebrew (macOS)
```

[![Get it from the Snap Store](https://snapcraft.io/en/dark/install.svg)](https://snapcraft.io/revenant)

Or download binaries from [GitHub Releases](https://github.com/lobotomoe/revenant/releases).

For detailed usage, see [`python/`](python/README.md).

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

## License

Apache 2.0
