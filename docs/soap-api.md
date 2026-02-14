# SOAP API Reference

Technical details of the CoSign SOAP API (OASIS DSS standard).

Server endpoints are configured through profiles (see `python/src/revenant/config/profiles.py`).
The WSDL is saved in [`wsdl_dss.xml`](wsdl_dss.xml) for reference.

## Discovery summary

| Check | Result |
|-------|--------|
| WSDL available | Yes — 40KB, fully parseable |
| Operations | `DssSign`, `DssVerify` |
| Auth model | `ClaimedIdentity` with `LogonPassword` (username + password) |
| Document input | Base64-encoded PDF in `InputDocuments` |

## Operations

| Operation | Description |
|-----------|-------------|
| `DssSign` | Sign a document (requires authentication) |
| `DssVerify` | Verify signatures in a document (no auth required, `SignatureType` in `OptionalInputs` mandatory) |

### DssVerify

Verifies signatures in a PDF. **Authentication is not required** —
verification is a public operation.

Requires `<SignatureType>` in `OptionalInputs`. Supported modes:

- **Field verify** (`signature-field-verify`): recommended for PDFs with
  embedded signature fields. Returns `SAPIFieldsInfo` with signer name,
  timestamp, certificate status, and signature status per field.
- **XMLDSig** (`urn:ietf:rfc:3275`): also works for embedded PDF signatures
  (returns identical results to field verify on tested servers).
- **Detached CMS** (`urn:ietf:rfc:3369`): requires document in
  `InputDocuments` + signature in `SignatureObject`. Fails if
  `SignatureObject` is absent.

On success, returns `ResultMajor: Success` and `SAPIFieldsInfo` with signer
certificate, signer name, and signing timestamp.

Omitting `SignatureType` causes `GeneralError`.

## Authentication

Authentication uses the OASIS DSS `ClaimedIdentity` element. The correct XML structure (determined empirically — namespace placement matters):

```xml
<ClaimedIdentity>
  <Name>your_username</Name>
  <SupportingInfo>
    <LogonPassword xmlns="http://arx.com/SAPIWS/DSS/1.0">your_password</LogonPassword>
  </SupportingInfo>
</ClaimedIdentity>
```

Key namespace details discovered during probing:
- `Name` must **not** have the SAML namespace (`urn:oasis:names:tc:SAML:1.0:assertion`) — despite the WSDL declaring `NameIdentifierType`
- `LogonPassword` must be in `http://arx.com/SAPIWS/DSS/1.0` namespace, applied at the element level
- `SupportingInfo` must be in the default (core DSS) namespace

## Signature types

### Standard OASIS DSS types

| URI | Status | Output |
|-----|--------|--------|
| `urn:ietf:rfc:3369` | Working | Detached CMS/PKCS#7 signature (~1.8 KB) |
| `urn:ietf:rfc:3275` | Working | Full PDF with embedded XML signature (~5.4 KB) |
| (none / omitted) | Rejected | `"missing or not suported"` |
| `urn:ietf:rfc:2315` | Rejected | `NotSupported` |
| `urn:oasis:names:tc:dss:1.0:core:schema:CAdES-BES` | Rejected | `NotSupported` |
| `urn:oasis:names:tc:dss:1.0:core:schema:XAdES-BES` | Rejected | `NotSupported` |
| `urn:oasis:names:tc:dss:1.0:core:schema:PAdES-Basic` | Rejected | `NotSupported` |
| `urn:ietf:rfc:2437:RSASSA-PKCS1-v1_5` (PKCS#1) | Rejected | `NotSupported` (per-profile) |
| `urn:ietf:rfc:2437` (RAW/PKCS#1) | Rejected | `NotSupported` |
| `http://www.w3.org/2000/09/xmldsig#rsa-sha1` | Rejected | `NotSupported` |
| `urn:ietf:rfc:3161` (Timestamp) | Rejected | `NotSupported` |
| (empty string) | Rejected | `NotSupported` |

### SAPI operations (via DssSign)

These are proprietary SAPI URIs (`http://arx.com/SAPIWS/DSS/1.0/...`):

| URI suffix | Operation | Auth | PDF required | Notes |
|------------|-----------|------|--------------|-------|
| `signature-field-create-sign` | Create field + sign | Yes | Yes | Returns full PDF or tail (`ReturnPDFTailOnly`) |
| `signature-field-create` | Create empty field | No | Yes | Modifies PDF without signing |
| `signature-field-sign` | Sign existing field | Yes | Yes | Requires `FieldName`; fails if field doesn't exist |
| `signature-field-clear` | Clear a signed field | Yes | Yes | Removes signature from field, returns modified PDF |
| `signature-field-remove` | Remove a field | Yes | Yes | Field must be unsigned or cleared first |
| `enum-certificates` | List user certs | Yes | No | Returns `AvailableCertificate` elements (DER X.509) |
| `enum-graphic-images` | List graphic images | Yes | No | Returns `SAPIGraphicImageInfo` with image data |
| `set-graphic-image` | Upload graphic image | Yes | No | Upload a handwritten signature image |
| `enum-field-locators` | List field locators | Yes | Yes | Server-dependent; not supported on all profiles |

### SAPI operations (via DssVerify)

| URI suffix | Operation | Auth | Notes |
|------------|-----------|------|-------|
| `signature-field-verify` | Verify all fields | No | Returns `SAPIFieldsInfo` with per-field status |
| `ca-info-get` | Get CA certs/CRL | No | Returns root certificate and revocation list |
| `time-get` | Get server time | No | Returns `SAPITime` element |
| `cosign-info` | Get appliance info | No | Returns `CoSignInfo` with version, serial, auth mode |

**XMLDSig note:** Despite the URI `urn:ietf:rfc:3275` suggesting a raw XML
digital signature, the server returns a complete PDF document with the
signature embedded inside it (starts with `%PDF-1.0`). This is not a raw
`<Signature>` XML element.

### Server-side embedded signing (XMLDSig)

When using `urn:ietf:rfc:3275`, the server performs embedded PDF signing
using the same approach as revenant's client-side workflow:

| Aspect | Server (XMLDSig) | revenant (client-side) |
|--------|-----------------|------------------------|
| Original bytes preserved | Yes (byte-for-byte prefix) | Yes |
| Incremental update | Yes (after `%%EOF`) | Yes |
| `/Filter` | `/Adobe.PPKMS` | `/Adobe.PPKLite` |
| `/SubFilter` | `/adbe.pkcs7.detached` | `/adbe.pkcs7.detached` |
| Signature format | CMS/PKCS#7 | CMS/PKCS#7 |
| AcroForm `/SigFlags` | 3 | 3 |
| Invisible by default | Yes (`/Rect[0 0 0 0]`) | Configurable |

The server also adds a proprietary `/AR.SigFieldData` attribute with
appearance settings (date format, labels) and uses `/Filter /Adobe.PPKMS`
instead of the more common `/Adobe.PPKLite`.

Client-side embedded signing is preferred because it gives control over
signature appearance, field placement, and reserved space sizing.

## Supported file formats

Only PDF is accepted. Other MIME types return `"Bad Mime type"`:

| Format | MIME type | Result |
|--------|-----------|--------|
| PDF | `application/pdf` | Accepted |
| Plain text | `text/plain` | Rejected (`Bad Mime type`) |
| XML | `application/xml` | Rejected (`Bad Mime type`) |
| Binary | `application/octet-stream` | Rejected (`Bad Mime type`) |
| Image | `image/png` | Rejected (`Bad Mime type`) |
| No MimeType attribute | (omitted) | Rejected (`Bad Mime type`) |

The `MimeType` attribute on `Base64Data` is required and must be
`application/pdf`.

## Embedded vs detached signatures

With `urn:ietf:rfc:3369` (buffer sign), the server returns a **detached
CMS/PKCS#7 signature** only. `SAPISigFieldSettings`, `ReturnPDFTailOnly`,
and `GraphicImageToSet` are accepted but ignored in this mode.

With `signature-field-create-sign`, the server returns a **full signed PDF**
(or just the incremental tail if `ReturnPDFTailOnly=true`).
`SAPISigFieldSettings` placement values are honored in this mode.

The server also **supports `DocumentHash` input** (SHA-1 only) — this enables client-side embedded PDF signatures via the hash-then-sign workflow:

1. Client prepares PDF with empty signature field and ByteRange
2. Client computes SHA-1 of the ByteRange
3. Client sends hash via `DocumentHash` -> server returns CMS
4. Client inserts CMS into the reserved space

See [embedded-signing.md](embedded-signing.md) for implementation details.

### Hash algorithm support

Only SHA-1 is accepted for `DocumentHash` signing:

| Algorithm URI | Result |
|---------------|--------|
| `http://www.w3.org/2000/09/xmldsig#sha1` | Accepted |
| (omitted — no `DigestMethod` element) | Accepted (defaults to SHA-1) |
| `http://www.w3.org/2001/04/xmlenc#sha256` | Rejected (`Unsupported hash algorithm`) |
| `http://www.w3.org/2001/04/xmldsig-more#sha256` | Rejected |
| `http://www.w3.org/2001/04/xmldsig-more#sha384` | Rejected |
| `http://www.w3.org/2001/04/xmldsig-more#sha512` | Rejected |
| `http://www.w3.org/2001/04/xmldsig-more#md5` | Rejected |
| `http://www.w3.org/2001/04/xmlenc#ripemd160` | Rejected |

**Quirks:**
- The `DigestMethod` element can be omitted entirely — the server defaults
  to SHA-1 and signs whatever bytes are provided.
- The server does **not validate digest length** — a 32-byte value (wrong
  for SHA-1's 20 bytes) is accepted without error. The resulting CMS
  signature will be invalid but the server does not reject it.

## Determinism

Signing the same document twice produces **different CMS signatures** of the
same size (~1867 bytes). The CMS contains a `signingTime` attribute (UTC
timestamp) which changes between invocations, making each signature unique.

## Signature stacking

The server supports **multiple signatures** on a single PDF. Signing an
already-signed PDF (XMLDSig mode) produces a new incremental update appended
after the previous one. The original bytes are preserved as a byte-for-byte
prefix through all signing rounds:

| Step | Size |
|------|------|
| Original PDF | ~295 bytes |
| 1x signed | ~5,371 bytes |
| 2x signed | ~10,379 bytes |

DssVerify correctly reports **all signatures** in a stacked PDF — each
`SignedFieldInfo` element in the response corresponds to one signature,
with its own signer name, timestamp, and certificate status.

## Verify unsigned PDF

Verifying an unsigned PDF with `SignatureType=urn:ietf:rfc:3275` returns
`Success` with `onAllDocuments` — the server reports success even with
zero signatures. This is a quirk: "all zero signatures are valid."

With `SignatureType=urn:ietf:rfc:3369` and no `SignatureObject`, the
server returns `GeneralError` / `Exception occured`.

## Encrypted / password-protected PDFs

| Mode | Result |
|------|--------|
| CMS (detached) | Accepted — server signs blindly without parsing |
| XMLDSig (embedded) | Rejected: `Failed create and sign err 90034002` |
| XMLDSig + `<PDFPassword>` | Rejected: same error (password not used) |

The server cannot embed signatures into encrypted PDFs because it needs
to parse the PDF structure for incremental updates. Detached CMS works
because the server just signs the raw bytes without parsing.

## Document size limits

Maximum accepted PDF size: **35 MB** (reliable, 5/5 stable) / **36+ MB**
(flaky, ~50-67% failure rate). Above ~40 MB the server returns HTTP 500
(`OutOfMemoryException`) or drops the connection (`Broken pipe`).

The limit is on **decoded PDF size, not SOAP request size** -- a 60 MB SOAP
envelope with a tiny PDF succeeds, while a 53 MB envelope containing a 40 MB
PDF fails. The server decodes the Base64 and processes the PDF; the failure
is in PDF handling, not HTTP body parsing.

CMS signature size is constant (~1867 bytes) regardless of document size:

| Document size | CMS sign | Time |
|---------------|----------|------|
| 10 KB | OK | ~0.3s |
| 100 KB | OK | ~0.2s |
| 1 MB | OK | ~0.5s |
| 5 MB | OK | ~1.8s |
| 10 MB | OK | ~33s |
| 20 MB | OK | ~6s |
| 30 MB | OK | ~19s |
| 40 MB | OK | ~87s |
| 42 MB | FAIL | Broken pipe |
| 50 MB | FAIL | HTTP 500 |

Timing varies significantly due to network conditions and `tlslite-ng`
pure-Python TLS overhead (the server uses TLSv1.0 / RC4-MD5).

### Timing breakdown (upload vs server processing)

Instrumented timing with separate TCP connect, TLS handshake, upload, and
server processing phases. Upload goes through `tlslite-ng` pure-Python TLS:

| PDF size | SOAP size | Upload | Server sign | Total |
|----------|-----------|--------|-------------|-------|
| 100 KB | 134 KB | 0.02s | 0.17s | 0.2s |
| 1 MB | 1.3 MB | 0.24s | 0.21s | 0.5s |
| 5 MB | 6.7 MB | 1.21s | 0.38s | 1.6s |
| 10 MB | 13.3 MB | 2.31s | 0.79s | 3.1s |
| 20 MB | 26.7 MB | 4.47s | 1.27s | 5.8s |
| 30 MB | 40.0 MB | 6.70s | 20.34s | 27.1s |
| 40 MB | 53.3 MB | 9.76s | 38.08s | 48.2s (FAIL) |

- **TCP + TLS handshake**: ~50ms (stable)
- **Upload speed**: ~5.5-6.0 MB/s (limited by pure-Python TLS, not network)
- **Server signing up to 20 MB**: scales linearly ~0.06s/MB
- **Server signing 30+ MB**: non-linear spike (20s for 30 MB, 38s for 40 MB) --
  likely memory pressure on the IIS 5.1 / ASP.NET 2.0 server
- **Download**: ~0ms (CMS response is always ~3 KB)
- **Cold start**: first request after idle may take 5+ seconds (ASP.NET
  AppPool wake-up), subsequent requests are fast

For typical documents (<5 MB), upload through `tlslite-ng` takes ~1 second
and server signing takes <0.5 second. The bottleneck is the pure-Python
TLS encryption, not network bandwidth or server processing. Practical
comfort limit is ~20 MB (6s total); 30+ MB hits server-side degradation.
Hard limit is 35 MB (reliable); 36+ MB fails intermittently.

## CMS signature structure

The CMS/PKCS#7 signature contains:

| Field | Value |
|-------|-------|
| Content type | `pkcs7-signedData` (1.2.840.113549.1.7.2) |
| Version | 1 |
| Digest algorithm | `sha1WithRSAEncryption` |
| Signed attributes | `signingTime` (UTC), `messageDigest` |
| Certificate | Signer's X.509 cert (RSA 2048-bit) embedded |
| eContent | Absent (detached signature) |

The `signingTime` attribute in each CMS is what makes repeated signatures
on the same document produce different output.

## Supported features (from WSDL)

- **Signature field placement**: page, X, Y, width, height (honored with `signature-field-create-sign`; ignored with `urn:ietf:rfc:3369` buffer sign)
- **Signature types**: Digital, EHash
- **Graphic signatures**: BMP, PDF-embedded images
- **Configuration options**: reason, timestamps, OCSP, CRL checks, PDF passwords
- **Signature appearance**: custom labels, date/time format, logos

## SAPISigFieldSettings

Behavior depends on the `SignatureType`:

- **`urn:ietf:rfc:3369`** (buffer sign): all settings are **accepted but
  ignored**. The server returns a detached CMS; it does not modify the PDF.
- **`signature-field-create-sign`**: placement settings (`Page`, `X`, `Y`,
  `Width`, `Height`) are **honored**. By default the server creates an
  invisible field (`/Rect[0 0 0 0]`). Set `Invisible="false"` to get a
  visible field with an appearance stream (`/AP`). Note: the WSDL
  `Visible="true"` attribute is ignored — only `Invisible="false"` works.

Settings tested with `urn:ietf:rfc:3369` (all ignored):

| Setting | Tested | Effect |
|---------|--------|--------|
| `Page`, `X`, `Y`, `Width`, `Height` | Yes | Ignored |
| `Visible="true"`, `AppearanceMask` | Yes | Ignored |
| `FieldName` | Yes | Ignored |
| `<Reason>` | Yes | Ignored |
| Page number beyond document (e.g. page 2 of 1-page PDF) | Yes | Ignored (no error) |

## Edge cases

| Input | Result |
|-------|--------|
| Empty `Base64Data` | Empty response (no `Result` element) |
| Empty `InputDocuments` | `GeneralError` / `Exception occured` |
| No credentials | `InsufficientInformation` / `No password` |
| `SignatureType` omitted from `DssSign` | `NotSupported` / `missing or not suported` |
| `EstimateSignatureSize` flag | Ignored (server signs normally) |
| `ReturnPDFTailOnly` flag | Works with `signature-field-create-sign` (returns tail only); ignored with `urn:ietf:rfc:3369` |
| `ConfigurationValues` query | Ignored (server signs normally) |
| Unsigned PDF + DssVerify (XMLDSig) | Success (zero signatures = all valid) |
| Encrypted PDF + CMS sign | Accepted (server signs blindly) |
| Encrypted PDF + XMLDSig sign | Rejected (`err 90034002`) |

## HTTP behavior

| Request | Result |
|---------|--------|
| `GET /DSS.asmx` | HTML service page with WSDL link |
| `POST` without `SOAPAction` header | Routed by XML body content (still works) |
| `POST` with wrong `SOAPAction` | HTTP 500 |

## Other endpoints

### SPML user management (`/SAPIWS/spml.asmx`)

The SAPI guide documents an SPML 2.0 endpoint for user management (add,
delete, lookup, modify, search, setPassword, etc.). The WSDL is served
but the endpoint requires operator/admin credentials — regular user accounts
cannot call it. Not used by revenant.

### REST/JSON API (port 8081)

The SAPI guide also documents a REST API at `https://<host>:8081/sapiws/`
with endpoints for signing, verification, certificate management, and user
administration. This port is typically not exposed on production appliances.
Not used by revenant.

## Identity discovery

To obtain the signer's certificate info (CN, email, organization) during
setup, revenant uses `enum-certificates` (preferred) with dummy-hash signing
as a fallback:

1. **enum-certificates** — sends a DssSign request with
   `SignatureType=enum-certificates`. The server returns the user's X.509
   certificate directly, without signing anything. Auth required.
2. **Dummy-hash fallback** — if enum-certificates is not supported, signs a
   20-byte zero hash via `DocumentHash` and extracts the signer certificate
   from the CMS response.

## Appliance-specific details

For EKENG-specific information (TLS, PKI chain, DssVerify status, recon),
see [ekeng](ekeng/).
