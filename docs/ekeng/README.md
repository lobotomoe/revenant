# EKENG Appliance — Specifics

Everything specific to the Armenian Government's EKENG CoSign appliance
(`ca.gov.am:8080`). The rest of the documentation describes generic CoSign
SOAP behavior that applies to any appliance.

EKENG is configured as the `ekeng` built-in profile in the Python client (`python/src/revenant/config/profiles.py`).

## Server

| Parameter | Value |
|-----------|-------|
| Endpoint | `https://ca.gov.am:8080/SAPIWS/DSS.asmx` |
| TLS | TLSv1.0 / RC4-MD5 (self-signed cert, CN=CoSign, issuer=AR Ltd., 2006) |
| Server | Microsoft-IIS/5.1 (Windows XP), ASP.NET 2.0.50727 (.NET 2.0) |
| SAPI version | CoSign 5.2 (serial CSN00346, via `cosign-info` DssVerify) |
| Operations | `DssSign` (working), `DssVerify` (working — see below) |

### TLS caveat

The appliance uses **TLSv1.0 with RC4-MD5** — a cipher suite removed from
OpenSSL 3.x. Python's `ssl` module cannot connect directly. revenant uses
`tlslite-ng` (pure-Python TLS library with built-in RC4 support) for this
server. The transport layer auto-detects legacy TLS per host; the EKENG
profile pre-registers `ca.gov.am` as a legacy TLS host.

### Appliance reconnaissance (2026-01-31)

| Path | Status |
|------|--------|
| `/SAPIWS/DSS.asmx` | Active — DssSign, DssVerify |
| `/SAPIWS/SAPI.asmx` | 404 |
| `/SAPIWS/UserManagement.asmx` | 404 |
| `/SAPIWS/Admin.asmx` | 404 |
| `/SAPIWS/SignatureAPI.asmx` | 404 |
| Other ports (80, 443, 8443, 8081, 9443) | Closed or TLS error |

Only `DSS.asmx` is deployed.

### DssVerify

Functional on this appliance, but requires `<SignatureType>` in
`OptionalInputs` — without it the server returns `GeneralError` /
`Exception occured`.

**Authentication is not required** for DssVerify — requests with no
credentials, or even wrong credentials, succeed. The server verifies
the cryptographic signature, not the caller's identity.

Three SignatureType values tested for PDF verification (2026-02-11):

| SignatureType | Purpose per SAPI guide | EKENG result |
|---|---|---|
| `http://arx.com/SAPIWS/DSS/1.0/signature-field-verify` | PDF field verification | OK |
| `urn:ietf:rfc:3275` | XML signature verification | OK (works for PDF too) |
| `urn:ietf:rfc:3369` | Detached CMS buffer verification | OK (requires `SignatureObject`) |

revenant uses `signature-field-verify` as the default — it is the
semantically correct type for PDF field verification per the SAPI 8.0
Developer's Guide. The `urn:ietf:rfc:3275` also happens to work on this
appliance but is documented as the XML signature type.

Detached CMS verification (`urn:ietf:rfc:3369`) requires a
`SignatureObject` element containing the CMS/PKCS#7 signature bytes.
Earlier tests without `SignatureObject` returned `ResponderError`.

The response includes `ResultMajor: Success` and a `SAPIFieldsInfo` block.
All values are **XML attributes** (not child elements) — confirmed by raw
XML capture (2026-02-11):

```
SigFieldSettings Name="Signature1"
                 DependencyMode="Dependant"
                 SignatureType="Digital"
                 Invisible="true"
                 Flags="0"
SignedFieldInfo  SignerName="Aleksandr Kraiz 3105951040"
                 IsSigned="true"
                 SignatureTime="2026-02-11T16:08:32Z"
FieldStatus      SignatureStatus="0"
                 CertificateStatus="OK"
                 OSCertificateStatus="16777280"
```

`SignedFieldInfo` also contains `Certificate` (base64 X.509), `GraphicImage`
and `GraphicLogo` child elements (both empty/zero on this appliance).

Signature verification is also done client-side (ByteRange hash check, CMS structure validation, pikepdf readability).

### Multi-signature verification

DssVerify correctly handles PDFs with **stacked signatures** (multiple
incremental updates). The response contains one `SignedFieldInfo` element
per signature, each with its own signer name, timestamp, and certificate
status. All `FieldStatus` elements report independently.

### Unsigned PDF quirk

Verifying an unsigned PDF with `SignatureType=urn:ietf:rfc:3275` returns
`Success` / `onAllDocuments` — the server considers "all zero signatures
are valid." This is a server-side quirk, not a bug in revenant.

### PDF size limits (2026-02-11)

Tested with padded PDFs via `urn:ietf:rfc:3369` (buffer sign):

| PDF size | SOAP body | Attempts | Success rate |
|---|---|---|---|
| 0.1 - 30 MB | 0.1 - 40 MB | many | 100% |
| 35 MB | 46.7 MB | 5 | 5/5 (100%) |
| 36 MB | 48 MB | 3 | 2/3 (~67%) |
| 37 MB | 49.3 MB | 3 | 1/3 (~33%) |
| 38 MB | 50.7 MB | 3 | 2/3 (~67%) |
| 40 MB | 53.3 MB | 5 | 3/5 (60%) |

Failures are HTTP 500 Internal Server Error (ASP.NET crash, likely
`OutOfMemoryException`). Non-deterministic — depends on server memory
state at the time.

`PDF_WARN_SIZE` is set to **35 MB** based on this data.

### ReturnPDFTailOnly (2026-02-11)

The SAPI `ReturnPDFTailOnly` flag modifies the response for
field-based signing operations. When `true`, the server returns only
the incremental PDF revision (to be appended) instead of the full
signed document.

Tested on this appliance:

| SignatureType | ReturnPDFTailOnly | Response location | Works? |
|---|---|---|---|
| `signature-field-create-sign` | false | `DocumentWithSignature` (5383 B full PDF) | OK |
| `signature-field-create-sign` | true | `SignatureObject` (5080 B tail) | OK |
| `urn:ietf:rfc:3369` (buffer sign) | true | Flag ignored, full doc in `DocumentWithSignature` | N/A |
| `signature-field-sign` | true | Error: `Failed to enum signature fields` | Error |

The tail is a valid incremental PDF revision starting with new objects
and ending with a new xref table + `%%EOF`. It includes `/Prev`
pointing to the original `startxref` offset.

Not used in the current implementation — revenant uses hash-based
signing (`urn:ietf:rfc:3369` + `DocumentHash`) which only sends the
hash to the server and constructs the PDF incremental revision locally.
ReturnPDFTailOnly is irrelevant for this approach.

### AppearanceMask (2026-02-11)

Tested with `signature-field-create-sign`. By default the server creates
invisible fields (`/Rect[0 0 0 0]`, 5383 B). Setting `Invisible="false"`
produces a **visible** field with `/Rect[10 10 190 70]` and a full `/AP`
appearance stream (21500 B). The WSDL `Visible="true"` attribute is
**ignored** — only `Invisible="false"` controls visibility.

With `Invisible="false"`, `AppearanceMask` controls the content:

| Mask bits | Size | Content |
|-----------|------|---------|
| Text only (0x02, 0x08, 0x0A, 0x0E, 0x2E) | ~7.8 KB | Signer name, time, reason |
| With graphic (0x00 default, 0x0F, 0x4F, 0x6F) | ~21.5 KB | Includes handwritten signature image |

The **graphic signature image is stored server-side** in the user's EKENG
profile — no `GraphicImageToSet` is needed. The server inserts it
automatically when the graphic bit (0x01) is set or when mask is 0x00
(default includes graphic).

With invisible fields (default), all mask values produce byte-identical
output since there's no appearance to render.

Not relevant for revenant — we control appearance locally in the PDF builder.

### ConfigurationValues (2026-02-11)

`ConfigurationValues` query (with `ConfID` elements for `AppearanceMask`,
`Reason`, `GMTOffset`, `SignerLabel`, `DateLabel`) is **accepted but ignored**.
The server returns `Success` and signs normally without including any
configuration data in the response.

### Complete SAPI operation inventory (2026-02-11)

Exhaustive test of all operations from the SAPI 8.0 Developer's Guide.

#### DssSign operations (with auth + PDF)

| Operation | Works? | Notes |
|---|---|---|
| `urn:ietf:rfc:3369` | OK | Buffer sign, detached CMS. Used by revenant |
| `urn:ietf:rfc:3275` | OK | XMLDSig mode, returns full signed PDF |
| `signature-field-create-sign` | OK | Creates field + signs, returns full PDF |
| `signature-field-sign` | OK | Signs a pre-existing empty field (fails if no field exists) |
| `signature-field-create` | OK | Creates empty unsigned field |
| `signature-field-clear` | OK | Clears signature from a signed field (returns unsigned PDF) |
| `signature-field-remove` | OK | Removes unsigned/cleared fields. Fails on signed fields (error 90030103) |
| `enum-certificates` | OK | Returns user's X.509 cert. No PDF needed |
| `enum-graphic-images` | OK | Returns graphic signature images. No PDF needed |
| `enum-field-locators` | Error | "not suported by this profile" |
| `set-graphic-image` | Error | "Exception occured" (all formats: PNG, BMP) |
| `urn:ietf:rfc:2437:RSASSA-PKCS1-v1_5` | Error | "not suported by this profile" |
| `time-get` | Error | "SignatureType is missing or not supported" |
| `cosign-info` | Error | "not suported by this profile" |
| `graphic-image-get` | Error | "not suported by this profile" |
| `user-certificate-get` | Error | "not suported by this profile" |
| `user-info` | Error | "not suported by this profile" |

#### DssSign operations (no auth)

| Operation | Works? | Notes |
|---|---|---|
| `signature-field-create` | OK | No auth needed for field creation |
| `enum-certificates` | Error | Auth required |
| `enum-graphic-images` | Error | Auth required |

#### DssVerify operations (no auth needed)

| Operation | Works? | Notes |
|---|---|---|
| `signature-field-verify` | OK | Returns `SAPIFieldsInfo` with per-field status |
| `urn:ietf:rfc:3275` | OK | Works for PDF verification too |
| `urn:ietf:rfc:3369` | OK | Detached CMS verification. Requires `SignatureObject` with CMS bytes |
| `urn:ietf:rfc:2437:RSASSA-PKCS1-v1_5` | Error | "not suported by this profile" |
| `ca-info-get` | OK | Returns CA cert + CRL (~147 KB) |
| `time-get` | OK | Returns `SAPITime` |
| `cosign-info` | OK | Returns `CoSignInfo` (see below) |

#### Operation details

**`cosign-info`** response (via DssVerify):

```
CoSignInfo SerialNumber="CSN00346"
           Major="5" Minor="2"
           InstallStatus="400"
           DirectoryKind="3"
           SubDirectoryKind="0"
           AuthMode="4" AuthMode2="0"
           ClusterID="1"
```

**`enum-certificates`** (via DssSign, auth required, no PDF needed):

Returns `<AvailableCertificate>` elements containing the user's full
X.509 certificate in base64. Useful for extracting signer info without
signing a document.

**`enum-graphic-images`** (via DssSign, auth required, no PDF needed):

Returns `<AvailableGraphicSignature>` elements with metadata and image data.
On this account: one JPEG image named "My hand", 324x246 px, 13369 bytes.
This is the same image the server inserts into visible signature fields.

**`ca-info-get`** (via DssVerify, no auth needed):

Returns the full CA certificate and Certificate Revocation List (CRL).
Response is ~147 KB. Includes AIA (`http://www.gov.am/CAStaff/GovRootCA.crt`)
and CDP (`http://www.gov.am/CAStaff/GovRootCA.crl`) URLs.

#### What doesn't work

- **Profile management operations** (`graphic-image-get`, `user-certificate-get`,
  `user-info`, `set-graphic-image`, `enum-field-locators`) are not exposed on
  this appliance profile. Error: "not suported by this profile".
- **PKCS#1 sign/verify** (`urn:ietf:rfc:2437:RSASSA-PKCS1-v1_5`) — not
  supported by this profile.
- **set-graphic-image** — accepts the request structure but returns
  "Exception occured" for all tested formats (1x1 PNG, 10x10 PNG, 1x1 BMP).
- **signature-field-remove on signed fields** — error 90030103. Must clear
  the field first with `signature-field-clear`, then remove.

The graphic signature is only accessible indirectly via `enum-graphic-images`
(metadata + image data) or via `signature-field-create-sign` with
`Invisible="false"` (embedded in the visible signature appearance).

#### Other endpoints

**SPML user management** (`/SAPIWS/spml.asmx`): WSDL is served (12 operations:
addRequest, deleteRequest, listTargets, lookupRequest, modifyRequest,
searchRequest, setPassword, etc.), but all calls return HTTP 500. Likely
requires an operator/admin account — the WSDL defines `OperatorLogonInfo`
with `UserID`/`Password` elements, not regular user credentials.

**REST/JSON API** (port 8081): Documented in SAPI 8.0 guide as an alternative
to SOAP. Port 8081 is not exposed on this appliance.

## PKI chain

```
Subject:  O=Staff of Government of RA, CN=<signer name> <signer id>
Issuer:   C=AM, O=Staff of Government of RA, CN=Staff of Government of RA Root CA
Validity: 2026-01-29 to 2029-01-29
Key:      RSA 2048-bit, sha1WithRSAEncryption
Signature: sha1WithRSAEncryption
Serial:   77:bc:3a:d5:ff:06:48:08:99:72:17:64:7e:7e:93:20
EKU:      TLS Server/Client Auth, Code Signing, Email Protection, Time Stamping
CRL:      http://www.gov.am/CAStaff/GovRootCA.crl
CA cert:  http://www.gov.am/CAStaff/GovRootCA.crt
```

The signer certificate is embedded in every CMS signature. The CA root
certificate is publicly available and the chain validates with
`openssl verify`.

## e-keng / e-request validator

The Armenian Government's e-keng and e-request portals issue PDF documents
and verify signed uploads. Their validator checks:

1. **Original bytes preserved** — the uploaded signed file must contain the
   original document as an exact byte-for-byte prefix (likely by comparing a
   hash stored in their database against bytes up to the first `%%EOF`)
2. **Trailer entries carried forward** — `/Info` (containing document
   identifiers in `/Author`) and `/ID` must be present in the incremental
   update trailer
3. **Valid client signature** — a structurally correct PDF signature

Missing `/Info` or `/ID` causes rejection with "Подлинность файла не
подтверждена" (file authenticity not confirmed).

### Account lockout

EKENG locks accounts after **5 consecutive failed authentication attempts**.
The CLI and GUI warn about this on auth failure.

### Certificate filtering

Credential PDFs from EKENG contain both the user's personal signature and
institutional CA signatures. The `revenant setup` command filters out entries
matching `ca_cert_markers` from the EKENG profile to auto-select the
personal certificate.
