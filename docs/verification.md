# Post-Sign Verification

How we verify that embedded PDF signatures are correctly constructed.

## Verification steps

After inserting the CMS into the PDF, the tool automatically verifies the result:

1. **Structure check** — re-reads the PDF, finds the last `/ByteRange`, extracts chunk1 + chunk2 (the signed data) and the CMS hex from `/Contents`.
2. **Signed-digest check** — reads the digest algorithm and mandatory `messageDigest` signed attribute from CMS, hashes the ByteRange data, and compares the two. The SHA-1 value originally sent to CoSign is an additional post-sign check when available; it never replaces the signed CMS digest.
3. **Signer-signature check** — verifies the RSA PKCS#1 v1.5 signature over the DER-encoded signed attributes with the certificate identified by `SignerInfo.sid`. Missing, ambiguous, malformed, or unsupported values fail closed.
4. **Signer and trust check** — extracts the signer identity and, when configured, starts chain validation from the same `SignerInfo.sid` certificate. CMS certificate order is never used to identify the signer.
5. **PDF readability** — opens the final PDF with pikepdf (Python) or pdf-lib (TypeScript) to report structural problems.

If a core structure, signed-digest, or signer-signature check fails, a newly signed PDF is **not saved** and an error is raised. Trust-chain status remains a separate result because a cryptographically authentic signature may use a certificate outside the configured TSL.

## Why not `openssl cms -verify`?

CoSign produces non-standard CMS for **all** `DssSign` SOAP operations — DocumentHash, Document (real PDF), and Document (raw data) all return identical CMS structure. Specifically:

| Field | Standard value | CoSign value |
|---|---|---|
| `digestAlgorithm` (in SET and SignerInfo) | `sha1` (OID 1.3.14.3.2.26) | `sha1WithRSAEncryption` (OID 1.2.840.113549.1.1.5) |
| `signatureAlgorithm` (in SignerInfo) | `sha1WithRSAEncryption` (OID 1.2.840.113549.1.1.5) | `rsaEncryption` (OID 1.2.840.113549.1.1.1) |

The CMS also includes `authenticatedAttributes` (contentType, signingTime, messageDigest, signingCertificate) — which the official CoSign GUI's CMS does not have (bare/direct signature).

OpenSSL's CMS verification rejects this because `sha1WithRSAEncryption` is a signature algorithm, not a digest algorithm. The CMS is otherwise valid — the signature math checks out, but the OIDs are wrong per RFC 5652.

External validators may report this as a format failure (e.g. "The digest algorithm ? is not authorised") because they can't resolve the non-standard OID. The signature itself is valid.

### What we tried

```bash
# This fails with "CMS Verification failure"
openssl cms -verify -inform DER -in sig.der -content data.bin -binary -noverify
```

The error comes from `CMS_SignerInfo_verify_content` — openssl cannot determine the correct hash algorithm from the non-standard OID.

### Our approach

Revenant resolves CoSign's non-standard digest OID to its standard hash and then performs both required checks directly:

```python
# Python
result = verify_embedded_signature(signed_pdf, expected_hash=hash_sent_to_cosign)
assert result["hash_ok"]
assert result["signature_valid"] is True
assert result["valid"]
```

```typescript
// TypeScript
const result = await verifyEmbeddedSignature(signedPdf, hashSentToCosign);
if (!result.hashOk || result.signatureValid !== true || !result.valid) {
  throw new Error("signature verification failed");
}
```

This catches integrity and authenticity failures, including:
- ByteRange offsets are wrong -> hash mismatch
- CMS inserted at wrong position -> hash mismatch
- Original PDF bytes corrupted during incremental update -> hash mismatch
- A fabricated or modified signature with a matching `messageDigest` -> signer-signature failure
- An unrelated certificate placed first in the CMS certificate set -> ignored; the `SignerInfo.sid` certificate is used
- Object serialization errors (e.g. `None` vs `null`) -> PDF readability check fails

### Note on pyhanko

[pyhanko](https://github.com/MatthiasValworthy/pyHanko) is a Python library for PDF signature creation and validation that handles non-standard CMS structures. Revenant implements its own chain validation (TSL-based, using `cryptography` for X.509 verification) rather than depending on pyhanko, which is a heavier dependency with different design goals. CRL/OCSP revocation checking may be added in a future version.

## PKI chain validation

Since v1.1, revenant can validate the signer's certificate chain against a Trust Service List (TSL). This answers: "is this signature from a publicly trusted CA?"

### How it works

1. **TSL fetch** -- downloads and caches the country's Trust Service List XML (ETSI TS 119 612). The TSL lists all trusted CA certificates.
2. **Chain building** -- selects the leaf named by `SignerInfo.sid`, then builds a chain using SKI/AKI matching. Missing intermediates are fetched via AIA URLs.
3. **Anchor matching** -- checks if the chain terminates at a CA listed in the TSL.
4. **Cryptographic verification** -- validates the chain using `cryptography.x509.verification` (Python) or `pkijs.CertificateChainValidationEngine` (TypeScript).

### Trust status

| Status | Meaning |
|---|---|
| `trusted` | Chain terminates at a TSL-listed CA. Signature is publicly trusted. |
| `untrusted` | Valid signature, but the root CA is not in the TSL. |
| `unknown` | Chain validation was not attempted (no TSL URL configured). |

The `valid` field requires valid structure, a matching signed `messageDigest`, and a cryptographically verified signer signature. Trust is reported separately via `chain_valid`, `trust_anchor`, and `trust_status`.

### TSL configuration

The TSL URL is per-profile. The built-in EKENG profile uses the Armenian TSL:

```
https://www.gov.am/files/TSL/AM-TL-1.xml
```

Custom profiles have no TSL by default. Add one via `ServerProfile.tsl_url` (Python) or `tslUrl` (TypeScript).

### Armenian PKI hierarchies

The Armenian TSL lists EKENG CJSC as the trust service provider with three CA anchors:

| CA | Type | Signs |
|---|---|---|
| RACitizen | CA/QC | Citizen certificates |
| CA of RoA | CA/QC | Citizen certificates |
| Citizen CA | CA/QC | Citizen certificates |

Certificates issued under "Staff of Government of RA Root CA" (used for government staff and foreign accounts) are **not in the TSL** and will report `chain_valid: false`.

### Limitations

- **No CRL/OCSP** -- revocation status is not checked. Chain validation confirms trust anchor only.
- **TSL cache** -- cached for 24 hours. No signature verification on the TSL XML itself.
- **BMPString certs** -- some certificates with BMPString-encoded fields fail `cryptography` parsing. Revenant falls back to SKI/AKI matching without cryptographic verification.

## CLI `check` command

For verifying already-signed PDFs (without the original hash):

```bash
revenant check signed.pdf        # Python CLI
npx revenant check signed.pdf    # TypeScript CLI
```

Output:
```
Checking signed.pdf (275.0 KB)...
  ByteRange OK -- signed data: 265237 bytes
  CMS blob: 1867 bytes
  CMS: valid ASN.1 structure
  Signer: Aleksandr Kraiz 3105951040
  Hash OK -- SHA-1 matches CMS messageDigest: 9488fb8869c8...
  Signature OK -- signer signature verifies
  LTV: Not LTV enabled
  Chain: signer cert: Common Name: Aleksandr Kraiz 3105951040
  Chain: no trusted CA found (operator: EKENG CJSC)
  pikepdf: valid PDF, 2 page(s)

  RESULT: Signature VALID
```

The original pre-sign hash is not required for standalone verification: the signed CMS `messageDigest` binds the signature to the PDF ByteRange, and the signer signature authenticates that attribute. The optional expected hash provides an additional post-sign consistency check. If a TSL is configured, `check` also reports certificate-chain trust separately.

## ByteRange layout

Understanding the exact byte layout was critical for verification:

```
offset 0                      len1          off2          off2+len2=EOF
|                              |             |             |
v                              v             v             v
[chunk1 ......................<]HEXHEXHEX...>[chunk2 ......]
^--- signed data (chunk1) ---^ ^-- CMS --^  ^-- signed ---^
                                             data (chunk2)
```

- `<` is the **last byte** of chunk1 (included in signed data)
- `>` is the **byte before** chunk2 starts (NOT in signed data)
- The hex between `<>` is the CMS DER, zero-padded

The ByteRange values point to the raw hex content, not the angle brackets:
- `len1` = offset of first hex byte (right after `<`)
- `off2` = offset right after `>` (first byte of chunk2)
