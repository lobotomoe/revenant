# Post-Sign Verification

How we verify that embedded PDF signatures are correctly constructed.

## Verification steps

After inserting the CMS into the PDF, the tool automatically verifies the result:

1. **Structure check** — re-reads the PDF, finds the last `/ByteRange`, extracts chunk1 + chunk2 (the signed data) and the CMS hex from `/Contents`
2. **Hash check** — computes SHA-1 of the extracted ByteRange data and compares with the hash originally sent to CoSign. Mismatch = corruption during incremental update construction
3. **CMS sanity** — checks blob is non-empty and starts with ASN.1 SEQUENCE tag (0x30)
4. **pikepdf readability** — opens the final PDF with pikepdf to confirm it's structurally valid

If any check fails, the signed PDF is **not saved** and an error is raised.

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

Since we control both the hash computation (before signing) and the hash extraction (after signing), we can verify directly:

```python
# During signing: we know the hash we sent
br_hash = compute_byterange_hash(prepared_pdf, hex_start, hex_len)

# After signing: re-extract and compare
signed_data, cms_der = extract_signature_data(signed_pdf)
actual_hash = hashlib.sha1(signed_data).digest()
assert actual_hash == br_hash  # This is our verification
```

This catches all corruption scenarios:
- ByteRange offsets are wrong -> hash mismatch
- CMS inserted at wrong position -> hash mismatch
- Original PDF bytes corrupted during incremental update -> hash mismatch
- Object serialization errors (e.g. `None` vs `null`) -> pikepdf readability check fails

### Future: pyhanko

[pyhanko](https://github.com/MatthiasValworthy/pyHanko) is a Python library for PDF signature creation and validation that handles non-standard CMS structures. If the library matures into a production-ready, well-maintained option, it could replace the current manual verification with proper cryptographic CMS validation (signature math, certificate chain, revocation checks) — not just structural/hash checks.

## CLI `check` command

For verifying already-signed PDFs (without the original hash):

```bash
python -m revenant check signed.pdf
```

Output:
```
Checking signed.pdf (275.0 KB)...
  ByteRange OK — signed data: 265237 bytes
  CMS blob: 1867 bytes
  CMS: valid ASN.1 structure
  pikepdf: valid PDF, 1 page(s)
  Hash OK — SHA-1 consistent: 2202bf4ad83cc553348195a580ab3640450e581a

  RESULT: Signature structure is VALID
```

Without the expected hash, `check` verifies structure, CMS format, and pikepdf readability. It cannot detect content tampering (since it doesn't know the original hash), but it confirms the PDF is well-formed and the signature field is structurally correct.

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
