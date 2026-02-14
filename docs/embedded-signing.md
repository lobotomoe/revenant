# Embedded PDF Signature — Implementation

How we embed CMS signatures directly into PDFs using the CoSign SOAP API.

## The workflow

Since the server supports signing but not embedded PDF creation, the client does all PDF manipulation. The key requirement is **true incremental update** — the original PDF bytes must be preserved exactly, byte-for-byte. This is critical for validators that verify the uploaded signed file is the same document they issued (see [ekeng](ekeng/) for EKENG-specific validator requirements).

1. **Read PDF with pikepdf** (read-only) — extract page dimensions, object numbers, existing annotations. pikepdf is never used to *save* the PDF.
2. **Build new PDF objects as raw bytes**:
   - Signature dictionary (`/Type /Sig`, `/Filter /Adobe.PPKLite`, `/SubFilter /adbe.pkcs7.detached`)
   - Annotation widget (`/Type /Annot`, `/Subtype /Widget`, `/FT /Sig`) with coordinates
   - **Visual appearance stream** (`/AP /N`) — stacked layout with profile-configured fields (see "Visual appearance" below)
   - Font objects (embedded TrueType: Type0 + CIDFont + FontDescriptor + stream)
   - Optional signature image XObject
   - Page object override (adds `/Annots` array referencing the new widget, preserving existing annotations)
   - Catalog override (adds `/AcroForm` with `/SigFlags 3`)
3. **Append raw incremental update** after the original `%%EOF`:
   - All new objects written as raw PDF syntax
   - Sig dict includes `/ByteRange` placeholder (fixed-width, patched in-place) and `/Contents <0000...0000>` — 8192 bytes reserved for CMS (16384 hex chars)
   - New xref table referencing only the new/overridden objects
   - Trailer with `/Prev` pointing to original xref, carrying forward `/Info`, `/ID`, and other original trailer entries
4. **Patch ByteRange** to actual offsets (in-place, same byte width)
5. **Compute SHA-1** of everything except the `/Contents` hex string
6. **Send ByteRange data** to CoSign via `sign_data()` -> server hashes internally and returns CMS (~1867 bytes)
7. **Insert CMS** hex into `/Contents`, zero-pad remainder
8. **Verify** the result (see [verification.md](verification.md))
9. **Write final signed PDF**

## Why true incremental update?

Previous approach used pikepdf to add signature objects and then `pikepdf.save()` — but this **rewrites the entire PDF**: renumbers objects, changes the binary header comment, restructures internal content. The original bytes are destroyed even though the visual content is identical.

Document validators compare the uploaded signed file against the original they issued. They typically check:
- That the original document bytes are preserved (by extracting bytes up to the first `%%EOF` and comparing a stored hash)
- That the trailer carries forward `/Info` and `/ID`
- That a valid client signature is present

When pikepdf rewrites the PDF, validators reject the file because the original bytes are destroyed. See [ekeng](ekeng/) for EKENG-specific validator behavior.

The solution: use pikepdf **only for reading** (page dimensions, object graph), then build all new objects as raw PDF bytes and append them after the original content. The original bytes are never modified.

## Object serialization

When overriding existing objects (page, catalog), we need to faithfully reproduce their dictionary entries. We use `pikepdf.Object.unparse(resolved=True)` for this — it produces correct PDF syntax for all types including `null` (not Python `None`), arrays, dictionaries, names, strings, and numbers. Indirect references are serialized as `N G R`.

## PDF structure of signed file

```
%PDF-1.x
... original content (UNTOUCHED — exact original bytes) ...
xref
0 N
... original xref table ...
trailer << /Size N /Root R 0 R /Info I 0 R /ID [...] >>
startxref
OFFSET1
%%EOF

% --- Incremental update (appended raw bytes) ---
31 0 obj        % Sig dict with ByteRange + Contents
<<
  /Type /Sig
  /Filter /Adobe.PPKLite
  /SubFilter /adbe.pkcs7.detached
  /ByteRange [0 hex_start hex_end remaining]
  /Contents <308207...0000>     % CMS DER hex-encoded, zero-padded to 16384 chars
  /M (D:20260131120000+00'00')
  /Reason (Signed with Revenant)
  /Name (Signer Name)
>>
endobj
32 0 obj        % Annotation widget
<< /Type /Annot /Subtype /Widget /FT /Sig /Rect [...] /V 31 0 R /AP << /N 34 0 R >> ... >>
endobj
33 0 obj        % Font (embedded TrueType, e.g. NotoSans)
<< /Type /Font /Subtype /Type0 /BaseFont /NotoSans ... /DescendantFonts [...] >>
endobj
34 0 obj        % Appearance stream
<< /Type /XObject /Subtype /Form ... /Length N >>
stream
... PDF drawing operators for visual signature ...
endstream
endobj
9 0 obj         % Page override (adds /Annots)
<< ... original page entries ... /Annots [7 0 R 8 0 R 32 0 R] >>
endobj
30 0 obj        % Catalog override (adds /AcroForm)
<< ... original catalog entries ... /AcroForm << /Fields [32 0 R] /SigFlags 3 >> >>
endobj
xref
9 1
OFFSET 00000 n
30 5
OFFSET 00000 n
OFFSET 00000 n
OFFSET 00000 n
OFFSET 00000 n
OFFSET 00000 n
trailer <<
  /Size 35
  /Prev OFFSET1
  /Root 30 0 R
  /Info 28 0 R
  /ID [ <01c7f7db...> <01c7f7db...> ]
>>
startxref
OFFSET2
%%EOF
```

## Trailer entries

Per PDF spec (§7.5.6), an incremental update trailer must contain all entries from the previous trailer that aren't being overridden. Critical entries:

- `/Size` — updated to new total
- `/Prev` — points to previous xref offset
- `/Root` — catalog reference (same or overridden)
- **`/Info`** — must be carried forward; contains document metadata including creator identifiers used by validators
- **`/ID`** — must be carried forward; document identity array

Missing `/Info` or `/ID` in the incremental trailer causes validators to reject the signed file.

## Visual appearance stream

The server ignores all `SAPISigFieldSettings` and `GraphicImageToSet` (see [soap-api.md](soap-api.md)), so the visual appearance is built entirely client-side in `core/appearance/` (fields, fonts, image, stream modules).

The appearance uses a stacked layout driven by the profile's `sig_fields` configuration. Each field is extracted from signer info using regex and rendered top-to-bottom:

```
Without image:
┌──────────────────────────────────────────────┐
│  Signer Name                                 │
│  SSN: 3105951040                             │
│  Date: 2026.01.30 16:59:32 +04'00'          │
└──────────────────────────────────────────────┘

With image:
┌──────────────────────────────────────────────┐
│  [signature img]  │  Signer Name             │
│                   │  SSN: 3105951040         │
│                   │  Date: 2026.01.30 ...    │
└──────────────────────────────────────────────┘
```

- **Fields**: configured per profile via `SigField` (id, source, regex, label). First field = large font (black), rest = smaller font (gray)
- **Image**: optional signature image on the left (~40% width), text stack on the right
- **Font**: Embedded TrueType fonts (NotoSans default, GHEA Mariam/Grapalat for Armenian), subset to reduce size, with glyph-width metrics for accurate text measurement
- **Adaptive width**: signature field width auto-sizes based on the widest field text
- **Signer info**: extracted from the signing certificate via `revenant setup`, or overridden with `REVENANT_NAME`

The stream is a raw PDF content stream (BT/ET text operators, rectangle drawing) attached to the annotation widget as `/AP /N` (normal appearance).

## Existing annotations

The page override preserves all existing annotations (e.g. link annotations) by reading them from the original page object and including them in the `/Annots` array alongside the new signature widget. This is important because TCPDF-generated PDFs often contain URI link annotations.

## pikepdf usage

pikepdf is used **read-only** in the current implementation:

- `pikepdf.open()` — read the PDF structure
- `pdf.pages[n].obj` — get page object number and dimensions
- `pdf.Root` — read catalog entries for override
- `pikepdf.Object.unparse()` — serialize objects to PDF syntax
- Page dimension extraction via `/MediaBox`, `/CropBox`

pikepdf is **not** used for writing or saving. All output is constructed as raw bytes.

## Differences from CoSign desktop signatures

The official CoSign desktop application produces structurally different (but
functionally equivalent) PDFs. None of these differences affect signature
validity, PDF compliance, or validator acceptance.

| Difference | Reason |
|-----------|--------|
| Single incremental update (vs two) | Simpler, equally valid per ISO 32000-1 |
| `/Adobe.PPKLite` (vs `/Adobe.PPKMS`) | Standard filter; PPKMS is CoSign-proprietary |
| 8192-byte CMS reservation with zero-padding | Standard practice; avoids needing to know CMS size in advance |
| No `/AR.SigFieldData` | Proprietary CoSign metadata, ignored by all PDF readers |
| No DSInvalid/DSUnknown/DSBlank XObjects | CoSign-specific status indicators, ignored by standard readers |
| Single-layer appearance stream | Functionally equivalent; multi-layer only needed for dynamic status icons |
| `/SMask` alpha transparency (vs `/Mask` color key) | More correct; supports true semi-transparency |
