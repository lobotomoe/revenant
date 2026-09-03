# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [4.0.0] - 2026-09-03

Two fixes -- logging in to a non-EKENG server, and the app icon on macOS -- plus
a dependency refresh that clears a withdrawn package and two advisories.

The major bump is required by one breaking change in the Rust crates:
`ServerProfile` in `revenant-sign-core` gains a public field, and the struct is
now `#[non_exhaustive]`. The Python and TypeScript packages keep their public
surface, and nothing changes for users of the desktop app or the CLIs.

### Fixed

- **Custom servers now accept non-ASCII credentials.** Both GUIs refused a
  username or password containing any non-Latin character, on every profile.
  The restriction describes EKENG, whose logins are Latin letters and digits,
  but it was applied to custom CoSign deployments too -- blocking credentials
  the SOAP envelope escapes and carries as UTF-8 without trouble, and that both
  CLIs already accepted. It is now a profile capability, off for custom servers
  and on for EKENG, where a non-ASCII entry is a keyboard-layout slip and
  refusing it spends none of that profile's five-attempt lockout budget.
  Reported by peyuaa (#76).
- **The macOS Dock no longer shows a black egui logo in place of the app icon.**
  The desktop app deliberately left its runtime icon unset on macOS, so that the
  Dock tile would stay with the bundle's `.icns`. eframe reads an unset icon the
  other way round: it substitutes its own default egui artwork and pushes that
  through `setApplicationIconImage`, taking over the tile for as long as the app
  runs. It now passes an empty `IconData` -- egui's documented opt-out -- so the
  installed icon survives launch.

### Security

- **The desktop app no longer ships a browser-launching flaw.** `webbrowser`,
  which the GUI stack uses to open links, honoured the Unix `BROWSER`
  environment variable in a way that allowed argument injection
  (RUSTSEC-2026-0257). Updated to 1.2.4.
- **Rust dependencies are now audited in CI.** `cargo audit` runs beside
  `pip-audit` in the required Security Audit job, so a known-vulnerable crate
  fails the build instead of waiting for a weekly Scorecard alert nobody is
  blocked on -- which is how the `webbrowser` advisory above went unnoticed.
  One finding is ignored with a recorded reason and a re-evaluation trigger: the
  `rsa` Marvin timing sidechannel, which has no released fix.
- **The Rust lockfile is refreshed to the latest compatible releases.** This
  takes `chacha20` off a yanked 0.10.1, `event-listener` off the unsound 5.4.1
  (RUSTSEC-2026-0221), and `wayland-scanner` onto a `quick-xml` 0.41 -- which
  removes the last vulnerable copy of that crate from the tree and lets the two
  `quick-xml` audit ignores go, arming that guard again.

### Changed

- **`ServerProfile` in `revenant-sign-core` is now `#[non_exhaustive]`** and
  gains a public `ascii_credentials_only` field. Profiles are meant to come from
  `ServerProfile::builtin` / `::custom_default`, which fill in every capability
  the deployment implies; code that constructed the struct literally must move
  to those constructors. Marking it non-exhaustive is itself the breaking part,
  and it is what keeps the next field addition off the major-version budget.

### Removed

- **`python/scripts/merge_universal.py`.** The release workflow has lipo'd the
  macOS universal binaries directly since the Rust pipeline landed, leaving the
  script unreachable from every workflow and build script. Its fallback read a
  `lipo -create` "same architectures" failure as proof that both inputs held
  the same architecture set and copied the arm64 side, which for partially
  overlapping inputs would have silently dropped the x86_64 slice. The live
  path has no such fallback. Reported by peyuaa (#75).

## [3.0.5] - 2026-08-18

Security release. Three fixes for background results being applied to state
that did not ask for them, one for the output path a signed file is written to,
and a hardened release pipeline.

### Fixed

- **A cancelled connection can no longer become the active server.** Dismissing
  the Connect dialog did not stop the server test already running, and neither
  GUI checked, when the answer arrived, whether it was still wanted. A slow
  endpoint could return success after the user backed out and be saved as the
  active profile, so later credentials and signing requests went somewhere the
  user had declined. Both GUIs now tag each attempt and drop a result that no
  longer belongs to the dialog on screen. Reported by peyuaa; found during that
  fix to affect the Python GUI as well.
- **A saved password can no longer be pre-filled into a different login.** The
  Rust GUI read the saved password in the background and applied whatever came
  back to whichever login was open, so cancelling one login and starting another
  could put the first account's password into the second. The read is now bound
  to the login and username that asked for it, and a password box the user has
  typed in and cleared is never silently re-filled. The same fix covers identity
  discovery, which could otherwise save one login's signer certificate under
  another's. Reported by peyuaa.
- **Signing no longer writes through a symlink at the output path.** When a
  sandbox forbids creating a temporary file, both the Python and Rust clients
  fall back to writing the output directly. That fallback followed a symlink
  left at a predictable output name (`<stem>_signed.pdf`) and truncated whatever
  it pointed at, where the normal path replaces the link instead. The fallback
  now refuses to follow links, refuses anything that is not a regular file, and
  fails outright on platforms that cannot express either. Reported by peyuaa
  against the Python client; the Rust CLI carried the same flaw.

### Security

- **The AppImage packaging tool is now pinned and verified.** The release job
  fetched `appimagetool` from a mutable tag over plain HTTP(S) and marked it
  executable without checking it, then used it to pack both published Linux
  AppImages -- so whatever that URL served on release day ran inside the release
  job and shipped to users. It is now pinned to a tagged release and checked
  against a known digest before it is made executable. Reported by peyuaa.

## [3.0.4] - 2026-08-18

Security release. Three fixes in what the desktop apps report about a
signature. The command-line tools were not affected and their verdicts are
unchanged.

### Fixed

- **A tampered PDF is no longer shown as a valid signature.** The Rust GUI took
  its green verdict from the CMS signature alone. Altering bytes the ByteRange
  covers while leaving the CMS object intact keeps that signature verifiable, so
  a modified document rendered `Signature VALID` in green with a red integrity
  failure beneath it, and named the embedded certificate as its signer. The
  verdict is now the full result -- integrity and signature -- which is what the
  core library already meant by valid, and what the CLI has always reported.
  Reported by peyuaa.
- **A failed signature no longer carries a trusted signer.** The Python GUI
  printed `Signature: Integrity check FAILED` directly above a green
  `Trust: Trusted (CA)`, because the trust line read only the chain result. The
  chain may genuinely be trusted; that is a fact about the certificate and not
  about a document the signature does not cover. Signer, organization and trust
  are now reported only for a signature that verified, on both the embedded and
  detached paths. Reported by peyuaa.
- **A certificate that is not yet valid is no longer styled as normal.** The
  Python GUI classified certificates by `notAfter` only, so one whose validity
  period had not started showed the ordinary presentation and a reassuring
  count of days remaining. It is now flagged like an expired certificate, since
  neither can be used. Reported by peyuaa.

## [3.0.3] - 2026-08-17

Security release completing a fix that 3.0.2 landed in only one of the three
clients. Users of the Python package or the Rust crates should upgrade.

### Fixed

- **The BER size bound now covers Python and Rust as well.** 3.0.2 fixed this
  in the TypeScript client because the report named only the npm package, but
  the flaw was identical in the other two: the 16 MiB ceiling sat in the
  definite-length branch, past the point where an indefinite-length header
  returns, and the `/Contents` gap was decoded to a string with no bound at all.
  A crafted `/ByteRange` therefore allocated the whole gap before anything
  rejected it. Both clients now refuse an oversized gap and an oversized input
  up front, against the same shared ceiling, matching TypeScript. Originally
  reported by peyuaa.

## [3.0.2] - 2026-08-16

Security release. Three reported vulnerabilities in signature verification,
plus a batch-signing fix in the desktop app. Upgrading is recommended.

### Fixed

- **Certificate order in a CMS no longer confers trust.** Chain validation began
  from the first embedded certificate and signer identity was read from the same
  one, while the signature itself was verified against the certificate named by
  `SignerInfo.sid`. A CMS certificate set is a `SET OF`, so those need not be the
  same certificate: signing detached content with an untrusted self-signed
  certificate and listing a trusted root ahead of it made Revenant verify the
  attacker's signature, walk the chain from the root, report `VALID and trusted`,
  and display the root as the signer. All three now resolve the signer through
  the `SignerInfo`, and only when exactly one embedded certificate matches --
  an ambiguous set has not named a signer. Rust's `build_chain` takes the leaf as
  a parameter instead of reading pool index 0. Reported by peyuaa.
- **LTV status is no longer raised by data anyone can append.** The status came
  from the presence of a revocation-related OID and counted the signer's
  *unsigned* attributes alongside the signed ones. Unsigned attributes are not
  covered by the signature, so an Adobe `RevocationInfoArchival` attribute
  holding the string `bogus-not-ocsp-or-crl` could be stapled onto a finished
  document and reported as LTV enabled with `has_ocsp` set. The `SignedData.crls`
  field is outside the signature for the same reason. Both are still reported,
  now marked as present and not counted, and attribute values are decoded rather
  than taken on the OID's word. This reports what a signature carries, not that
  the revocation data was validated -- that check does not exist yet, and the
  documentation says so. Python and TypeScript gain
  `has_unauthenticated_material`; Rust reports the same distinction as a
  `RevocationMaterial` enum. Rust was affected too, though the report named only
  the Python and npm packages. Reported by peyuaa.
- **A BER indefinite-length CMS is bounded before it is decoded.** The 16 MiB
  ceiling was checked against the length a definite-length header claims. An
  indefinite-length blob claims nothing, so it was decoded whole and its extent
  discovered only on reaching the end marker -- a crafted PDF allocated its
  entire `/Contents` gap regardless of the limit. Both the extractor and the PDF
  path now refuse an oversized gap up front, against the same exported ceiling.
  Fixed here in the TypeScript client only, which is what the report named; the
  Python and Rust clients carried the same flaw and are fixed in 3.0.3.
  Reported by peyuaa.
- **Batch signing no longer overwrites files it did not create.** Every
  destination is reserved before the first signing request and written with
  exclusive creation, so a queued input can no longer be replaced by an earlier
  file's output, and same-named inputs from different folders no longer collide.
  Outputs that could not take their derived name are now reported, labelled by
  full input path. Contributed by peyuaa.

## [3.0.1] - 2026-08-16

Security release. Fixes one vulnerability introduced in 3.0.0; upgrading is
recommended for everyone running that version.

### Fixed

- **A CMS signature without signed attributes no longer vouches for content it
  never covered.** RFC 5652 section 5.4 puts the signature over the content
  itself when `signedAttrs` is absent, and 3.0.0 added support for that shape.
  It resolved the content in the wrong order: an `encapContentInfo.eContent`
  embedded in the blob was preferred over the bytes the caller asked about, so a
  genuine attached signature over attacker-chosen bytes verified successfully
  and the result was then reported as covering an unrelated PDF `ByteRange` or
  detached payload. Because no signed attributes means no `messageDigest` to
  re-check, that signature verdict was the entire integrity argument:
  verification returned `valid`, `hash_ok` and `signature_valid` all true for a
  document the signer never saw. The caller's bytes are now authoritative, and a
  CMS that also embeds its own content is rejected as unverifiable unless the
  two are byte-identical. Verifying an attached CMS on its own terms, by passing
  no detached content, still works. Signatures that carry signed attributes were
  never affected -- their `messageDigest` was always compared against the
  caller's bytes.

## [3.0.0] - 2026-08-12

Security release. Every change below is a fix for a reported vulnerability;
upgrading is recommended for all users.

The major bump is required by one breaking API change in the Rust crates:
`pki::validate_chain` no longer takes a `Transport`, and
`constants::MAX_AIA_FETCHES` is gone. The Python and TypeScript packages keep
their public surface -- `MAX_AIA_FETCHES` was never exported from either
entry point -- but their verification behaviour changes, as described below.

### Removed

- **Certificate chains are no longer completed by fetching the Authority
  Information Access URLs printed inside a certificate.** Those URLs travel
  inside the document being verified, so following them let whoever produced a
  file choose hosts for the verifying machine to contact -- opening a document
  became a network callback that reports the reader's address and the moment
  they opened it, and a certificate may carry any number of them. The per-chain
  limit did not restrain this: it counted only fetches that *succeeded*, so
  unreachable URLs were retried without bound, each costing a connection
  attempt with retries. Issuers now come from the CMS blob, which is where
  RFC 5652 has a signer put them, and from the configured trust store. A
  signature whose CMS omits its own intermediates stops short of a trusted
  anchor and reads as `untrusted` -- or `indeterminate`, if an anchor still
  matched by name but the chain could not be verified -- instead of silently
  reaching out for them. No built-in
  profile is affected: EKENG's chain has no intermediates, and its certificates'
  AIA URLs are plain HTTP, which the transport has always refused.
  `MAX_AIA_FETCHES` is gone from all three implementations, and Rust's
  `validate_chain` no longer takes a `Transport` -- chain validation now has no
  way to reach the network at all.

### Fixed

- **Python/TypeScript: CMS verification now checks the cryptographic signer
  signature, not only the container structure and signed digest.** Unsupported,
  malformed, or unverifiable signatures fail closed. Signer identity and
  optional trust-chain validation now select the certificate named by
  `SignerInfo.sid` instead of relying on certificate `SET OF` order, and an ESS
  `signingCertificate`/`signingCertificateV2` attribute binds that identity to
  the exact embedded certificate. TypeScript verifies directly with that
  selected certificate instead of allowing PKIjs to resolve `sid` again, and
  both implementations expose signer metadata only when matching ESS or a
  trusted certificate chain authenticates it.
- **Python: the signer public key is read from the certificate's
  `SubjectPublicKeyInfo` instead of parsing the whole certificate.** Production
  signer certificates (EKENG/CoSign among them) encode DN attributes such as
  `emailAddress` as a `PrintableString` containing `@`, which is outside that
  type's character set; a strict X.509 parser rejects the entire certificate
  over a field signature verification never reads, turning genuine signatures
  into false negatives.
- **Python and TypeScript now agree on the CMS signature input.** Python hashed
  the signed attributes re-encoded as canonical DER while TypeScript hashed only
  the bytes as transmitted, so the same document could verify in one and fail in
  the other. Both now try the as-transmitted encoding first and the canonical
  DER re-encoding second. The two encodings carry the same parsed attributes,
  which are validated independently before any signature is checked, so nothing
  is loosened. Rust remains canonical-DER only and still rejects a signature
  made over a non-DER transmitted ordering.
- Failures that cannot be attributed to a specific check now name the
  underlying error instead of reporting an opaque "CMS signature check failed".
- **Signing workflows no longer return a signature nobody verified.** The
  CMS/PKCS#7 bytes a signing service sends back are now proven to be a genuine
  signature over exactly the bytes that were submitted, before any workflow
  reports success. A compromised or impersonated service could previously make
  `sign_data` / `sign_pdf_detached` succeed while returning something no
  conforming verifier would accept, and the embedded flow accepted a response
  that merely hashed correctly. Failures raise a distinct
  `SigningResponseError` (`RevenantError::SigningResponse` in Rust): the request
  succeeded at the protocol level, so retrying is pointless and nothing is
  saved. The raw `SigningTransport` methods remain unverified by design -- they
  are the low-level primitive, and calling them directly is an explicit opt-out.
- **Rust: knowing the hash that was submitted no longer stands in for checking
  what came back.** Post-sign verification treated a matching `expected_hash` as
  proof and skipped the CMS `messageDigest` comparison entirely, so a response
  carrying no digest at all could be reported as intact. Both are now required,
  matching Python and TypeScript.
- **Rust: `has_signed_attributes` distinguishes "the CMS says it has none" from
  "the CMS did not parse".** It now returns `Option<bool>`; previously a
  corrupt blob borrowed the diagnostic wording of a legitimate
  no-`signedAttrs` signature.
- **`sign_hash` now says what it actually does.** It signs the hash bytes
  themselves. What a service does with a submitted digest is service-defined and
  observed to vary: some sign it as a pre-computed digest, others hash it again
  and sign it as ordinary content -- and only the first kind yields a signature
  that can be attached to the document the hash came from. The response is
  checked to be a genuine signature, and a warning is logged naming both digests
  when it does not bind the one submitted. The operation is not failed over
  this: the caller asked for those bytes to be signed, and they were. To sign a
  document, pass the document to `sign_data`.
- **TypeScript: the signature image pixel budget is enforced before decoding,
  not after.** `loadSignatureImage` decoded the whole file and only then
  compared the pixel count against its limit, by which point the decoder had
  already allocated the full output: a 547 KB PNG declaring 12000x12000 drove
  resident memory to 1.7 GB before the check ran, and the 5 MB file cap allows
  an order of magnitude more. Dimensions are now read from the PNG `IHDR` chunk
  and the JPEG frame header, and refused there; `jpeg-js` is additionally given
  the same limit so that a frame the header scan did not reach cannot exceed it
  either. Python and Rust already checked dimensions before decoding.
- **Legacy TLS now authenticates the server, and is never selected on its
  own.** The TLS 1.0 + RC4 transport validated no certificate at all, and any
  host could be pushed onto it: a standard-HTTPS failure -- including a failed
  certificate check, the one signal that something is wrong -- made the client
  retry over a transport that performs no certificate check. Two changes close
  that. A profile now carries `tls_pins`, the SHA-256 of the server
  certificate's `SubjectPublicKeyInfo`, checked the moment the certificate
  arrives and before any request byte or premaster secret is sent; the `ekeng`
  profile ships the key its appliance has presented since 2006. And the
  transport no longer probes: a host reaches the legacy path only because a
  profile declared it, and every other host is standard HTTPS or nothing.
  Chain validation was never possible for these appliances -- they present a
  self-signed factory certificate naming neither the host nor a checkable
  authority -- so a pinned key is a stronger guarantee here than the public
  PKI could have given.

### Changed

- **Breaking (Python/TypeScript API):** `VerificationResult` gains
  `signature_valid` / `signatureValid` (`true`, `false`, or `null` when
  verification could not be performed), and `valid` now additionally requires
  that the signer signature verifies. Documents that earlier releases reported
  as valid on digest agreement alone are now reported invalid.
- **Breaking (Python/TypeScript API):** `signer` is `null` unless a matching ESS
  attribute or a trusted certificate chain authenticates the certificate.
  Callers that displayed signer identity unconditionally must handle absence.
- Only RSA PKCS#1 v1.5 signers are verified. ECDSA and RSASSA-PSS signers are
  reported as unverifiable, and therefore invalid, rather than accepted.
- **Consequence, stated deliberately:** because signing workflows now refuse a
  response they cannot verify, a signing service that switched to ECDSA or
  RSASSA-PSS would fail signing outright rather than return an unverifiable
  signature. That is the intended direction -- an unverifiable signature
  returned under a success message is the defect being fixed -- but it means
  algorithm support is now on the signing path, not only the verification path.
### Added

- **Signature coverage is now measured and reported.** A signature covers only
  the bytes named by its `/ByteRange`; anything after it belongs to a later
  incremental revision that the signature does not protect. Results gain
  `covers_whole_file`, `covered_bytes` and `total_bytes`, and each signature
  reports whether it covers the whole file or only part of it. When *no*
  signature in a document reaches the end of the file, the trailing region is
  signed by nobody and is called out explicitly. This is decided by arithmetic
  over the ByteRange alone -- the content of the unsigned region is never
  inspected or guessed at. Partial coverage does not by itself invalidate a
  signature: in a sequentially signed document every signature but the last
  legitimately covers an earlier revision.
- **CMS without signed attributes is now verified.** RFC 5652 section 5.4 makes
  `signedAttrs` optional and puts the signature over the content itself when it
  is absent. EKENG issues its credential documents in exactly that shape, so all
  three implementations previously reported genuine EKENG-issued signatures as
  invalid. The signature is now verified against the signed bytes, and because
  no `messageDigest` attribute exists in that form, integrity follows from the
  signature verdict alone. Such signatures can carry no ESS binding, so signer
  identity is exposed only when a trusted certificate chain authenticates it.

## [2.1.2] - 2026-08-03

### Fixed

- **macOS: sandbox write failure on auto-substituted output paths.** The GUI now resolves the output file/folder via native macOS Save/Open dialogs (Powerbox) on every sign operation, granting the app sandbox write permission. Previously, auto-derived paths like `Downloads/file_signed.pdf` triggered `Operation not permitted (os error 1)`.

### Changed

- **GUI: removed the separate output path text field and "Browse..." button.** The destination is now chosen directly from the native dialog when clicking "Sign PDF" (single file) or selecting a folder (batch mode).

## [2.1.1] - 2026-07-20

### Fixed

- **Python/TypeScript: signing a PDF that already has a form no longer
  destroys it.** The incremental update now merges the new signature field
  into the existing `/AcroForm` (preserving `/Fields`, `/DR`, `/DA`,
  `/NeedAppearances` and OR-ing `/SigFlags`) instead of replacing it
  wholesale -- the same fix the Rust port received in 2.1.0. Previously,
  signing a form-bearing PDF orphaned its fields, and counter-signing a
  server-pre-signed document (e.g. a tax-portal registration agreement)
  dropped the server's signature field from the form, so validators reported
  the document as tampered.

- **macOS: the Dock icon is no longer overridden by a flat square at runtime.**
  The desktop GUI forwarded its embedded window icon to
  `NSApplication.setApplicationIconImage`, which replaced the app bundle's
  rounded `.icns` with a square, full-bleed PNG for as long as the app ran. The
  runtime window icon is now set only on Windows (taskbar) and Linux (window
  manager); on macOS the Dock tile comes from the bundle icon.

## [2.1.0] - 2026-07-20

### Added

- **Rust port: a library plus a `revenant` CLI, published as three crates.**
  A new idiomatic Rust implementation targeting the same surface as the Python
  and TypeScript ports (no GUI):
  - `revenant-sign-tls` — from-scratch TLS 1.0 + RC4-MD5 client for the
    legacy CoSign appliances (EKENG's `ca.gov.am`) that no maintained Rust TLS
    library can reach, mirroring `tlslite-ng` / `node-forge`.
  - `revenant-sign-core` — the client library: config and credential storage, the
    CoSign DSS SOAP client with auto-detecting transport, CMS extraction,
    PDF signature preparation / embedding / verification, and pinned/TSL
    certificate-chain validation.
  - `revenant-sign` — the `revenant` binary (`sign`, `verify`, `check`, `info`,
    `cert`, `setup`, `logout`, `reset`), a thin front-end over `revenant-sign-core`.
- **Three new GUI languages: Turkish (tr), Georgian (ka), and Persian (fa).**
  The desktop app now ships in six languages. Persian is right-to-left;
  text in labels, messages, and input fields is right-aligned automatically
  when a right-to-left locale is active.

### Changed

- **The Rust workspace now versions as one unit on the product line (2.1.0),
  continuing from the Python client rather than restarting at 0.1.x.** The
  library crates (`revenant-sign-core`, `revenant-sign-tls`) and the shipped
  binaries (`revenant-sign`, `revenant-sign-gui`) share a single version, so the
  CLI `--version`, the GUI About box, the store listings, and the signer version
  recorded in each signed PDF (`/Prop_Build /REx`) all report the same number --
  matching the single-version model the Python and TypeScript packages use.

### Fixed

- **Rust: signing a PDF that already has a form no longer destroys it.** The
  incremental update now merges the new signature field into the existing
  `/AcroForm` (preserving `/Fields`, `/DR`, `/DA`, `/NeedAppearances` and
  OR-ing `/SigFlags`) instead of replacing it wholesale. Previously, signing a
  form-bearing PDF orphaned its fields, and re-signing dropped the earlier
  signature from the form.
- **Rust: `revenant verify` now recognises genuine signatures as trusted.** It
  validates detached CMS signatures fully in-crate against the active profile's
  pinned trust anchors (the same path `check` uses), instead of shelling out to
  `openssl` with the system trust store — which lacks the EKENG root and
  reported every valid signature as `INVALID`. The external `openssl`
  dependency is gone.
- **Rust: the CMS verifier no longer reports a signature `Valid` when the
  mandatory `contentType` signed attribute is missing or disagrees with
  `eContentType`** (RFC 5652 §11.1). It also now verifies the ESS
  `signingCertificate` / `signingCertificateV2` binding when present (RFC 5035):
  a signature whose ESSCertID hash names a different certificate than the one
  that verified is no longer accepted. EKENG CoSign signatures carry the v1
  form and continue to verify.
- **Rust: a CMS whose signature could not be *checked* (unusable key,
  unsupported algorithm OID, DER decode failure) is now reported `Unverifiable`
  rather than `Invalid`** — the latter wrongly implied the signature was forged.
- **Rust: the legacy TLS handshake is now bounded by an overall deadline,** so a
  server that dribbles records (or empty handshake records) can no longer pin a
  client thread indefinitely past the per-read socket timeout.
- **Rust: smaller correctness and robustness fixes.**
  - LTV status no longer claims an OCSP response merely because an Adobe
    `RevocationInfoArchival` container is present (it may hold only CRLs).
  - `/Contents` hex extraction now ignores insignificant white space inside the
    hex string, per ISO 32000-1 §7.3.4.3, so signatures laid out by other tools
    are read correctly.
  - The trailer `/ID` is carried into the incremental update as a hex string,
    preserving binary `/ID` values byte-for-byte instead of mangling them
    through a lossy UTF-8 conversion.
  - Signing a document whose catalog is at a non-zero generation now fails with
    a clear message instead of producing a structurally inconsistent file.
  - Signing a document large enough that a cross-reference-stream byte offset
    would exceed the 4-byte xref field now fails loudly instead of silently
    truncating the offset into a corrupt xref stream.
  - The legacy TLS client rejects a ServerHello that selects a version other
    than TLS 1.0, parses IPv6 URL literals correctly, and fails loudly if the
    socket read/write timeout cannot be set (rather than silently blocking).

## [2.0.0] - 2026-05-16

### TypeScript SDK only — Python client is unchanged

### Breaking

- Low-level signing functions in `revenant-sign` are renamed with a
  `WithTransport` suffix to free their unsuffixed names for new
  high-level wrappers:
  - `signPdfEmbedded` → `signPdfEmbeddedWithTransport`
  - `signPdfDetached` → `signPdfDetachedWithTransport`
  - `signHash` → `signHashWithTransport`
  - `signData` → `signDataWithTransport`

  The `SigningTransport` interface method names (`transport.signHash`,
  `transport.signData`, `transport.signPdfDetached`) are unchanged.
  Migration: rename your imports; transport-handling code is untouched.

### Added

- **High-level `signHash(hashBytes, username, password, options?)`** —
  detached CMS over a precomputed 20-byte SHA-1 hash, with profile
  resolution, transport setup, and TLS registration handled internally.
  Production callers no longer need to construct a `SoapSigningTransport`
  to sign a hash.
- **High-level `signData(dataBytes, username, password, options?)`** —
  same shape, detached CMS over arbitrary bytes (server computes the
  hash).
- **High-level `getCertInfo(username, password, options?)`** — returns
  the signer's identity (`CertInfo`: CN, email, organization, DN,
  `notBefore`, `notAfter`) by trying the `enum-certificates` SAPI
  operation first, falling back to dummy-hash signing.
- **High-level `verifyCredentials(username, password, options?)`** —
  thin wrapper over `getCertInfo` that discards the result and surfaces
  `AuthError` on bad credentials. One round-trip against the appliance's
  5-attempt lockout counter; suitable for "test before persist"
  credential-entry flows.
- `CertInfo` type is re-exported from the top-level `revenant-sign`
  entry.

## [1.2.1] - 2026-04-16

### Fixed

- Completed Armenian (hy) locale -- 21 strings were showing English fallback

## [1.2.0] - 2026-04-14

### Added

- **PKI chain validation** against ETSI Trust Service Lists (TSL) -- verifies signer certificate chains to trusted CAs (Python and TypeScript)
- TSL parser and cache with configurable TTL (24h default)
- Per-profile `tsl_url` field; EKENG profile uses the Armenian TSL
- Trust status display in GUI verify panel (trusted / not publicly trusted / not checked)
- Improved verify result formatting -- human-readable summary above technical details

### Improved

- Test coverage expanded to 95%+ (740 tests)
- New test modules: chain validation, LTV, ASN.1 BER edge cases, i18n

### Fixed

- CVE-2026-40192 (pillow), CVE-2025-71176 (pytest)
- CI: added `cryptography` and Python 3.10 backports to dev requirements

## [1.1.1] - 2026-04-10

### Improved

- Updated Russian and Armenian translations
- Added English locale for i18n completeness
- Refined translatable strings across GUI modules

## [1.1.0] - 2026-04-09

### Added

- **Localization**: Russian and Armenian language support for the GUI (gettext-based i18n)
- **Signature position preview**: mini page diagram in the sign form showing stamp placement
- **Password visibility toggle** in the login dialog
- **Friendly error messages**: raw HTTP/TLS errors mapped to user-readable messages in the GUI
- **ASCII credential warning**: warn when credentials contain non-Latin characters
- **Universal macOS binaries** (arm64 + x86_64) -- Intel Mac users can now install from the Mac App Store, Homebrew, and DMG
- Mac App Store badge in README
- `merge_universal.py` script for lipo-merging .app bundles and CLI binaries
- Translation consistency checker (`check_translations.py`) and .po compiler (`compile_translations.py`)

### Changed

- Homebrew formula no longer requires `arch: :arm64`
- Release pipeline builds on both `macos-latest` (arm64) and `macos-15-intel` (x86_64), merges with `lipo`
- Release artifacts renamed from `*-macos-arm64` to `*-macos-universal`
- Credential resolution moved off main thread to prevent UI freeze on macOS keychain prompts
- Platform-specific helpers (macOS menu bar, Windows icon) extracted to dedicated module

### Fixed

- Support for original EKENG cosign BER-encoded PDF signatures (indefinite-length CMS blobs) in both Python and TypeScript
- BER parser guards against deeply nested structures (depth limit) and oversized length fields
- npm publish step in release pipeline no longer silently swallows errors
- macOS notarization step properly fails on command errors instead of silently continuing

## [1.0.0] - 2026-02-26

### Added

- **TypeScript/Node.js client** (`revenant-sign` on npm) -- full-featured port of the Python client with CLI, library API, and 662 tests at 97%+ coverage
  - Dual ESM + CJS build via tsup
  - Embedded and detached PDF signing
  - Signature verification (embedded and detached CMS/PKCS#7)
  - CMS blob inspection and certificate info extraction
  - Multi-profile configuration with keytar credential storage
  - Legacy TLS 1.0 + RC4 transport for EKENG (pure JS via node-forge)
  - Armenian font support (GHEA Grapalat, GHEA Mariam, Noto Sans)
  - Signature image embedding (PNG/JPEG) with alpha channel support
- Microsoft Store distribution (Revenant Sign) with Partner Center identity
- Release pipeline now includes MAS .pkg in GitHub Releases

### Changed

- MSIX package renamed to RevenantSign.msix, display name updated to "Revenant Sign"

### Fixed

- PDF incremental updates now use cross-reference streams for PDFs that use XRef streams (PDF 1.5+), per ISO 32000-1 S7.5.8.4 -- fixes compatibility with macOS Preview and strict PDF readers when signing pdf-lib or modern-tool-generated PDFs (both Python and TypeScript)

## [0.2.6] - 2026-02-26

### Changed

- GUI window title simplified to "Revenant" (version removed to avoid screenshot staleness)
- MAS minimum deployment target bumped from macOS 11.0 to 12.0 (required for arm64-only builds)

## [0.2.5] - 2026-02-26

### Added

- macOS menu bar with File (Close Window) and Edit (Undo, Cut, Copy, Paste, Select All) menus
- Cmd+W keyboard shortcut to close windows and dialogs on macOS
- Privacy policy URL in Info.plist (MAS Guideline 5.1.1)

### Changed

- PyPI classifier updated from Beta to Production/Stable (MAS Guideline 2.2)

### Fixed

- MAS build: switch from system Tk 8.6 to Homebrew Tk 9.0 to resolve private API rejection (Guideline 2.5.1 -- `_NSWindowDidOrderOnScreenNotification`)
- CI: extract Python+Tk setup and private API verification into reusable composite actions
- macOS Preferences menu item no longer shows default Tk behavior

## [0.2.4] - 2026-02-21

### Fixed

- MAS build: use separate entitlements for nested executables to avoid ITMS-90885

## [0.2.3] - 2026-02-21

### Fixed

- MAS build: add application identifier to sandbox entitlements (ITMS-90886)

## [0.2.2] - 2026-02-21

### Fixed

- MAS build: embed provisioning profile for TestFlight and App Store submission (ITMS-90889)

## [0.2.1] - 2026-02-20

### Added

- Linux ARM64 build support
- Automatic Homebrew tap update on release

## [0.2.0] - 2026-02-16

### Changed

- **BREAKING:** Position preset names renamed to Y-first (CSS/UI) convention: `right-bottom` -> `bottom-right`, `right-top` -> `top-right`, `left-bottom` -> `bottom-left`, `left-top` -> `top-left`, `center-bottom` -> `bottom-center`. Short aliases updated accordingly (`rb` -> `br`, `rt` -> `tr`, etc.)
- Windows release artifact renamed from `revenant-cli-windows-x64.zip` to `revenant-windows-x64.zip` (contains both CLI and GUI)

### Fixed

- MAS build: include sandbox entitlements when signing outer .app bundle
- Snap: use `adopt-info` for version instead of `git describe`
- Integration tests TLS setup for env-var-only credentials

## [0.1.0] - 2026-02-14

### Added

- PDF digital signing via CoSign SAPI Web Service (SOAP/DSS)
- Embedded visible and invisible signature support with customizable appearance
- Armenian font support (GHEA Grapalat, GHEA Mariam, Noto Sans)
- Signature image embedding (PNG/JPEG) with alpha channel support
- PDF signature verification (embedded and detached CMS/PKCS#7)
- CMS blob inspection: digest algorithm, signer info, certificate chain
- Certificate information extraction from X.509 and CMS blobs
- Multi-profile configuration with per-profile credentials (keyring or config file)
- Automatic CoSign server discovery via DNS SRV records
- Legacy TLS 1.0 + RC4-MD5 transport for EKENG (ca.gov.am)
- Cross-platform GUI (tkinter) with sign, verify, and setup dialogs
- CLI with `sign`, `verify`, and `setup` commands
- Incremental PDF updates preserving existing signatures (re-signing support)
- Cross-reference stream PDF support (modern PDF 1.5+ format)
- Page size detection with CropBox/MediaBox/Rotate handling
- CI/CD workflows for linting, testing, and release builds
- Multi-platform release builds: macOS (.dmg), Windows (.msix, .zip), Linux (AppImage)
- Pyright strict mode type checking with 0 errors
- 96%+ test coverage (600+ tests)

[Unreleased]: https://github.com/lobotomoe/revenant/compare/v4.0.0...HEAD
[4.0.0]: https://github.com/lobotomoe/revenant/compare/v3.0.5...v4.0.0
[3.0.5]: https://github.com/lobotomoe/revenant/compare/v3.0.4...v3.0.5
[3.0.4]: https://github.com/lobotomoe/revenant/compare/v3.0.3...v3.0.4
[3.0.3]: https://github.com/lobotomoe/revenant/compare/v3.0.2...v3.0.3
[3.0.2]: https://github.com/lobotomoe/revenant/compare/v3.0.1...v3.0.2
[3.0.1]: https://github.com/lobotomoe/revenant/compare/v3.0.0...v3.0.1
[3.0.0]: https://github.com/lobotomoe/revenant/compare/v2.1.2...v3.0.0
[2.1.2]: https://github.com/lobotomoe/revenant/compare/v2.1.1...v2.1.2
[2.1.1]: https://github.com/lobotomoe/revenant/compare/v2.1.0...v2.1.1
[2.1.0]: https://github.com/lobotomoe/revenant/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/lobotomoe/revenant/compare/v1.2.1...v2.0.0
[1.2.1]: https://github.com/lobotomoe/revenant/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/lobotomoe/revenant/compare/v1.1.1...v1.2.0
[1.1.1]: https://github.com/lobotomoe/revenant/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/lobotomoe/revenant/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/lobotomoe/revenant/compare/v0.2.6...v1.0.0
[0.2.6]: https://github.com/lobotomoe/revenant/compare/v0.2.5...v0.2.6
[0.2.5]: https://github.com/lobotomoe/revenant/compare/v0.2.4...v0.2.5
[0.2.4]: https://github.com/lobotomoe/revenant/compare/v0.2.3...v0.2.4
[0.2.3]: https://github.com/lobotomoe/revenant/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/lobotomoe/revenant/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/lobotomoe/revenant/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/lobotomoe/revenant/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/lobotomoe/revenant/releases/tag/v0.1.0
