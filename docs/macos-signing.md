# macOS Code Signing & Notarization

The release workflow signs and notarizes macOS binaries when GitHub secrets are configured.
Without secrets, builds are unsigned (same as before).

## Required GitHub Secrets

| Secret | Description | How to get |
|--------|-------------|------------|
| `MACOS_CERTIFICATE_BASE64` | Developer ID Application cert + key (.p12), base64 | Keychain Access -> export cert -> `base64 -i cert.p12` |
| `MACOS_CERTIFICATE_PASSWORD` | Password for the .p12 file | Set when exporting from Keychain |
| `APPLE_IDENTITY` | Signing identity name, e.g. `Your Name (TEAMID)` | `security find-identity -v -p codesigning` |
| `APPSTORE_API_KEY_BASE64` | App Store Connect API key (.p8), base64 | App Store Connect -> Users and Access -> Keys -> Generate |
| `APPSTORE_API_KEY_ID` | API Key ID (10-char alphanumeric) | Shown when creating the key |
| `APPSTORE_API_ISSUER_ID` | Issuer UUID | Top of the Keys page in App Store Connect |

## Step-by-step setup

1. **Get Developer ID certificate** (requires Apple Developer Program membership):
   - Open Xcode -> Settings -> Accounts -> Manage Certificates
   - Create a "Developer ID Application" certificate
   - In Keychain Access, find the cert, right-click -> Export -> save as `.p12` with a password
   - `base64 -i DeveloperID.p12 | pbcopy` (copies base64 to clipboard)

2. **Create App Store Connect API key**:
   - Go to [App Store Connect -> Keys](https://appstoreconnect.apple.com/access/integrations/api)
   - Click "+", name it "CI Notarization", grant "Developer" access
   - Download the `.p8` file (only available once!)
   - Note the Key ID and Issuer ID from the page
   - `base64 -i AuthKey_XXXXXXXXXX.p8 | pbcopy`

3. **Add secrets to GitHub**:
   - Repo -> Settings -> Secrets and variables -> Actions -> New repository secret
   - Add all 6 secrets from the table above

## CI flow (macOS only, when secrets are present)

```
Build .app (--no-dmg) -> Codesign .app + CLI -> Create DMG -> Notarize DMG -> Staple -> Notarize CLI
```

Entitlements: [`python/entitlements.plist`](../python/entitlements.plist) (hardened runtime exceptions for PyInstaller's Python runtime).
