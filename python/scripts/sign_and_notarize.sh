#!/usr/bin/env bash
#
# Local macOS signing and notarization script.
#
# Reads secrets from python/.env, signs the .app bundle, creates a DMG,
# and submits it for Apple notarization.
#
# Usage:
#   cd python/
#   bash scripts/sign_and_notarize.sh          # full pipeline: sign + DMG + notarize
#   bash scripts/sign_and_notarize.sh sign      # sign only (no notarization)
#   bash scripts/sign_and_notarize.sh notarize  # notarize existing signed DMG
#
# Prerequisites:
#   - python/.env with MACOS_CERTIFICATE_BASE64, MACOS_CERTIFICATE_PASSWORD,
#     APPLE_IDENTITY, APPSTORE_API_KEY_BASE64, APPSTORE_API_KEY_ID,
#     APPSTORE_API_ISSUER_ID
#   - dist/Revenant.app must exist (run: python scripts/build.py mac --no-dmg)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
DIST_DIR="$PROJECT_DIR/dist"
APP_PATH="$DIST_DIR/Revenant.app"
DMG_PATH="$DIST_DIR/Revenant.dmg"
ENTITLEMENTS="$PROJECT_DIR/entitlements.plist"
ENV_FILE="$PROJECT_DIR/.env"

# ── Helpers ─────────────────────────────────────────────────────────

die() { echo "ERROR: $*" >&2; exit 1; }

load_env() {
    [ -f "$ENV_FILE" ] || die ".env not found at $ENV_FILE"

    MACOS_CERTIFICATE_BASE64=$(sed -n 's/^MACOS_CERTIFICATE_BASE64="\(.*\)"$/\1/p' "$ENV_FILE")
    MACOS_CERTIFICATE_PASSWORD=$(sed -n 's/^MACOS_CERTIFICATE_PASSWORD="\(.*\)"$/\1/p' "$ENV_FILE")
    APPLE_IDENTITY=$(sed -n 's/^APPLE_IDENTITY="\(.*\)"$/\1/p' "$ENV_FILE")
    APPSTORE_API_KEY_BASE64=$(sed -n 's/^APPSTORE_API_KEY_BASE64="\(.*\)"$/\1/p' "$ENV_FILE")
    APPSTORE_API_KEY_ID=$(sed -n 's/^APPSTORE_API_KEY_ID="\(.*\)"$/\1/p' "$ENV_FILE")
    APPSTORE_API_ISSUER_ID=$(sed -n 's/^APPSTORE_API_ISSUER_ID="\(.*\)"$/\1/p' "$ENV_FILE")

    [ -n "$MACOS_CERTIFICATE_BASE64" ] || die "MACOS_CERTIFICATE_BASE64 not set in .env"
    [ -n "$MACOS_CERTIFICATE_PASSWORD" ] || die "MACOS_CERTIFICATE_PASSWORD not set in .env"
    [ -n "$APPLE_IDENTITY" ] || die "APPLE_IDENTITY not set in .env"
}

check_notarize_vars() {
    [ -n "$APPSTORE_API_KEY_BASE64" ] || die "APPSTORE_API_KEY_BASE64 not set in .env"
    [ -n "$APPSTORE_API_KEY_ID" ] || die "APPSTORE_API_KEY_ID not set in .env"
    [ -n "$APPSTORE_API_ISSUER_ID" ] || die "APPSTORE_API_ISSUER_ID not set in .env"
}

# ── Keychain ────────────────────────────────────────────────────────

KEYCHAIN_NAME="revenant-sign.keychain-db"
KEYCHAIN_PASS="revenant-local-build"

setup_keychain() {
    echo "Setting up temporary keychain..."
    security delete-keychain "$KEYCHAIN_NAME" 2>/dev/null || true
    security create-keychain -p "$KEYCHAIN_PASS" "$KEYCHAIN_NAME"
    security set-keychain-settings -lut 900 "$KEYCHAIN_NAME"
    security list-keychains -d user -s "$KEYCHAIN_NAME" $(security list-keychains -d user | tr -d '"')
    security unlock-keychain -p "$KEYCHAIN_PASS" "$KEYCHAIN_NAME"

    echo "$MACOS_CERTIFICATE_BASE64" | base64 -d > /tmp/revenant-cert.p12
    security import /tmp/revenant-cert.p12 -k "$KEYCHAIN_NAME" \
        -P "$MACOS_CERTIFICATE_PASSWORD" \
        -T /usr/bin/codesign -T /usr/bin/productsign
    security set-key-partition-list -S apple-tool:,apple:,codesign: \
        -s -k "$KEYCHAIN_PASS" "$KEYCHAIN_NAME"
    rm -f /tmp/revenant-cert.p12

    # Find the full identity string
    IDENTITY=$(security find-identity -v -p codesigning "$KEYCHAIN_NAME" \
        | grep "Developer ID Application" | head -1 \
        | sed 's/.*"\(.*\)"/\1/')
    [ -n "$IDENTITY" ] || die "No Developer ID Application identity found in keychain"
    echo "Identity: $IDENTITY"
}

cleanup_keychain() {
    security delete-keychain "$KEYCHAIN_NAME" 2>/dev/null || true
}

# ── Sign ────────────────────────────────────────────────────────────

sign_app() {
    [ -d "$APP_PATH" ] || die "App not found at $APP_PATH. Run: python scripts/build.py mac --no-dmg"
    [ -f "$ENTITLEMENTS" ] || die "Entitlements not found at $ENTITLEMENTS"

    echo ""
    echo "=== Signing .so and .dylib files ==="
    find "$APP_PATH/Contents" -type f \( -name '*.so' -o -name '*.dylib' \) | while read -r f; do
        codesign --force --sign "$IDENTITY" --timestamp --options runtime "$f"
    done

    echo "=== Signing Python framework ==="
    local py_framework="$APP_PATH/Contents/Frameworks/Python.framework"
    if [ -d "$py_framework" ]; then
        local py_bin
        py_bin=$(find "$py_framework" -name "Python" -type f | head -1)
        if [ -n "$py_bin" ]; then
            codesign --force --sign "$IDENTITY" --entitlements "$ENTITLEMENTS" \
                --timestamp --options runtime "$py_bin"
            echo "Signed: $py_bin"
        fi
    fi

    echo "=== Signing MacOS/python ==="
    if [ -f "$APP_PATH/Contents/MacOS/python" ]; then
        codesign --force --sign "$IDENTITY" --entitlements "$ENTITLEMENTS" \
            --timestamp --options runtime "$APP_PATH/Contents/MacOS/python"
    fi

    echo "=== Signing main executable ==="
    codesign --force --sign "$IDENTITY" --entitlements "$ENTITLEMENTS" \
        --timestamp --options runtime "$APP_PATH/Contents/MacOS/Revenant"

    echo "=== Signing app bundle ==="
    codesign --force --sign "$IDENTITY" --entitlements "$ENTITLEMENTS" \
        --timestamp --options runtime "$APP_PATH"

    echo "=== Verifying ==="
    codesign --verify --deep --strict "$APP_PATH"
    echo "Signature VALID"
}

# ── DMG ─────────────────────────────────────────────────────────────

create_dmg() {
    echo ""
    echo "=== Creating DMG ==="
    rm -f "$DMG_PATH"
    python "$SCRIPT_DIR/build.py" dmg

    echo "=== Signing DMG ==="
    codesign --force --sign "$IDENTITY" --timestamp "$DMG_PATH"
    codesign --verify --strict "$DMG_PATH"
    echo "DMG signed: $DMG_PATH"
}

# ── Notarize ────────────────────────────────────────────────────────

notarize_dmg() {
    [ -f "$DMG_PATH" ] || die "DMG not found at $DMG_PATH"
    check_notarize_vars

    local api_key="/tmp/revenant-apikey.p8"
    echo "$APPSTORE_API_KEY_BASE64" | base64 -d > "$api_key"

    echo ""
    echo "=== Submitting for notarization ==="
    xcrun notarytool submit "$DMG_PATH" \
        --key "$api_key" \
        --key-id "$APPSTORE_API_KEY_ID" \
        --issuer "$APPSTORE_API_ISSUER_ID" \
        --wait

    echo "=== Stapling ticket ==="
    xcrun stapler staple "$DMG_PATH"

    rm -f "$api_key"
    echo ""
    echo "Notarization complete: $DMG_PATH"
}

# ── Main ────────────────────────────────────────────────────────────

main() {
    local mode="${1:-all}"

    echo "Revenant macOS Sign & Notarize"
    echo "=============================="

    load_env

    trap cleanup_keychain EXIT

    case "$mode" in
        sign)
            setup_keychain
            sign_app
            create_dmg
            echo ""
            echo "Done. DMG is signed but NOT notarized."
            ;;
        notarize)
            notarize_dmg
            ;;
        all)
            setup_keychain
            sign_app
            create_dmg
            notarize_dmg
            echo ""
            echo "Done. DMG is signed and notarized."
            ;;
        *)
            echo "Usage: $0 [sign|notarize|all]"
            exit 1
            ;;
    esac
}

main "$@"
