#!/usr/bin/env bash
#
# Assemble Revenant.app from a prebuilt `revenant-gui` binary.
#
# The Rust binary is self-contained, so bundling is just: lay out the standard
# .app structure, drop in the binary + icon + privacy manifest, and stamp the
# version into a copy of Info.plist. Signing, DMG, and the MAS .pkg are separate
# steps (sign-app.sh / make-dmg.sh / make-mas-pkg.sh) so this stays runnable
# locally with no certificates.
#
# Usage:
#   bundle-app.sh <binary> <output-dir> [short-version] [build-number]
#
#   binary         path to the built revenant-gui (single-arch or lipo'd universal)
#   output-dir     directory to write Revenant.app into (created if missing)
#   short-version  CFBundleShortVersionString (marketing version); default 0.1.0
#   build-number   CFBundleVersion (must increment per App Store upload); default 1
#
# Prints the path to the assembled bundle.
set -euo pipefail

BINARY="${1:?usage: bundle-app.sh <binary> <output-dir> [short-version] [build-number]}"
OUT_DIR="${2:?missing output directory}"
SHORT_VERSION="${3:-0.1.0}"
BUILD_NUMBER="${4:-1}"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ICONS_DIR="$HERE/../icons"

if [[ ! -f "$BINARY" ]]; then
	echo "error: binary not found: $BINARY" >&2
	exit 1
fi

APP="$OUT_DIR/Revenant.app"
CONTENTS="$APP/Contents"

rm -rf "$APP"
mkdir -p "$CONTENTS/MacOS" "$CONTENTS/Resources"

# Executable.
cp "$BINARY" "$CONTENTS/MacOS/revenant-gui"
chmod +x "$CONTENTS/MacOS/revenant-gui"

# Icon and privacy manifest (required by MAS since May 2024).
cp "$ICONS_DIR/revenant.icns" "$CONTENTS/Resources/revenant.icns"
cp "$HERE/PrivacyInfo.xcprivacy" "$CONTENTS/Resources/PrivacyInfo.xcprivacy"

# Info.plist with the version stamped in.
sed -e "s/__SHORT_VERSION__/$SHORT_VERSION/g" \
	-e "s/__BUILD_NUMBER__/$BUILD_NUMBER/g" \
	"$HERE/Info.plist" >"$CONTENTS/Info.plist"

# Classic four-char package/creator record. py2app writes this; some older
# Finder/LaunchServices paths still consult it.
printf 'APPL????' >"$CONTENTS/PkgInfo"

echo "$APP"
