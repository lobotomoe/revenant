#!/usr/bin/env bash
#
# Build a Developer-ID distribution DMG from a (already signed) Revenant.app,
# using the branded background. Falls back to a plain hdiutil image if
# create-dmg is unavailable. The resulting DMG is signed + notarized by the
# caller (CI), not here.
#
# Usage: make-dmg.sh <app> <output.dmg>
set -euo pipefail

APP="${1:?usage: make-dmg.sh <app> <output.dmg>}"
OUT="${2:?missing output .dmg path}"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKGROUND="$HERE/dmg-background.png"
APP_NAME="$(basename "$APP")"

[[ -d "$APP" ]] || { echo "error: app not found: $APP" >&2; exit 1; }

rm -f "$OUT"

if command -v create-dmg >/dev/null 2>&1; then
	# Window/icon geometry matches the 660x400 background art (app on the left,
	# the Applications drop target on the right).
	create-dmg \
		--volname "Revenant" \
		--background "$BACKGROUND" \
		--window-pos 200 120 \
		--window-size 660 400 \
		--icon-size 100 \
		--icon "$APP_NAME" 180 200 \
		--hide-extension "$APP_NAME" \
		--app-drop-link 480 200 \
		--hdiutil-quiet \
		"$OUT" "$APP" && { echo "$OUT"; exit 0; }
	echo "create-dmg failed; falling back to a plain hdiutil image" >&2
fi

hdiutil create -volname "Revenant" -srcfolder "$APP" -ov -format UDZO "$OUT"
echo "$OUT"
