#!/usr/bin/env bash
#
# Regenerate revenant.icns (macOS app icon) from revenant-macos.svg -- the
# rounded, padded macOS-grid variant of the master. The Python repo had no
# icon-generation step (all derivatives were committed by hand); this makes the
# macOS icon reproducible.
#
# Requires: rsvg-convert (librsvg) + iconutil (macOS). Run on macOS.
#
# Usage: make-icns.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SVG="$HERE/revenant-macos.svg"
OUT="$HERE/revenant.icns"

command -v rsvg-convert >/dev/null || { echo "error: rsvg-convert not found (brew install librsvg)" >&2; exit 1; }
command -v iconutil >/dev/null || { echo "error: iconutil not found (macOS only)" >&2; exit 1; }

WORK="$(mktemp -d)"
ICONSET="$WORK/revenant.iconset"
mkdir -p "$ICONSET"
trap 'rm -rf "$WORK"' EXIT

# iconutil expects the standard 1x/2x pairs from 16 up to 512.
for size in 16 32 128 256 512; do
	rsvg-convert -w "$size" -h "$size" "$SVG" -o "$ICONSET/icon_${size}x${size}.png"
	rsvg-convert -w "$((size * 2))" -h "$((size * 2))" "$SVG" -o "$ICONSET/icon_${size}x${size}@2x.png"
done

iconutil -c icns "$ICONSET" -o "$OUT"
echo "wrote $OUT"
