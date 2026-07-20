#!/usr/bin/env bash
#
# Assemble an AppDir from the prebuilt revenant-gui binary and pack it into an
# AppImage. The AppDir layout (and all metadata) is reused verbatim from the
# Python client -- only the binary source changes; the Rust binary is
# self-contained so there are no bundled interpreter/Tcl libraries to carry.
#
# `appimagetool` is Linux-only, so on other hosts this stops after staging the
# AppDir (useful for verifying the layout). Provide the tool via $APPIMAGETOOL or
# on PATH; CI installs it.
#
# Usage:
#   build-appimage.sh <gui-binary> <output-dir> [version] [arch]
#
#   gui-binary   path to the built revenant-gui
#   output-dir   where to write the AppDir and the .AppImage
#   version      marketing version, embedded in the output name (default 0.1.0)
#   arch         x86_64 (default) or aarch64 -- must match the binary
#
# Prints the AppDir path, and the .AppImage path when packing runs.
set -euo pipefail

BINARY="${1:?usage: build-appimage.sh <gui-binary> <output-dir> [version] [arch]}"
OUT_DIR="${2:?missing output directory}"
VERSION="${3:-0.1.0}"
ARCH="${4:-x86_64}"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_ID="io.github.lobotomoe.revenant"

[[ -f "$BINARY" ]] || { echo "error: binary not found: $BINARY" >&2; exit 1; }

APPDIR="$OUT_DIR/AppDir"
rm -rf "$APPDIR"
mkdir -p "$APPDIR/usr/bin" \
	"$APPDIR/usr/share/icons/hicolor/256x256/apps" \
	"$APPDIR/usr/share/metainfo"

# Binary + entry point.
cp "$BINARY" "$APPDIR/usr/bin/revenant-gui"
chmod +x "$APPDIR/usr/bin/revenant-gui"
cp "$HERE/AppRun" "$APPDIR/AppRun"
chmod +x "$APPDIR/AppRun"

# Desktop entry (AppDir root, where appimagetool looks for it).
cp "$HERE/$APP_ID.desktop" "$APPDIR/$APP_ID.desktop"

# Icon: at the AppDir root, in the hicolor theme, and as the .DirIcon thumbnail.
cp "$HERE/$APP_ID.png" "$APPDIR/$APP_ID.png"
cp "$HERE/$APP_ID.png" "$APPDIR/usr/share/icons/hicolor/256x256/apps/$APP_ID.png"
ln -sf "$APP_ID.png" "$APPDIR/.DirIcon"

# AppStream metadata (installed as .appdata.xml, the name appimagetool expects).
cp "$HERE/$APP_ID.metainfo.xml" "$APPDIR/usr/share/metainfo/$APP_ID.appdata.xml"

echo "staged: $APPDIR"

# Pack only when appimagetool is available.
APPIMAGETOOL="${APPIMAGETOOL:-}"
if [[ -z "$APPIMAGETOOL" ]] && command -v appimagetool >/dev/null 2>&1; then
	APPIMAGETOOL="$(command -v appimagetool)"
fi
if [[ -z "$APPIMAGETOOL" ]]; then
	echo "appimagetool not found; stopped after staging (set APPIMAGETOOL or run on Linux)." >&2
	exit 0
fi

OUTPUT="$OUT_DIR/Revenant-$ARCH.AppImage"
ARCH="$ARCH" "$APPIMAGETOOL" "$APPDIR" "$OUTPUT"
echo "packed: $OUTPUT"
