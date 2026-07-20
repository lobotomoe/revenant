#!/usr/bin/env bash
#
# Stage and (optionally) pack an MSIX for the Microsoft Store from the prebuilt
# Rust binaries. Runs under git-bash on the windows-latest CI runner; the actual
# `makeappx pack` needs the Windows SDK, so on non-Windows hosts this stops after
# staging (useful for verifying the layout).
#
# The Rust binaries reuse the Python client's exe names (revenant-gui.exe /
# revenant.exe), so AppxManifest.xml and the Store identity carry over verbatim;
# only the Version is stamped (M.m.p -> M.m.p.0, the MSIX 4-part form).
#
# Usage:
#   build-msix.sh <gui-exe> <cli-exe> <version> [staging-dir] [output-msix]
#
#   gui-exe / cli-exe  paths to revenant-gui.exe and revenant.exe
#   version            semver M.m.p (from the release tag)
#   staging-dir        where to assemble the package (default: ./msix-staging)
#   output-msix        packed output path (default: <staging>/../RevenantSign.msix)
#
# Prints the staging dir, and the .msix path when packing runs.
set -euo pipefail

GUI_EXE="${1:?usage: build-msix.sh <gui-exe> <cli-exe> <version> [staging] [out.msix]}"
CLI_EXE="${2:?missing revenant.exe path}"
VERSION="${3:?missing version (M.m.p)}"
STAGING="${4:-msix-staging}"
OUTPUT="${5:-}"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"

for exe in "$GUI_EXE" "$CLI_EXE"; do
	[[ -f "$exe" ]] || { echo "error: binary not found: $exe" >&2; exit 1; }
done

# MSIX requires a purely numeric 4-part version, and the Store requires the
# revision (4th) part to be 0. Map the semver M.m.p to M.m.p.0. A prerelease tag
# (v2.1.0-rc.1) has no MSIX equivalent -- MSIX has no prerelease concept and the
# suffix is non-numeric -- so strip it: 2.1.0-rc.1 -> 2.1.0.0. (Distinct
# prereleases would collide, but MSIX/Store prereleases are not a workflow here.)
MSIX_VERSION="${VERSION%%-*}.0"

rm -rf "$STAGING"
mkdir -p "$STAGING/Assets"

cp "$GUI_EXE" "$STAGING/revenant-gui.exe"
cp "$CLI_EXE" "$STAGING/revenant.exe"
cp "$HERE/Assets/"*.png "$STAGING/Assets/"
cp "$REPO_ROOT/../LICENSE" "$STAGING/LICENSE" 2>/dev/null || cp "$REPO_ROOT/LICENSE" "$STAGING/LICENSE"

# Stamp the version into the Identity element only. The anchored pattern (start
# of line + indentation + Version=) avoids matching MinVersion/MaxVersionTested,
# which contain "Version=" as a substring.
sed -E "s/^([[:space:]]*)Version=\"[0-9.]+\"/\1Version=\"$MSIX_VERSION\"/" \
	"$HERE/AppxManifest.xml" >"$STAGING/AppxManifest.xml"

echo "staged: $STAGING (version $MSIX_VERSION)"

# Pack only when makeappx is available (Windows SDK). MAKEAPPX may override the
# discovered path.
MAKEAPPX="${MAKEAPPX:-}"
if [[ -z "$MAKEAPPX" ]] && command -v makeappx.exe >/dev/null 2>&1; then
	MAKEAPPX="$(command -v makeappx.exe)"
fi
if [[ -z "$MAKEAPPX" ]]; then
	echo "makeappx not found; stopped after staging (set MAKEAPPX or run on Windows)." >&2
	exit 0
fi

OUTPUT="${OUTPUT:-$(dirname "$STAGING")/RevenantSign.msix}"
# git-bash (MSYS) rewrites arguments that look like Unix paths, turning the
# makeappx flags /d and /p into drive paths ("D:/", "P:/") -- makeappx then
# rejects them as unknown options. Disable that conversion for this call; the
# path arguments are relative, so none of them need rewriting.
MSYS2_ARG_CONV_EXCL='*' MSYS_NO_PATHCONV=1 "$MAKEAPPX" pack /d "$STAGING" /p "$OUTPUT" /overwrite
echo "packed: $OUTPUT"
