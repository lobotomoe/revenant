#!/usr/bin/env bash
# Prepare a Mac App Store release in App Store Connect: upload the signed .pkg,
# create the App Store version, attach the build and replace the screenshots in
# every localization of that version.
#
# It stops short of submitting for review. What's New is required in each
# localization and is written by hand in App Store Connect, followed by the
# Submit for Review click.
#
# Safe to re-run. An upload that already reached App Store Connect is not
# repeated (the store refuses a second upload of the same build number), and an
# existing version is reused.
#
# Usage:
#   publish-app-store.sh <pkg> <screenshots-dir> <version> <build-number>
#
# Needs the asc CLI (github.com/rorkai/App-Store-Connect-CLI) and jq, with
# ASC_APP_ID, ASC_KEY_ID, ASC_ISSUER_ID and ASC_PRIVATE_KEY_B64 (or
# ASC_PRIVATE_KEY_PATH) in the environment.

set -euo pipefail

PKG="${1:?usage: publish-app-store.sh <pkg> <screenshots-dir> <version> <build-number>}"
SCREENSHOTS_DIR="${2:?usage: publish-app-store.sh <pkg> <screenshots-dir> <version> <build-number>}"
VERSION="${3:?usage: publish-app-store.sh <pkg> <screenshots-dir> <version> <build-number>}"
BUILD_NUMBER="${4:?usage: publish-app-store.sh <pkg> <screenshots-dir> <version> <build-number>}"
ASC="${ASC:-asc}"

PLATFORM=MAC_OS
SCREENSHOT_DISPLAY_TYPE=APP_DESKTOP
# The states in which a version's build, metadata and screenshots can still be
# changed. Anything else (waiting for or in review, released) is not ours to
# touch from a pipeline.
EDITABLE_STATES="PREPARE_FOR_SUBMISSION DEVELOPER_REJECTED REJECTED METADATA_REJECTED INVALID_BINARY"

find_build() {
	"$ASC" builds list --version "$VERSION" --build-number "$BUILD_NUMBER" \
		--platform "$PLATFORM" --processing-state all --output json |
		jq -c '.data[0] // empty'
}

build="$(find_build)"
if [ -z "$build" ]; then
	echo "Uploading $PKG as $VERSION ($BUILD_NUMBER)"
	"$ASC" builds upload --pkg "$PKG" --version "$VERSION" --build-number "$BUILD_NUMBER" \
		--platform "$PLATFORM" --wait --output json >/dev/null
	build="$(find_build)"
	if [ -z "$build" ]; then
		echo "::error::the upload finished but App Store Connect lists no build $VERSION ($BUILD_NUMBER)"
		exit 1
	fi
else
	echo "Build $VERSION ($BUILD_NUMBER) is already in App Store Connect"
fi
build_id="$(jq -r '.id' <<<"$build")"
build_state="$(jq -r '.attributes.processingState' <<<"$build")"
if [ "$build_state" != "VALID" ]; then
	echo "::error::build $VERSION ($BUILD_NUMBER) is $build_state, not VALID; re-run once App Store Connect has processed it"
	exit 1
fi

# App Store Connect allows one editable version at a time. One left over from an
# earlier release, prepared but never submitted or rejected in review, becomes
# this release: it keeps its listing text and What's New, and gets this build.
stale_version="$("$ASC" versions list --platform "$PLATFORM" --state "${EDITABLE_STATES// /,}" \
	--output json | jq -c --arg version "$VERSION" '[.data[] | select(.attributes.versionString != $version)][0] // empty')"
if [ -n "$stale_version" ]; then
	stale_id="$(jq -r '.id' <<<"$stale_version")"
	stale_string="$(jq -r '.attributes.versionString' <<<"$stale_version")"
	echo "Renaming the unreleased App Store version $stale_string to $VERSION"
	"$ASC" versions update --version-id "$stale_id" --version "$VERSION" --output json >/dev/null
fi

# A new version starts from the listing text of the one on sale. What's New is
# left out: it describes the previous release.
live_version="$("$ASC" versions list --platform "$PLATFORM" --state READY_FOR_DISTRIBUTION \
	--paginate --output json | jq -r '.data | max_by(.attributes.createdDate) | .attributes.versionString')"
if [ "$live_version" = "null" ]; then
	echo "::error::App Store Connect lists no version on sale to copy the listing text from"
	exit 1
fi
"$ASC" versions create --version "$VERSION" --platform "$PLATFORM" --if-exists skip \
	--copy-metadata-from "$live_version" --exclude-fields whatsNew --output json >/dev/null

version="$("$ASC" versions list --version "$VERSION" --platform "$PLATFORM" --output json |
	jq -c '.data[0]')"
version_id="$(jq -r '.id' <<<"$version")"
version_state="$(jq -r '.attributes.appVersionState' <<<"$version")"
if [[ " $EDITABLE_STATES " != *" $version_state "* ]]; then
	echo "::error::App Store version $VERSION is $version_state and can no longer be changed"
	exit 1
fi

echo "Attaching build $BUILD_NUMBER to version $VERSION"
"$ASC" versions attach-build --version-id "$version_id" --build-id "$build_id" --output json >/dev/null

# The screenshots are rendered in English only, so every localization gets the
# same set. Without this the other localizations would keep the screenshots
# copied over from the previous version.
localizations="$("$ASC" localizations list --version "$version_id" --output json |
	jq -r '.data[] | "\(.id) \(.attributes.locale)"')"
while read -r localization_id locale; do
	echo "Replacing the $locale screenshots"
	"$ASC" screenshots upload --version-localization "$localization_id" --path "$SCREENSHOTS_DIR" \
		--device-type "$SCREENSHOT_DISPLAY_TYPE" --replace --confirm --output json >/dev/null
done <<<"$localizations"

echo "Version $VERSION is ready in App Store Connect. Add What's New and submit it for review there."
