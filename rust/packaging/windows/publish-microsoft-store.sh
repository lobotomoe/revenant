#!/usr/bin/env bash
# Submit a release to the Microsoft Store through the Store submission API, or
# report where the latest submission stands.
#
# `publish` creates a submission from the one on sale and fills it in:
#   - the new MSIX in place of the old package;
#   - each listing's screenshots replaced by the set rendered in its language,
#     each with its caption;
#   - each listing's What's New from the AppStream <release> notes in its
#     language;
# then commits it for certification and waits until Partner Center has taken
# the commit. With --dry-run it stops before the commit and deletes the
# submission it made, which exercises every step without touching the Store.
#
# A leftover draft (status PendingCommit) is deleted first, since the API holds
# one pending submission at a time. A submission that is already in
# certification or being published is never touched: the script stops instead.
#
# Usage:
#   publish-microsoft-store.sh publish <msix> <screenshots-dir> <version> [--dry-run]
#   publish-microsoft-store.sh status
#
# <screenshots-dir> is the release's `microsoft-store` directory: one
# subdirectory per listing language (en, ru, hy), each with the PNGs and a
# captions.txt of `file<TAB>caption` lines in upload order.
#
# Needs curl, jq, zip and python3, and MSSTORE_CLIENT_ASSERTION: a token the
# revenant-ci Entra app accepts as a federated credential (in CI, the job's
# GitHub OIDC token for the microsoft-store environment).

set -euo pipefail

TENANT_ID=b91cfdba-8ac2-4da3-a30c-6401e849e14d
CLIENT_ID=aa0979c7-672b-4f5e-af69-34b7bdfae11f
# Store ID of "Revenant Sign" (apps.microsoft.com/detail/9NVH62M20DS3).
APP_ID=9NVH62M20DS3
API="https://manage.devcenter.microsoft.com/v1.0/my/applications/$APP_ID"
METAINFO="$(dirname "$0")/../linux/io.github.lobotomoe.revenant.metainfo.xml"
PACKAGE_NAME=RevenantSign.msix
# How long to wait for Partner Center to accept a commit, in 10 s polls.
COMMIT_POLLS=60

usage() {
	echo "usage: publish-microsoft-store.sh publish <msix> <screenshots-dir> <version> [--dry-run]" >&2
	echo "       publish-microsoft-store.sh status" >&2
	exit 2
}

# An access token for the Store API, from the federated credential.
sign_in() {
	: "${MSSTORE_CLIENT_ASSERTION:?MSSTORE_CLIENT_ASSERTION is not set}"
	TOKEN="$(curl -fsS "https://login.microsoftonline.com/$TENANT_ID/oauth2/v2.0/token" \
		--data-urlencode grant_type=client_credentials \
		--data-urlencode "client_id=$CLIENT_ID" \
		--data-urlencode "scope=https://manage.devcenter.microsoft.com/.default" \
		--data-urlencode client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer \
		--data-urlencode "client_assertion=$MSSTORE_CLIENT_ASSERTION" |
		jq -er '.access_token')"
	if [ -n "${GITHUB_ACTIONS:-}" ]; then
		echo "::add-mask::$TOKEN"
	fi
}

# api <method> <path> [curl args...]: call the Store API, print the response
# body. A failed call prints the API's error body and exits.
api() {
	local method="$1" path="$2"
	shift 2
	local body status
	body="$(mktemp)"
	status="$(curl -sS -o "$body" -w '%{http_code}' -X "$method" \
		-H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
		"$API$path" "$@")"
	if [ "${status:0:1}" != 2 ]; then
		echo "error: $method $path returned HTTP $status" >&2
		# The error body never carries the upload URL; a submission body would.
		jq 'del(.fileUploadUrl?)' "$body" >&2 2>/dev/null || cat "$body" >&2
		rm -f "$body"
		exit 1
	fi
	cat "$body"
	rm -f "$body"
}

# The submission status with its errors and warnings, without the upload URL.
print_status() {
	jq '{status, statusDetails: {errors: .statusDetails.errors, warnings: .statusDetails.warnings}}'
}

status() {
	sign_in
	local app
	app="$(api GET "")"
	local pending published
	pending="$(jq -r '.pendingApplicationSubmission.id // empty' <<<"$app")"
	published="$(jq -r '.lastPublishedApplicationSubmission.id // empty' <<<"$app")"
	if [ -n "$pending" ]; then
		echo "Pending submission $pending:"
		api GET "/submissions/$pending/status" | print_status
	else
		echo "No pending submission."
	fi
	if [ -n "$published" ]; then
		echo "Last published submission: $published"
	fi
}

# Remove a leftover draft so a new submission can be created. Anything further
# along is someone's release in flight.
clear_pending() {
	local pending state
	pending="$(api GET "" | jq -r '.pendingApplicationSubmission.id // empty')"
	if [ -z "$pending" ]; then
		return
	fi
	state="$(api GET "/submissions/$pending/status" | jq -r '.status')"
	if [ "$state" != PendingCommit ]; then
		echo "error: submission $pending is $state, not a draft; wait for it to finish or cancel it in Partner Center" >&2
		exit 1
	fi
	echo "Deleting the draft submission $pending"
	api DELETE "/submissions/$pending" >/dev/null
}

# What's New for `version` in `lang`, from the metainfo <release> entry. English
# paragraphs carry no xml:lang. A language without notes is an error, not a
# fallback to English: a listing must not show text its readers cannot read.
release_notes() {
	python3 - "$METAINFO" "$1" "$2" <<'EOF'
import sys
import xml.etree.ElementTree as ET

LANG = "{http://www.w3.org/XML/1998/namespace}lang"
path, version, lang = sys.argv[1:]
release = ET.parse(path).find(f"./releases/release[@version='{version}']")
if release is None:
    sys.exit(f"metainfo has no <release version='{version}'>")
paragraphs = [
    " ".join("".join(p.itertext()).split())
    for p in release.iter("p")
    if p.get(LANG, "en") == lang
]
if not paragraphs:
    sys.exit(f"<release version='{version}'> has no notes in '{lang}'")
print("\n\n".join(paragraphs))
EOF
}

publish() {
	local msix="$1" shots="$2" version="$3" dry_run="$4"
	[ -f "$msix" ] || { echo "error: no package at $msix" >&2; exit 1; }
	[ -d "$shots" ] || { echo "error: no screenshots at $shots" >&2; exit 1; }

	sign_in
	clear_pending

	local submission id upload_url
	submission="$(api POST "/submissions")"
	id="$(jq -er '.id' <<<"$submission")"
	upload_url="$(jq -er '.fileUploadUrl' <<<"$submission")"
	if [ -n "${GITHUB_ACTIONS:-}" ]; then
		echo "::add-mask::$upload_url"
	fi
	echo "Created submission $id"

	local work bundle edits
	work="$(mktemp -d)"
	bundle="$work/bundle"
	mkdir -p "$bundle"
	cp "$msix" "$bundle/$PACKAGE_NAME"

	# Per listing: copy its language's shots into the bundle under
	# <lang>/<file> and collect {lang, notes, images} for the JSON edit.
	edits="[]"
	local listing lang dir notes images file caption
	for listing in $(jq -r '.listings | keys[]' <<<"$submission"); do
		lang="${listing%%-*}"
		dir="$shots/$lang"
		if [ ! -f "$dir/captions.txt" ]; then
			echo "error: listing '$listing' has no screenshots in $dir" >&2
			exit 1
		fi
		notes="$(release_notes "$version" "$lang")"
		mkdir -p "$bundle/$lang"
		images="[]"
		while IFS=$'\t' read -r file caption; do
			cp "$dir/$file" "$bundle/$lang/$file"
			images="$(jq -c --arg file "$lang/$file" --arg caption "$caption" \
				'. + [{fileName: $file, fileStatus: "PendingUpload", imageType: "Screenshot", description: $caption}]' \
				<<<"$images")"
		done <"$dir/captions.txt"
		# Partner Center takes at most ten desktop screenshots per listing.
		if [ "$(jq length <<<"$images")" -gt 10 ]; then
			echo "error: more than ten screenshots for '$listing'" >&2
			exit 1
		fi
		edits="$(jq -c --arg listing "$listing" --arg notes "$notes" --argjson images "$images" \
			'. + [{listing: $listing, notes: $notes, images: $images}]' <<<"$edits")"
		echo "Listing $listing: $(jq length <<<"$images") screenshots, notes in '$lang'"
	done

	(cd "$bundle" && zip -qr "$work/upload.zip" .)
	curl -fsS --retry 3 -X PUT -H "x-ms-blob-type: BlockBlob" \
		-T "$work/upload.zip" "$upload_url" >/dev/null
	echo "Uploaded the package and screenshots"

	# Old package and old screenshots out, new ones in. Other image types
	# (logos, promotional art) are left as they are.
	jq --argjson edits "$edits" --arg package "$PACKAGE_NAME" '
		del(.fileUploadUrl)
		| .applicationPackages = (
			[.applicationPackages[] | .fileStatus = "PendingDelete"]
			+ [{fileName: $package, fileStatus: "PendingUpload"}])
		| reduce $edits[] as $edit (.;
			.listings[$edit.listing].baseListing.releaseNotes = $edit.notes
			| .listings[$edit.listing].baseListing.images = (
				[(.listings[$edit.listing].baseListing.images // [])[]
					| if .imageType == "Screenshot" then .fileStatus = "PendingDelete" else . end]
				+ $edit.images))
	' <<<"$submission" >"$work/submission.json"
	api PUT "/submissions/$id" --data-binary "@$work/submission.json" >/dev/null
	echo "Updated submission $id"
	rm -rf "$work"

	if [ "$dry_run" = yes ]; then
		api DELETE "/submissions/$id" >/dev/null
		echo "Dry run: deleted submission $id without committing it"
		return
	fi

	api POST "/submissions/$id/commit" >/dev/null
	echo "Committed submission $id; waiting for Partner Center to take it"
	local poll response state
	for ((poll = 0; poll < COMMIT_POLLS; poll++)); do
		response="$(api GET "/submissions/$id/status")"
		state="$(jq -r '.status' <<<"$response")"
		case "$state" in
		CommitStarted)
			sleep 10
			;;
		CommitFailed)
			echo "error: Partner Center refused the submission:" >&2
			print_status <<<"$response" >&2
			exit 1
			;;
		*)
			echo "Submission $id is $state"
			print_status <<<"$response"
			return
			;;
		esac
	done
	echo "error: submission $id was still CommitStarted after $((COMMIT_POLLS * 10)) s" >&2
	exit 1
}

case "${1:-}" in
publish)
	[ $# -eq 4 ] || [ $# -eq 5 ] || usage
	dry_run=no
	if [ $# -eq 5 ]; then
		[ "$5" = --dry-run ] || usage
		dry_run=yes
	fi
	publish "$2" "$3" "$4" "$dry_run"
	;;
status)
	[ $# -eq 1 ] || usage
	status
	;;
*)
	usage
	;;
esac
