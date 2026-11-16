#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bump one pinned package in the hashed lockfiles under .github/requirements.

Regenerating a lockfile resolves for the machine it runs on, so doing it on
macOS drops the Linux-only keyring backends and breaks Linux CI. This replaces
a single ``name==version`` block instead and writes every sha256 PyPI lists for
the new version, which keeps the file valid on every platform.

Usage:
    python scripts/bump_requirement_pin.py certifi 2026.10.18 ../.github/requirements/audit.txt

    # The new version dropped a Python the project still tests on: keep the
    # old pin there and add the new one beside it.
    python scripts/bump_requirement_pin.py pillow 13.0.0 ../.github/requirements/dev.txt \\
        --keep-old-when 'python_version < "3.11"' --new-when 'python_version >= "3.11"'

    # The file already holds one block per marker: name the one to bump.
    python scripts/bump_requirement_pin.py pillow 13.0.1 ../.github/requirements/dev.txt \\
        --only-marker 'python_version >= "3.11"'
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

PYPI_RELEASE_URL = "https://pypi.org/pypi/{package}/{version}/json"
PYPI_TIMEOUT_SECONDS = 30
HTTP_NOT_FOUND = 404

# What PyPI accepts in a project name and what PEP 440 allows in a version.
# Checked before either is put into a URL.
_PACKAGE_NAME = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?")
_VERSION = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9.!+_-]*[A-Za-z0-9])?")

_BLOCK = re.compile(
    r"^(?P<name>[A-Za-z0-9._-]+)(?P<extras>\[[^\]\n]*\])?==(?P<version>[^ ;\\\n]+)(?: ; (?P<marker>[^\\\n]+?))? \\\n"
    r"(?P<hashes>(?:    --hash=sha256:[0-9a-f]{64}(?: \\)?\n)+)"
    r"(?P<trailer>(?:    #[^\n]*\n)*)",
    re.MULTILINE,
)
_HASH = re.compile(r"sha256:([0-9a-f]{64})")


class PinError(Exception):
    """The lockfile or the request does not allow the bump."""


@dataclass(frozen=True)
class Split:
    """Keep the old pin under one marker and add the new one under another."""

    keep_old_when: str
    new_when: str


def normalize_name(name: str) -> str:
    """Return the PEP 503 form of a project name, the one names compare by."""
    return re.sub(r"[-_.]+", "-", name).lower()


def fetch_sha256_digests(package: str, version: str) -> list[str]:
    """Return the sha256 of every file PyPI lists for a release, sorted.

    Raises:
        PinError: If PyPI has no such release, cannot be reached, or lists no
            files for it.
    """
    url = PYPI_RELEASE_URL.format(package=package, version=version)
    try:
        with urllib.request.urlopen(url, timeout=PYPI_TIMEOUT_SECONDS) as response:
            release = json.load(response)
    except urllib.error.HTTPError as error:
        if error.code == HTTP_NOT_FOUND:
            raise PinError(f"PyPI has no release {package} {version}.") from error
        raise PinError(f"PyPI answered {error.code} for {package} {version}.") from error
    except urllib.error.URLError as error:
        raise PinError(f"Could not reach PyPI: {error.reason}") from error
    digests = sorted(str(file["digests"]["sha256"]) for file in release["urls"])
    if not digests:
        raise PinError(f"PyPI lists no files for {package} {version}.")
    return digests


def _render_block(
    name: str, version: str, marker: str | None, digests: Sequence[str], trailer: str
) -> str:
    header = f"{name}=={version}"
    if marker:
        header += f" ; {marker}"
    lines = [f"{header} \\"]
    lines += [f"    --hash=sha256:{digest} \\" for digest in digests]
    lines[-1] = lines[-1].removesuffix(" \\")
    return "\n".join(lines) + "\n" + trailer


def _select_block(text: str, package: str, only_marker: str | None) -> re.Match[str]:
    wanted = normalize_name(package)
    blocks = [m for m in _BLOCK.finditer(text) if normalize_name(m["name"]) == wanted]
    if not blocks:
        raise PinError(f"No pinned block for {package}.")
    if only_marker is not None:
        blocks = [m for m in blocks if m["marker"] == only_marker]
        if not blocks:
            raise PinError(f"No {package} block carries the marker {only_marker!r}.")
    if len(blocks) > 1:
        markers = ", ".join(repr(m["marker"]) for m in blocks)
        raise PinError(
            f"{len(blocks)} blocks pin {package} (markers: {markers}). Name one with --only-marker."
        )
    return blocks[0]


def replace_pin(
    text: str,
    package: str,
    version: str,
    digests: Sequence[str],
    *,
    only_marker: str | None = None,
    split: Split | None = None,
) -> tuple[str, str]:
    """Replace the block that pins ``package`` in the text of a lockfile.

    The ``# via`` comment under the block is kept, as is the block's marker.

    Args:
        text: Contents of the lockfile.
        package: Project to bump; compared by normalized name.
        version: Version to pin.
        digests: sha256 digests of the new version's files.
        only_marker: Marker of the block to bump, when several pin the package.
        split: Keep the old pin and add the new one, each under its own marker.

    Returns:
        The new contents and the version that was pinned before.

    Raises:
        PinError: If no block, or more than one, matches, or if a split is
            asked of a block that already has a marker.
    """
    if not digests:
        raise PinError(f"No hashes given for {package} {version}.")
    block = _select_block(text, package, only_marker)
    # Extras are part of how the requirement is written, not of the project
    # that PyPI is asked about.
    name = block["name"] + (block["extras"] or "")
    old_version, trailer = block["version"], block["trailer"]

    if split is None:
        replacement = _render_block(name, version, block["marker"], digests, trailer)
    else:
        if block["marker"]:
            raise PinError(
                f"The {package} block already has the marker {block['marker']!r}; "
                "it cannot be split again."
            )
        old_digests = _HASH.findall(block["hashes"])
        kept = _render_block(name, old_version, split.keep_old_when, old_digests, trailer)
        added = _render_block(name, version, split.new_when, digests, trailer)
        replacement = kept + added

    return text[: block.start()] + replacement + text[block.end() :], old_version


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Bump one pinned package in hashed requirements lockfiles."
    )
    parser.add_argument("package", help="project name as on PyPI")
    parser.add_argument("version", help="version to pin")
    parser.add_argument("lockfiles", nargs="+", type=Path, help="lockfiles to edit")
    parser.add_argument("--only-marker", help="marker of the block to bump")
    parser.add_argument("--keep-old-when", help="marker under which the old pin stays")
    parser.add_argument("--new-when", help="marker under which the new pin applies")
    args = parser.parse_args(argv)
    if (args.keep_old_when is None) != (args.new_when is None):
        parser.error("--keep-old-when and --new-when go together")
    if args.keep_old_when is not None and args.only_marker is not None:
        parser.error("--only-marker cannot be combined with a split")
    if not _PACKAGE_NAME.fullmatch(args.package):
        parser.error(f"not a project name: {args.package!r}")
    if not _VERSION.fullmatch(args.version):
        parser.error(f"not a version: {args.version!r}")
    return args


def main(
    argv: Sequence[str] | None = None,
    fetch_digests: Callable[[str, str], list[str]] = fetch_sha256_digests,
) -> int:
    """Bump the pin in every lockfile given, or change none of them."""
    args = _parse_args(argv)
    split = None
    if args.keep_old_when is not None:
        split = Split(keep_old_when=args.keep_old_when, new_when=args.new_when)

    try:
        digests = fetch_digests(args.package, args.version)
        # Work out every file first, so a lockfile that cannot be bumped stops
        # the run before any other has been written.
        pending: list[tuple[Path, str, str]] = []
        for lockfile in args.lockfiles:
            text = lockfile.read_text(encoding="utf-8")
            new_text, old_version = replace_pin(
                text,
                args.package,
                args.version,
                digests,
                only_marker=args.only_marker,
                split=split,
            )
            pending.append((lockfile, new_text, old_version))
    except PinError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1

    for lockfile, new_text, old_version in pending:
        lockfile.write_text(new_text, encoding="utf-8")
        print(f"{lockfile.name}: {args.package} {old_version} -> {args.version}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
