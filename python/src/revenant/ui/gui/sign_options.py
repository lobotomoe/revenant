# SPDX-License-Identifier: Apache-2.0
"""Signing options dataclass -- bundles user-chosen signing parameters."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class SignOptions:
    """User-chosen signing parameters, shared across batch operations.

    Pure data container -- no UI references, no I/O.
    Constructed in app.py from form StringVars, consumed by sign_worker.py.
    """

    signing_mode: str  # "embedded" | "detached"
    position: str  # position preset name
    page: str  # raw page string: "last", "first", or digit
    font_key: str  # font registry key
    invisible: bool  # True = invisible signature
    reason: str  # signature reason text (empty -> default)
    image_path: str  # optional stamp image path (empty = none)
    signer_name: str | None  # display name for signature field
