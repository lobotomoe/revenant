"""Core signing and PDF operations."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..errors import RevenantError

if TYPE_CHECKING:
    import types

__all__: list[str] = []


def require_pikepdf() -> types.ModuleType:
    """Lazily import pikepdf to avoid loading the C extension at startup.

    pikepdf is a required dependency; this defers the import for
    startup performance, not optionality.
    """
    try:
        import pikepdf
    except ImportError as exc:
        raise RevenantError(
            "pikepdf is required for this operation.\nInstall with: pip install pikepdf"
        ) from exc
    else:
        return pikepdf
