# SPDX-License-Identifier: Apache-2.0
"""Internationalization support for the Revenant GUI.

Uses Python's gettext module with .po/.mo translation catalogs.
No fallbacks -- every string must be translated for non-English locales.

Usage in GUI modules::

    from .i18n import _

    label = ttk.Label(frame, text=_("Username:"))
"""

from __future__ import annotations

import gettext
import locale
import logging
from pathlib import Path

_logger = logging.getLogger(__name__)

# Supported locales: code -> display name (in that language)
SUPPORTED_LOCALES: dict[str, str] = {
    "en": "English",
    "ru": "\u0420\u0443\u0441\u0441\u043a\u0438\u0439",
    "hy": "\u0540\u0561\u0575\u0565\u0580\u0565\u0576",
}

SYSTEM_LOCALE = "system"

_LOCALES_DIR = Path(__file__).parent / "locales"
_DOMAIN = "revenant"

# Module-level translator -- initialized once at startup
_current_locale: str = "en"
_translator: gettext.GNUTranslations | gettext.NullTranslations = gettext.NullTranslations()


def get_current_locale() -> str:
    """Return the active locale code (e.g. 'en', 'ru', 'hy')."""
    return _current_locale


def _detect_system_locale() -> str:
    """Detect OS locale and map to a supported locale code."""
    try:
        # locale.getlocale() returns (language_code, encoding) or (None, None)
        os_locale = locale.getlocale()[0] or ""
    except ValueError:
        os_locale = ""

    # Try exact match first (e.g. "ru_RU"), then language prefix (e.g. "ru")
    if os_locale in SUPPORTED_LOCALES:
        return os_locale
    lang = os_locale.split("_")[0]
    if lang in SUPPORTED_LOCALES:
        return lang
    return "en"


def init_locale(language_setting: str = SYSTEM_LOCALE) -> str:
    """Initialize the translation system.

    Args:
        language_setting: A locale code ('en', 'ru', 'hy') or 'system'
            to auto-detect from OS.

    Returns:
        The resolved locale code that was activated.
    """
    global _current_locale, _translator

    if language_setting == SYSTEM_LOCALE:
        resolved = _detect_system_locale()
    elif language_setting in SUPPORTED_LOCALES:
        resolved = language_setting
    else:
        _logger.warning("Unknown locale '%s', falling back to English", language_setting)
        resolved = "en"

    _current_locale = resolved

    if resolved == "en":
        _translator = gettext.NullTranslations()
    else:
        try:
            _translator = gettext.translation(
                _DOMAIN,
                localedir=str(_LOCALES_DIR),
                languages=[resolved],
            )
        except FileNotFoundError:
            _logger.exception(
                "Translation catalog not found for '%s' in %s", resolved, _LOCALES_DIR
            )
            raise

    _logger.info("Locale initialized: %s (setting=%s)", resolved, language_setting)
    return resolved


def _(message: str) -> str:
    """Translate a string using the active locale."""
    return _translator.gettext(message)
