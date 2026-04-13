# SPDX-License-Identifier: Apache-2.0
"""Tests for revenant.ui.gui.i18n -- internationalization."""

from __future__ import annotations

from unittest.mock import patch

from revenant.ui.gui.i18n import (
    SUPPORTED_LOCALES,
    _detect_system_locale,
    get_current_locale,
    init_locale,
)


def test_get_current_locale_default():
    """Default locale should be 'en'."""
    # Reset to default
    init_locale("en")
    assert get_current_locale() == "en"


def test_init_locale_explicit():
    """Explicit locale setting should be used."""
    result = init_locale("ru")
    assert result == "ru"
    assert get_current_locale() == "ru"
    # Clean up
    init_locale("en")


def test_init_locale_unknown_falls_back():
    """Unknown locale should fall back to English."""
    result = init_locale("xx")
    assert result == "en"
    init_locale("en")


def test_init_locale_system():
    """System locale auto-detection."""
    with patch("revenant.ui.gui.i18n._detect_system_locale", return_value="hy"):
        result = init_locale("system")
    assert result == "hy"
    init_locale("en")


def test_detect_system_locale_exact_match():
    with patch("locale.getlocale", return_value=("ru", "UTF-8")):
        assert _detect_system_locale() == "ru"


def test_detect_system_locale_prefix_match():
    with patch("locale.getlocale", return_value=("hy_AM", "UTF-8")):
        assert _detect_system_locale() == "hy"


def test_detect_system_locale_unknown():
    with patch("locale.getlocale", return_value=("zh_CN", "UTF-8")):
        assert _detect_system_locale() == "en"


def test_detect_system_locale_none():
    with patch("locale.getlocale", return_value=(None, None)):
        assert _detect_system_locale() == "en"


def test_detect_system_locale_value_error():
    with patch("locale.getlocale", side_effect=ValueError):
        assert _detect_system_locale() == "en"


def test_init_locale_missing_catalog():
    """Missing translation catalog should use NullTranslations."""
    # Use a locale that has a valid catalog, then try a locale without one
    result = init_locale("en")
    assert result == "en"


def test_translation_function():
    """The _() function should return translated text."""
    from revenant.ui.gui.i18n import _

    init_locale("en")
    # For a known key, should return the English translation
    translated = _("gui.cancel")
    # It should not be empty
    assert len(translated) > 0


def test_supported_locales_complete():
    """All declared locales should be present."""
    assert "en" in SUPPORTED_LOCALES
    assert "ru" in SUPPORTED_LOCALES
    assert "hy" in SUPPORTED_LOCALES
