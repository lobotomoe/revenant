//! How the window frame, the app's own toolbar, its dialogs and its text sizes
//! follow the conventions of the platform.
//!
//! A field of the app rather than a `cfg`, because the store screenshots render
//! every platform's look from one build.

use crate::dialog::ButtonLayout;

/// The parts of the platform's look the app has to account for.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct WindowStyle {
    /// Height of a transparent title bar the content runs under, which the
    /// toolbar leaves clear for the traffic lights and the window title.
    pub(crate) title_bar_inset: f32,
    /// Settings and About are in the system menu bar, not in the toolbar.
    pub(crate) menu_bar: bool,
    /// How dialogs order and size their buttons.
    pub(crate) dialog_buttons: ButtonLayout,
    /// The type scale, in points.
    pub(crate) text: TextSizes,
}

/// The sizes of the app's text styles, in points.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct TextSizes {
    pub(crate) heading: f32,
    pub(crate) body: f32,
    pub(crate) small: f32,
    pub(crate) monospace: f32,
}

impl TextSizes {
    /// The macOS scale: 13 pt body and controls, 11 pt for secondary text,
    /// 17 pt for a view's title (Apple's "title 2").
    const MACOS: Self = Self {
        heading: 17.0,
        body: 13.0,
        small: 11.0,
        monospace: 12.0,
    };

    /// The Fluent scale Windows and GNOME are close to: 14 body, 12 caption,
    /// 20 subtitle.
    const FLUENT: Self = Self {
        heading: 20.0,
        body: 14.0,
        small: 12.0,
        monospace: 13.0,
    };
}

impl WindowStyle {
    /// macOS: a transparent title bar continued by the toolbar, and a menu bar.
    pub(crate) const MACOS: Self = Self {
        title_bar_inset: 28.0,
        menu_bar: true,
        dialog_buttons: ButtonLayout::Trailing,
        text: TextSizes::MACOS,
    };

    /// Windows: an opaque title bar above the content, no menu bar, and Fluent
    /// dialogs.
    pub(crate) const WINDOWS: Self = Self {
        title_bar_inset: 0.0,
        menu_bar: false,
        dialog_buttons: ButtonLayout::Fluent,
        text: TextSizes::FLUENT,
    };

    /// Linux: as Windows, but with dialog buttons in the GNOME order.
    pub(crate) const LINUX: Self = Self {
        title_bar_inset: 0.0,
        menu_bar: false,
        dialog_buttons: ButtonLayout::Trailing,
        text: TextSizes::FLUENT,
    };

    /// The style of the platform this build runs on.
    pub(crate) fn native() -> Self {
        if cfg!(target_os = "macos") {
            Self::MACOS
        } else if cfg!(target_os = "windows") {
            Self::WINDOWS
        } else {
            Self::LINUX
        }
    }
}
