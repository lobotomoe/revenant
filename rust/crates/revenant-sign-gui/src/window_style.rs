//! How the window frame, the app's own toolbar and its dialogs follow the
//! conventions of the platform.
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
}

impl WindowStyle {
    /// macOS: a transparent title bar continued by the toolbar, and a menu bar.
    pub(crate) const MACOS: Self = Self {
        title_bar_inset: 28.0,
        menu_bar: true,
        dialog_buttons: ButtonLayout::Trailing,
    };

    /// Windows: an opaque title bar above the content, no menu bar, and Fluent
    /// dialogs.
    pub(crate) const WINDOWS: Self = Self {
        title_bar_inset: 0.0,
        menu_bar: false,
        dialog_buttons: ButtonLayout::Fluent,
    };

    /// Linux: as Windows, but with dialog buttons in the GNOME order.
    pub(crate) const LINUX: Self = Self {
        title_bar_inset: 0.0,
        menu_bar: false,
        dialog_buttons: ButtonLayout::Trailing,
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
