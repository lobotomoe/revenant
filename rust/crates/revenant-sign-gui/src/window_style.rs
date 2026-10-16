//! How the window frame and the app's own toolbar share the top of the window.
//!
//! A field of the app rather than a `cfg`, because the store screenshots render
//! every platform's look from one build.

/// The parts of the window frame the toolbar has to account for.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct WindowStyle {
    /// Height of a transparent title bar the content runs under, which the
    /// toolbar leaves clear for the traffic lights and the window title.
    pub(crate) title_bar_inset: f32,
    /// Settings and About are in the system menu bar, not in the toolbar.
    pub(crate) menu_bar: bool,
}

impl WindowStyle {
    /// macOS: a transparent title bar continued by the toolbar, and a menu bar.
    pub(crate) const MACOS: Self = Self {
        title_bar_inset: 28.0,
        menu_bar: true,
    };

    /// Windows and Linux: an opaque title bar above the content, no menu bar.
    pub(crate) const OTHER: Self = Self {
        title_bar_inset: 0.0,
        menu_bar: false,
    };

    /// The style of the platform this build runs on.
    pub(crate) fn native() -> Self {
        if cfg!(target_os = "macos") {
            Self::MACOS
        } else {
            Self::OTHER
        }
    }
}
