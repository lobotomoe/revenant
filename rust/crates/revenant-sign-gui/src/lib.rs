//! Revenant desktop GUI: a cross-platform egui/eframe front-end over
//! `revenant-sign-core`.
//!
//! The binary is intentionally thin -- it drives the same signing and
//! verification API the CLI uses, adding a windowed interface, drag-and-drop,
//! and localization. All signing logic lives in the core crate.

mod app;
mod fonts;
mod friendly;
mod i18n;
mod icons;
mod jobs;
#[cfg(target_os = "macos")]
mod macos;
mod reveal;
mod segmented;
mod style;
mod theme;
mod views;
mod window_style;
mod worker;

#[cfg(feature = "store-screenshots")]
pub mod store_screenshots;

use app::RevenantApp;

const INITIAL_SIZE: [f32; 2] = [940.0, 700.0];
const MIN_SIZE: [f32; 2] = [640.0, 480.0];

/// The window/taskbar icon, embedded in the binary. Rendered from the same
/// master (`packaging/icons/revenant.svg`) the app-store bundles use, so the
/// running window matches the installed icon. Covers Windows (taskbar) and
/// Linux (window manager).
///
/// Not compiled on macOS: there the Dock tile is owned by the `.app` bundle's
/// `.icns` (the rounded, beveled artwork macOS expects). eframe forwards a
/// runtime icon straight to `setApplicationIconImage`, which would replace that
/// tile with this flat, square PNG for as long as the app runs.
#[cfg(not(target_os = "macos"))]
const APP_ICON_PNG: &[u8] = include_bytes!("../assets/icon-256.png");

/// Open the main window and run the GUI until it is closed.
///
/// # Errors
///
/// Returns the eframe error when the window or its renderer cannot be created.
pub fn run() -> eframe::Result<()> {
    let viewport = eframe::egui::ViewportBuilder::default()
        .with_inner_size(INITIAL_SIZE)
        .with_min_inner_size(MIN_SIZE)
        .with_title("Revenant")
        .with_app_id("io.github.lobotomoe.revenant");

    // macOS: the content runs under a transparent title bar, so the toolbar
    // below the traffic lights reads as part of it (see `app::chrome`).
    #[cfg(target_os = "macos")]
    let viewport = viewport
        .with_fullsize_content_view(true)
        .with_titlebar_shown(false);

    // Windows (taskbar) and Linux (window manager) take the embedded PNG.
    #[cfg(not(target_os = "macos"))]
    let viewport = {
        // Committed, compile-time-embedded PNG, so a decode failure is a build
        // defect, not a runtime condition -- surface it loudly.
        let icon = eframe::icon_data::from_png_bytes(APP_ICON_PNG)
            .expect("embedded app icon must be a valid PNG");
        viewport.with_icon(icon)
    };

    // macOS keeps the bundle's `.icns` Dock tile -- but leaving the icon unset
    // does not mean "leave it alone": eframe substitutes its own egui logo (a
    // black hexagon) and pushes that through `setApplicationIconImage`, taking
    // over the Dock tile for as long as the app runs. An empty `IconData` is
    // egui's documented opt-out ("if you prefer the OS default").
    #[cfg(target_os = "macos")]
    let viewport = viewport.with_icon(eframe::egui::IconData::default());

    let native_options = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };

    eframe::run_native(
        "Revenant",
        native_options,
        Box::new(|cc| Ok(Box::new(RevenantApp::new(cc)))),
    )
}
