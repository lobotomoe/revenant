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
mod reveal;
mod style;
mod theme;
mod views;
mod worker;

use app::RevenantApp;

const INITIAL_SIZE: [f32; 2] = [940.0, 700.0];
const MIN_SIZE: [f32; 2] = [640.0, 480.0];

/// The window/taskbar icon, embedded in the binary. Rendered from the same
/// master (`packaging/icons/revenant.svg`) the app-store bundles use, so the
/// running window matches the installed icon. On macOS the Dock icon comes from
/// the `.app` bundle's `.icns`; this covers the other platforms and the
/// bare-binary case.
const APP_ICON_PNG: &[u8] = include_bytes!("../assets/icon-256.png");

fn main() -> eframe::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // The icon is a committed, compile-time-embedded PNG, so a decode failure is
    // a build defect, not a runtime condition -- surface it loudly.
    let icon = eframe::icon_data::from_png_bytes(APP_ICON_PNG)
        .expect("embedded app icon must be a valid PNG");

    let native_options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size(INITIAL_SIZE)
            .with_min_inner_size(MIN_SIZE)
            .with_title("Revenant")
            .with_app_id("io.github.lobotomoe.revenant")
            .with_icon(icon),
        ..Default::default()
    };

    eframe::run_native(
        "Revenant",
        native_options,
        Box::new(|cc| Ok(Box::new(RevenantApp::new(cc)))),
    )
}
