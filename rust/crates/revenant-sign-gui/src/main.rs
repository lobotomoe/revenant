//! Revenant desktop GUI: a cross-platform egui/eframe front-end over
//! `revenant-sign-core`.
//!
//! The binary is intentionally thin -- it drives the same signing and
//! verification API the CLI uses, adding a windowed interface, drag-and-drop,
//! and localization. All signing logic lives in the core crate.

mod app;
mod fonts;
mod i18n;
mod reveal;
mod theme;
mod views;
mod worker;

use app::RevenantApp;

const INITIAL_SIZE: [f32; 2] = [900.0, 640.0];
const MIN_SIZE: [f32; 2] = [640.0, 480.0];

fn main() -> eframe::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let native_options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size(INITIAL_SIZE)
            .with_min_inner_size(MIN_SIZE)
            .with_title("Revenant")
            .with_app_id("io.github.lobotomoe.revenant"),
        ..Default::default()
    };

    eframe::run_native(
        "Revenant",
        native_options,
        Box::new(|cc| Ok(Box::new(RevenantApp::new(cc)))),
    )
}
