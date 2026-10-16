//! First pass: render the app's window contents for one shot.

use eframe::egui;
use egui_kittest::Harness;
use image::RgbaImage;
use revenant_sign_core::config::ConfigStore;

use super::listing::WINDOW_SIZE;
use super::ScreenshotError;
use crate::app::stage::Stage;
use crate::app::RevenantApp;
use crate::window_style::WindowStyle;

/// Render the app, staged at `stage` over `store`, at the shots' window size.
///
/// `pixels_per_point` is chosen by the caller so the result lands on the final
/// canvas at 1:1 -- text is rasterized once, at the size it is shown, instead
/// of being scaled after the fact.
pub(crate) fn render(
    store: ConfigStore,
    stage: Stage,
    window_style: WindowStyle,
    pixels_per_point: f32,
) -> Result<RgbaImage, ScreenshotError> {
    let [width, height] = WINDOW_SIZE;
    let mut harness = Harness::builder()
        .with_size(egui::vec2(width, height))
        .with_pixels_per_point(pixels_per_point)
        .with_theme(egui::Theme::Light)
        .wgpu()
        .build_eframe(|cc| RevenantApp::staged(cc, store, stage, window_style));
    harness
        .try_run()
        .map_err(|err| ScreenshotError::Render(err.to_string()))?;
    harness.render().map_err(ScreenshotError::Render)
}
