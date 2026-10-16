//! Second pass: frame a rendered window on the store's canvas.
//!
//! The frame is itself drawn with egui at one pixel per point, so every
//! coordinate here is a canvas pixel and the window image is placed 1:1.

use std::sync::Arc;

use eframe::egui::{
    self, epaint::Shadow, pos2, vec2, Align2, Color32, ColorImage, CornerRadius, FontData,
    FontDefinitions, FontFamily, FontId, Rect, Stroke, StrokeKind, TextureHandle, TextureOptions,
};
use egui_kittest::Harness;
use image::RgbaImage;

use super::listing::{Chrome, CopyPlacement, Shot, Store, WINDOW_SIZE};
use super::{backdrop, chrome, ScreenshotError};

/// Font family name for the bold face used by headlines and some titles.
pub(crate) const BOLD_FAMILY: &str = "bold";

const HEADLINE: Color32 = Color32::WHITE;
const SUBLINE: Color32 = Color32::from_rgb(0xC9, 0xC3, 0xC4);

/// Where things go on one store's canvas, all in canvas pixels.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Layout {
    canvas: Rect,
    chrome: Chrome,
    /// Canvas pixels per app point.
    scale: f32,
    /// The whole window, title bar included.
    window: Rect,
    /// Whether the headline and subline are drawn above the window.
    copy_on_image: bool,
    headline_top: f32,
    headline_size: f32,
    subline_size: f32,
}

impl Layout {
    pub(crate) fn for_store(store: Store) -> Self {
        let [width, height] = store.canvas().map(f32::from);
        let chrome = store.chrome();
        let canvas = Rect::from_min_size(pos2(0.0, 0.0), vec2(width, height));

        // With copy on the image, the headline block takes the top quarter and
        // the window fills the rest down to a small bottom margin. Without it,
        // the window is centered with an even margin.
        let copy_on_image = store.copy() == CopyPlacement::OnImage;
        let (window_top, window_bottom) = if copy_on_image {
            (height * 0.255, height * 0.965)
        } else {
            (height * 0.06, height * 0.94)
        };
        let [app_width, app_height] = WINDOW_SIZE;
        let bar_above_content = if chrome.title_bar_overlays_content() {
            0.0
        } else {
            chrome.title_bar_height()
        };
        let window_points = vec2(app_width, app_height + bar_above_content);
        let scale = (window_bottom - window_top) / window_points.y;
        let window_size = window_points * scale;
        // Whole-pixel origin so the window image maps onto pixels exactly.
        let window_min = pos2(((width - window_size.x) / 2.0).round(), window_top.round());
        let window = Rect::from_min_size(window_min, window_size);

        Layout {
            canvas,
            chrome,
            scale,
            window,
            copy_on_image,
            headline_top: height * 0.075,
            headline_size: height * 0.052,
            subline_size: height * 0.025,
        }
    }

    /// The pixels-per-point the window pass renders at to land here 1:1.
    pub(crate) fn window_scale(&self) -> f32 {
        self.scale
    }
}

/// Frame `window` (the rendered app) for `shot` on `store`'s canvas.
pub(crate) fn frame(
    store: Store,
    shot: &Shot,
    layout: &Layout,
    window: &RgbaImage,
) -> Result<RgbaImage, ScreenshotError> {
    let layout = *layout;
    let window_pixels = color_image(window);
    let window_size = pixel_size(window)?;
    let icon_pixels = app_icon()?;
    let headline = shot.headline;
    let subline = shot.subline;

    // egui assumes a 2048 px texture limit unless told otherwise, and a 4K
    // canvas places a window wider than that. The device already renders the
    // whole canvas as one target, so a texture no larger than the canvas is
    // within its limits.
    let texture_limit = texture_side(layout.canvas.width().max(layout.canvas.height()));
    let mut fonts_installed = false;
    let mut textures: Option<(TextureHandle, TextureHandle)> = None;
    let mut harness = Harness::builder()
        .with_size(layout.canvas.size())
        .with_pixels_per_point(1.0)
        .wgpu()
        .build_ui(move |ui| {
            let ctx = ui.ctx().clone();
            if !fonts_installed {
                // Fonts set now only take effect next frame.
                install_fonts(&ctx);
                fonts_installed = true;
                ctx.request_repaint();
                return;
            }
            // The harness runs frames while it is still being built, before the
            // raised texture limit below reaches the context; wait for it.
            if ctx.input(|input| input.max_texture_side) < texture_limit {
                ctx.request_repaint();
                return;
            }
            let (window_texture, icon_texture) = textures.get_or_insert_with(|| {
                (
                    ctx.load_texture("window", window_pixels.clone(), TextureOptions::LINEAR),
                    ctx.load_texture("icon", icon_pixels.clone(), TextureOptions::LINEAR),
                )
            });
            let painter = ctx.layer_painter(egui::LayerId::background());
            backdrop::paint(&painter, layout.canvas, layout.window);
            if layout.copy_on_image {
                paint_copy(&painter, &layout, headline, subline);
            }
            paint_window(
                &painter,
                &layout,
                window_size,
                window_texture.id(),
                icon_texture.id(),
            );
        });
    harness.input_mut().max_texture_side = Some(texture_limit);
    harness
        .try_run()
        .map_err(|err| ScreenshotError::Render(format!("{}: {err}", store.dir_name())))?;
    harness.render().map_err(ScreenshotError::Render)
}

fn paint_copy(painter: &egui::Painter, layout: &Layout, headline: &str, subline: &str) {
    let center_x = layout.canvas.center().x;
    let headline_font = FontId::new(layout.headline_size, FontFamily::Name(BOLD_FAMILY.into()));
    painter.text(
        pos2(center_x, layout.headline_top),
        Align2::CENTER_TOP,
        headline,
        headline_font,
        HEADLINE,
    );
    let subline_top = layout.headline_top + layout.headline_size * 1.45;
    painter.text(
        pos2(center_x, subline_top),
        Align2::CENTER_TOP,
        subline,
        FontId::proportional(layout.subline_size),
        SUBLINE,
    );
}

/// Paint the window: shadow, the app image (`window`, `window_size` pixels)
/// under the platform title bar, and a hairline outline.
fn paint_window(
    painter: &egui::Painter,
    layout: &Layout,
    window_size: egui::Vec2,
    window: egui::TextureId,
    icon: egui::TextureId,
) {
    let scale = layout.scale;
    let corner = chrome::radius(layout.chrome.corner_radius() * scale);
    // The body is sized by the rendered image itself, so it maps 1:1 even
    // where the renderer rounded the window to whole pixels.
    let bar_height = (layout.chrome.title_bar_height() * scale).round();
    let bar = Rect::from_min_size(layout.window.min, vec2(window_size.x, bar_height));
    let overlaid = layout.chrome.title_bar_overlays_content();
    let body_top = if overlaid {
        bar.left_top()
    } else {
        bar.left_bottom()
    };
    let body = Rect::from_min_size(body_top, window_size);
    let outline = bar.union(body);

    let shadow = Shadow {
        offset: [0, shadow_drop(18.0 * scale)],
        blur: chrome::radius(60.0 * scale),
        spread: 0,
        color: Color32::from_black_alpha(150),
    };
    painter.add(shadow.as_shape(outline, CornerRadius::same(corner)));

    let top = if overlaid { corner } else { 0 };
    let bottom_corners = CornerRadius {
        nw: top,
        ne: top,
        sw: corner,
        se: corner,
    };
    let full_uv = Rect::from_min_max(pos2(0.0, 0.0), pos2(1.0, 1.0));
    painter.add(
        egui::epaint::RectShape::filled(body, bottom_corners, Color32::WHITE)
            .with_texture(window, full_uv),
    );
    chrome::paint_title_bar(painter, layout.chrome, bar, scale, icon);
    painter.rect_stroke(
        outline,
        CornerRadius::same(corner),
        Stroke::new(1.0_f32, Color32::from_white_alpha(40)),
        StrokeKind::Outside,
    );
}

/// A canvas side in pixels as a texture-size limit. Canvases are `u16`-sized.
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "a canvas side is a whole, positive u16 converted to f32 and back"
)]
fn texture_side(pixels: f32) -> usize {
    pixels as usize
}

/// A vertical shadow offset in whole pixels, as egui stores it.
#[expect(
    clippy::cast_possible_truncation,
    reason = "rounded and clamped to the i8 range first, so the cast is exact"
)]
fn shadow_drop(pixels: f32) -> i8 {
    pixels.round().clamp(0.0, f32::from(i8::MAX)) as i8
}

fn install_fonts(ctx: &egui::Context) {
    let mut fonts = FontDefinitions::default();
    fonts.font_data.insert(
        "NotoSans".to_owned(),
        Arc::new(FontData::from_static(include_bytes!(
            "../fonts/NotoSans-Regular.ttf"
        ))),
    );
    fonts.font_data.insert(
        "NotoSansBold".to_owned(),
        Arc::new(FontData::from_static(include_bytes!(
            "../fonts/NotoSans-Bold.ttf"
        ))),
    );
    if let Some(proportional) = fonts.families.get_mut(&FontFamily::Proportional) {
        proportional.insert(0, "NotoSans".to_owned());
    }
    fonts.families.insert(
        FontFamily::Name(BOLD_FAMILY.into()),
        vec!["NotoSansBold".to_owned()],
    );
    ctx.set_fonts(fonts);
}

/// An image's size in canvas pixels. Every canvas is at most 4K, so a window
/// image that does not fit `u16` means the window pass went wrong.
fn pixel_size(image: &RgbaImage) -> Result<egui::Vec2, ScreenshotError> {
    let side = |pixels: u32| {
        u16::try_from(pixels).map(f32::from).map_err(|_| {
            ScreenshotError::Render(format!("window image is {pixels} px wide or tall"))
        })
    };
    Ok(vec2(side(image.width())?, side(image.height())?))
}

fn color_image(image: &RgbaImage) -> ColorImage {
    let size = [image.width() as usize, image.height() as usize];
    ColorImage::from_rgba_unmultiplied(size, image.as_raw())
}

/// The app icon, as the Windows title bar shows it.
fn app_icon() -> Result<ColorImage, ScreenshotError> {
    let decoded = image::load_from_memory(include_bytes!("../../assets/icon-256.png"))
        .map_err(|err| ScreenshotError::Render(format!("embedded app icon: {err}")))?;
    Ok(color_image(&decoded.to_rgba8()))
}

#[cfg(test)]
mod tests {
    use super::Layout;
    use crate::store_screenshots::listing::{Store, CAPTION_LIMIT, SHOTS};

    #[test]
    fn captions_fit_the_partner_center_limit() {
        for shot in &SHOTS {
            let caption = shot.caption();
            assert!(
                caption.chars().count() <= CAPTION_LIMIT,
                "{}: caption is {} characters",
                shot.slug,
                caption.chars().count()
            );
        }
    }

    #[test]
    fn window_fits_each_canvas_below_the_copy() {
        for store in Store::ALL {
            let layout = Layout::for_store(store);
            assert!(
                layout.canvas.contains_rect(layout.window),
                "{store:?}: window {:?} leaves canvas {:?}",
                layout.window,
                layout.canvas
            );
            if !layout.copy_on_image {
                continue;
            }
            let copy_bottom =
                layout.headline_top + layout.headline_size * 1.45 + layout.subline_size * 1.5;
            assert!(
                layout.window.top() > copy_bottom,
                "{store:?}: window overlaps the headline"
            );
        }
    }
}
