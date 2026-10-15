//! The background behind the window: a near-black base, a warm glow in the
//! brand orange rising behind the window, and a fine grid that fades out toward
//! the edges. Everything is drawn from geometry, so the backdrop scales to any
//! canvas without a source image.

use std::f32::consts::TAU;

use eframe::egui::ecolor::linear_u8_from_linear_f32;
use eframe::egui::{epaint::Mesh, pos2, vec2, Color32, Painter, Pos2, Rect, Shape, Stroke};

/// Base gradient, top to bottom.
const BASE_TOP: Color32 = Color32::from_rgb(0x0C, 0x0B, 0x10);
const BASE_BOTTOM: Color32 = Color32::from_rgb(0x17, 0x11, 0x14);

/// The app icon's orange (`packaging/icons/revenant.svg`).
const BRAND_ORANGE: [u8; 3] = [0xE6, 0x66, 0x0B];
/// A warmer, redder companion glow so the light is not one flat hue.
const EMBER: [u8; 3] = [0xD9, 0x2E, 0x4A];

/// Grid cells across the canvas height.
const GRID_ROWS: f32 = 22.0;
/// Peak grid line opacity, at the center of the fade.
const GRID_ALPHA: f32 = 0.10;

/// Rings and segments of a radial glow mesh: enough that the Gaussian falloff
/// shows no banding or polygon edges at 4K.
const GLOW_RINGS: u16 = 48;
const GLOW_SEGMENTS: u16 = 160;

/// Paint the backdrop over `canvas`, lit from behind `window`.
pub(crate) fn paint(painter: &Painter, canvas: Rect, window: Rect) {
    paint_base(painter, canvas);
    paint_grid(painter, canvas);

    let height = canvas.height();
    let behind_window = pos2(window.center().x, window.top() + window.height() * 0.35);
    paint_glow(painter, behind_window, height * 0.95, BRAND_ORANGE, 0.55);
    let left_of_title = pos2(
        canvas.center().x - canvas.width() * 0.28,
        canvas.top() + height * 0.18,
    );
    paint_glow(painter, left_of_title, height * 0.55, EMBER, 0.30);
}

fn paint_base(painter: &Painter, canvas: Rect) {
    let mut mesh = Mesh::default();
    mesh.colored_vertex(canvas.left_top(), BASE_TOP);
    mesh.colored_vertex(canvas.right_top(), BASE_TOP);
    mesh.colored_vertex(canvas.right_bottom(), BASE_BOTTOM);
    mesh.colored_vertex(canvas.left_bottom(), BASE_BOTTOM);
    mesh.add_triangle(0, 1, 2);
    mesh.add_triangle(0, 2, 3);
    painter.add(Shape::mesh(mesh));
}

/// A grid of thin lines, each segment as opaque as the fade at its midpoint:
/// strongest in the upper middle, gone at the edges.
fn paint_grid(painter: &Painter, canvas: Rect) {
    let cell = canvas.height() / GRID_ROWS;
    let width = (cell / 60.0).max(1.0);
    let focus = pos2(canvas.center().x, canvas.top() + canvas.height() * 0.40);
    let reach = canvas.height() * 0.85;
    let fade = |point: Pos2| -> Color32 {
        let distance = (point - focus).length() / reach;
        let alpha = GRID_ALPHA * (1.0 - distance * distance).max(0.0);
        Color32::from_white_alpha(linear_u8_from_linear_f32(alpha))
    };

    // A vertical line runs through the canvas center; rows start at the top.
    let columns = grid_lines(canvas.center().x, canvas.left(), canvas.right(), cell);
    let rows = grid_lines(canvas.top(), canvas.top(), canvas.bottom(), cell);
    let segment = |from: Pos2, to: Pos2| {
        let color = fade(from.lerp(to, 0.5));
        painter.line_segment([from, to], Stroke::new(width, color));
    };
    for &x in &columns {
        for pair in rows.windows(2) {
            segment(pos2(x, pair[0]), pos2(x, pair[1]));
        }
    }
    for &y in &rows {
        for pair in columns.windows(2) {
            segment(pos2(pair[0], y), pos2(pair[1], y));
        }
    }
}

/// Line positions `step` apart, one of them at `through`, reaching one step
/// past `min` and `max` so the grid never stops short of an edge.
fn grid_lines(through: f32, min: f32, max: f32, step: f32) -> Vec<f32> {
    let mut first = through;
    while first > min {
        first -= step;
    }
    std::iter::successors(Some(first), |line| Some(line + step))
        .take_while(|line| *line < max + step)
        .collect()
}

/// A radial glow with a Gaussian falloff, built as concentric rings of
/// vertices so the GPU interpolates a smooth gradient between them.
fn paint_glow(painter: &Painter, center: Pos2, radius: f32, rgb: [u8; 3], peak_alpha: f32) {
    let [red, green, blue] = rgb;
    let color_at = |fraction: f32| -> Color32 {
        // exp(-4 r^2) is ~0.02 at the rim, so the edge of the mesh is invisible.
        let alpha = peak_alpha * (-4.0 * fraction * fraction).exp();
        Color32::from_rgba_unmultiplied(red, green, blue, linear_u8_from_linear_f32(alpha))
    };

    let mut mesh = Mesh::default();
    mesh.colored_vertex(center, color_at(0.0));
    for ring in 1..=GLOW_RINGS {
        let fraction = f32::from(ring) / f32::from(GLOW_RINGS);
        let color = color_at(fraction);
        for segment in 0..GLOW_SEGMENTS {
            let angle = TAU * f32::from(segment) / f32::from(GLOW_SEGMENTS);
            let offset = vec2(angle.cos(), angle.sin()) * radius * fraction;
            mesh.colored_vertex(center + offset, color);
        }
    }

    // Vertex 0 is the center; ring `n` occupies the next GLOW_SEGMENTS slots.
    let segments = u32::from(GLOW_SEGMENTS);
    let vertex =
        |ring: u16, segment: u32| 1 + (u32::from(ring) - 1) * segments + segment % segments;
    for segment in 0..segments {
        mesh.add_triangle(0, vertex(1, segment), vertex(1, segment + 1));
    }
    for ring in 2..=GLOW_RINGS {
        for segment in 0..segments {
            let (inner, outer) = (ring - 1, ring);
            mesh.add_triangle(
                vertex(inner, segment),
                vertex(outer, segment),
                vertex(outer, segment + 1),
            );
            mesh.add_triangle(
                vertex(inner, segment),
                vertex(outer, segment + 1),
                vertex(inner, segment + 1),
            );
        }
    }
    painter.add(Shape::mesh(mesh));
}
