//! Content-stream operator emission for the signature appearance.
//!
//! Given a computed layout ([`RenderParams`]) and the wrapped text, emit the PDF
//! graphics operators for the backdrop, border, optional image, and text stack.
//! The layout computation lives in the parent [`super`] module.

use super::{RenderParams, BG_COLOR, BORDER_COLOR, DETAIL_COLOR, NAME_DETAIL_GAP_RATIO};
use crate::appearance::fonts::Font;

/// Emit the PDF content-stream operators for the computed layout.
pub(super) fn render_ops(
    font: &Font,
    p: &RenderParams,
    name_lines: &[String],
    detail_texts: &[String],
) -> Vec<u8> {
    let mut ops: Vec<String> = Vec::new();

    // 0. Semi-transparent backdrop.
    ops.push("q".to_owned());
    ops.push("/GS1 gs".to_owned());
    ops.push(format!("{BG_COLOR} g"));
    ops.push(format!("0 0 {:.2} {:.2} re", p.width, p.height));
    ops.push("f".to_owned());
    ops.push("Q".to_owned());

    // 1. Border rectangle.
    ops.push("q".to_owned());
    ops.push(format!("{BORDER_COLOR} {BORDER_COLOR} {BORDER_COLOR} RG"));
    ops.push(format!("{} w", p.bw));
    ops.push(format!(
        "{:.2} {:.2} {:.2} {:.2} re",
        p.half_bw,
        p.half_bw,
        p.width - p.bw,
        p.height - p.bw
    ));
    ops.push("S".to_owned());
    ops.push("Q".to_owned());

    // 2. Image column (aspect-preserving fit).
    if p.has_image {
        let mut draw_w = p.img_w;
        let mut draw_h = p.content_h;
        if let Some(aspect) = p.image_aspect {
            if aspect > 0.0 {
                let space_aspect = if p.content_h > 0.0 {
                    p.img_w / p.content_h
                } else {
                    1.0
                };
                if aspect > space_aspect {
                    draw_h = p.img_w / aspect;
                } else {
                    draw_w = p.content_h * aspect;
                }
            }
        }
        let draw_x = p.content_x + (p.img_w - draw_w) / 2.0;
        let draw_y = p.content_y + (p.content_h - draw_h) / 2.0;
        ops.push("q".to_owned());
        ops.push(format!(
            "{draw_w:.2} 0 0 {draw_h:.2} {draw_x:.2} {draw_y:.2} cm"
        ));
        ops.push("/Img1 Do".to_owned());
        ops.push("Q".to_owned());
    }

    // 3. Text stack, clipped to the text area.
    ops.push("q".to_owned());
    ops.push(format!(
        "{:.2} {:.2} {:.2} {:.2} re W n",
        p.text_x, p.content_y, p.text_w, p.content_h
    ));
    ops.push("BT".to_owned());
    ops.push("0 Tc 0 Tw".to_owned());

    // Name line (large, black).
    let cursor_y = p.content_y + p.content_h - p.name_font - p.v_offset;
    ops.push("0 g".to_owned());
    ops.push(format!("/F1 {:.3} Tf", p.name_font));
    ops.push(format!("{:.2} {:.2} Td", p.text_x, cursor_y));
    for (i, line) in name_lines.iter().enumerate() {
        if i > 0 {
            ops.push(format!("0 {:.2} Td", -p.name_leading));
        }
        ops.push(format!("{} Tj", font.pdf_escape(line)));
    }

    // Detail lines (smaller, gray).
    if !detail_texts.is_empty() {
        let name_gap = p.name_font * NAME_DETAIL_GAP_RATIO;
        ops.push(format!("0 {:.2} Td", -name_gap));
        ops.push(format!("{DETAIL_COLOR} g"));
        ops.push(format!("/F1 {:.3} Tf", p.detail_font));

        for (idx, detail) in detail_texts.iter().enumerate() {
            let detail_lines = font.wrap_lines(detail, p.detail_font, p.text_w);
            for (i, line) in detail_lines.iter().enumerate() {
                if i > 0 || idx > 0 {
                    ops.push(format!("0 {:.2} Td", -p.detail_leading));
                }
                ops.push(format!("{} Tj", font.pdf_escape(line)));
            }
        }
    }

    ops.push("ET".to_owned());
    ops.push("Q".to_owned());

    ops.join("\n").into_bytes()
}
