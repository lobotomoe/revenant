//! Signature visual appearance: fonts, display fields, images, and the content
//! stream that readers render inside the signature widget.
//!
//! Font metrics and the embedded subset TTFs are generated data (see
//! [`font_data`]); the rest is layout and PDF content-stream construction.

mod fields;
mod font_data;
mod fonts;
mod image;
mod stream;

pub use fields::{extract_cert_fields, extract_display_fields, format_utc_offset, make_date_str};
pub use fonts::{get_default_font, get_font, Font, AVAILABLE_FONTS, DEFAULT_FONT};
pub use image::{load_signature_image, SignatureImageData};
pub use stream::{
    build_appearance_stream, compute_optimal_height, compute_optimal_width, AppearanceData,
    FontResources,
};
