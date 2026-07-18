//! Signature image loading for PDF appearances.
//!
//! Loads a PNG/JPEG/GIF/BMP/TIFF/WEBP image, downscales it if large, splits any
//! alpha channel into a soft mask, converts to RGB, and returns deflate-
//! compressed pixel data ready to embed as a PDF image XObject.
//!
//! The signature image is decorative and lies outside the signed byte range, so
//! resampling need only be visually reasonable, not bit-exact.

use std::io::{Cursor, Write as _};
use std::path::Path;

use flate2::write::ZlibEncoder;
use flate2::Compression;
use image::imageops::FilterType;
use image::{ImageFormat, ImageReader};

use crate::{Result, RevenantError};

/// Maximum image dimension (px) before downscaling. 200 is plenty for print.
const MAX_IMAGE_PX: u32 = 200;
/// Maximum input file size (5 MB): larger is not a reasonable signature image.
const MAX_FILE_SIZE: u64 = 5 * 1024 * 1024;
/// Maximum pixel count, guarding against decompression bombs (CWE-400).
const MAX_IMAGE_PIXELS: u64 = 2000 * 2000;
/// Human-readable list of accepted formats (sorted), for error messages.
const SUPPORTED: &str = "BMP, GIF, JPEG, PNG, TIFF, WEBP";

/// Decoded, PDF-ready signature image data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureImageData {
    /// Deflate-compressed RGB pixel data.
    pub samples: Vec<u8>,
    /// Deflate-compressed alpha channel, or `None` if the image is opaque.
    pub smask: Option<Vec<u8>>,
    /// Pixel width (after any downscale).
    pub width: u32,
    /// Pixel height (after any downscale).
    pub height: u32,
    /// Bits per component (always 8).
    pub bpc: u8,
}

/// Load an image file and prepare it for embedding in a PDF signature.
///
/// # Errors
///
/// Returns [`RevenantError::Pdf`] if the file is missing, empty, too large, in
/// an unsupported format, exceeds the pixel-count guard, or cannot be decoded.
pub fn load_signature_image(image_path: &str) -> Result<SignatureImageData> {
    let path = Path::new(image_path);

    let meta = std::fs::metadata(path)
        .map_err(|_| RevenantError::Pdf(format!("Signature image not found: {image_path}")))?;
    let file_size = meta.len();
    if file_size > MAX_FILE_SIZE {
        // One-decimal MB via integer tenths (no float cast).
        let tenths = file_size * 10 / (1024 * 1024);
        return Err(RevenantError::Pdf(format!(
            "Signature image too large: {}.{} MB (max {} MB)",
            tenths / 10,
            tenths % 10,
            MAX_FILE_SIZE / 1024 / 1024
        )));
    }
    if file_size == 0 {
        return Err(RevenantError::Pdf(
            "Signature image file is empty".to_owned(),
        ));
    }

    let bytes = std::fs::read(path)
        .map_err(|e| RevenantError::Pdf(format!("Cannot read signature image: {e}")))?;

    // Detect the format and read dimensions from the header (no full decode yet)
    // so a decompression bomb is rejected before any large allocation.
    let probe = ImageReader::new(Cursor::new(bytes.as_slice()))
        .with_guessed_format()
        .map_err(|e| RevenantError::Pdf(format!("Cannot load image file: {e}")))?;
    let format = probe.format().ok_or_else(|| {
        RevenantError::Pdf(format!(
            "Unsupported image format: unknown. Supported: {SUPPORTED}"
        ))
    })?;
    if !is_supported(format) {
        return Err(RevenantError::Pdf(format!(
            "Unsupported image format: {format:?}. Supported: {SUPPORTED}"
        )));
    }
    let (w, h) = probe
        .into_dimensions()
        .map_err(|e| RevenantError::Pdf(format!("Cannot read image dimensions: {e}")))?;
    let pixels = u64::from(w) * u64::from(h);
    if pixels > MAX_IMAGE_PIXELS {
        return Err(RevenantError::Pdf(format!(
            "Image too large: {w}x{h} ({pixels} pixels). Maximum: {MAX_IMAGE_PIXELS} pixels."
        )));
    }

    let mut img = ImageReader::new(Cursor::new(bytes.as_slice()))
        .with_guessed_format()
        .map_err(|e| RevenantError::Pdf(format!("Cannot load image file: {e}")))?
        .decode()
        .map_err(|e| RevenantError::Pdf(format!("Cannot decode image: {e}")))?;

    // Downscale so the longest side is at most MAX_IMAGE_PX, preserving aspect.
    // Integer math avoids float->int casts; the resulting size may differ by a
    // pixel from a floating-point scale, which is immaterial for a decorative image.
    let max_dim = w.max(h);
    if max_dim > MAX_IMAGE_PX {
        let new_w = scaled_dim(w, max_dim);
        let new_h = scaled_dim(h, max_dim);
        img = img.resize_exact(new_w, new_h, FilterType::Lanczos3);
    }

    let width = img.width();
    let height = img.height();

    // Split the alpha channel into a soft mask if present, then flatten to RGB.
    let smask = if img.color().has_alpha() {
        let rgba = img.to_rgba8();
        let alpha: Vec<u8> = rgba.pixels().map(|p| p.0[3]).collect();
        Some(deflate(&alpha)?)
    } else {
        None
    };

    let rgb = img.to_rgb8().into_raw();
    let samples = deflate(&rgb)?;

    Ok(SignatureImageData {
        samples,
        smask,
        width,
        height,
        bpc: 8,
    })
}

/// Scale one dimension by `MAX_IMAGE_PX / max_dim`, clamped to at least 1.
fn scaled_dim(value: u32, max_dim: u32) -> u32 {
    let scaled = u64::from(value) * u64::from(MAX_IMAGE_PX) / u64::from(max_dim);
    u32::try_from(scaled).unwrap_or(MAX_IMAGE_PX).max(1)
}

/// Whether a decoded format is one Revenant accepts.
fn is_supported(format: ImageFormat) -> bool {
    matches!(
        format,
        ImageFormat::Png
            | ImageFormat::Jpeg
            | ImageFormat::Gif
            | ImageFormat::Bmp
            | ImageFormat::Tiff
            | ImageFormat::WebP
    )
}

/// Zlib-deflate a byte slice at the default compression level.
fn deflate(data: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(data)
        .map_err(|e| RevenantError::Pdf(format!("Image compression failed: {e}")))?;
    encoder
        .finish()
        .map_err(|e| RevenantError::Pdf(format!("Image compression failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::read::ZlibDecoder;
    use std::io::Read as _;

    /// Encode an RGBA image to PNG bytes and write it to a temp file, returning
    /// the path (kept alive by the returned `TempDir`).
    fn byte(v: u32) -> u8 {
        u8::try_from(v % 256).unwrap()
    }

    /// Write an image to a temp PNG. `with_alpha` chooses an RGBA PNG (with an
    /// alpha channel) or a true opaque RGB PNG (no alpha channel).
    fn write_png(width: u32, height: u32, with_alpha: bool) -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("img.png");
        if with_alpha {
            let mut buf = image::RgbaImage::new(width, height);
            for (x, y, px) in buf.enumerate_pixels_mut() {
                *px = image::Rgba([byte(x), byte(y), 128, byte(x + y)]);
            }
            buf.save_with_format(&path, ImageFormat::Png).unwrap();
        } else {
            let mut buf = image::RgbImage::new(width, height);
            for (x, y, px) in buf.enumerate_pixels_mut() {
                *px = image::Rgb([byte(x), byte(y), 128]);
            }
            buf.save_with_format(&path, ImageFormat::Png).unwrap();
        }
        let path_str = path.to_str().unwrap().to_owned();
        (dir, path_str)
    }

    fn inflate(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        ZlibDecoder::new(data).read_to_end(&mut out).unwrap();
        out
    }

    #[test]
    fn loads_opaque_image() {
        let (_dir, path) = write_png(40, 20, false);
        let data = load_signature_image(&path).unwrap();
        assert_eq!(data.width, 40);
        assert_eq!(data.height, 20);
        assert_eq!(data.bpc, 8);
        assert!(data.smask.is_none());
        // RGB: 3 bytes per pixel after inflation.
        assert_eq!(inflate(&data.samples).len(), 40 * 20 * 3);
    }

    #[test]
    fn extracts_alpha_channel() {
        let (_dir, path) = write_png(30, 15, true);
        let data = load_signature_image(&path).unwrap();
        let smask = data.smask.expect("smask");
        assert_eq!(inflate(&smask).len(), 30 * 15);
        assert_eq!(inflate(&data.samples).len(), 30 * 15 * 3);
    }

    #[test]
    fn downscales_large_image() {
        let (_dir, path) = write_png(400, 100, false);
        let data = load_signature_image(&path).unwrap();
        // Longest side clamped to 200; aspect preserved.
        assert_eq!(data.width, 200);
        assert_eq!(data.height, 50);
    }

    #[test]
    fn rejects_missing_file() {
        let err = load_signature_image("/nonexistent/does-not-exist.png").unwrap_err();
        assert!(err.to_string().contains("not found"), "{err}");
    }

    #[test]
    fn rejects_empty_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.png");
        std::fs::write(&path, b"").unwrap();
        let err = load_signature_image(path.to_str().unwrap()).unwrap_err();
        assert!(err.to_string().contains("empty"), "{err}");
    }

    #[test]
    fn rejects_non_image() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("notimage.png");
        std::fs::write(&path, b"this is definitely not an image file").unwrap();
        let err = load_signature_image(path.to_str().unwrap()).unwrap_err();
        // Either format detection or decode fails; both are surfaced.
        assert!(!err.to_string().is_empty());
    }
}
