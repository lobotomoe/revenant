//! App-store screenshots rendered from the real UI.
//!
//! Each shot is two renders. The app is staged with a fictional account (see
//! [`listing`]) and drawn headlessly at its default window size; that image is
//! then framed -- background, headline, window chrome for the store's platform
//! -- at the store's canvas size. Nothing is captured from a real screen, so no
//! real name, ID number, or path can reach a listing, and every release renders
//! the screenshots from the UI it ships.

mod backdrop;
mod chrome;
mod compose;
mod listing;
mod window;

use std::fmt;
use std::path::{Path, PathBuf};

use revenant_sign_core::error::RevenantError;

use listing::{Store, SHOTS};

/// Why rendering the screenshots failed.
#[derive(Debug)]
pub enum ScreenshotError {
    /// Staging the fictional account in the isolated config store failed.
    Config(RevenantError),
    /// The headless renderer failed or the UI never settled.
    Render(String),
    /// Writing an output file failed.
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    /// Encoding an output image failed.
    Encode {
        path: PathBuf,
        source: image::ImageError,
    },
}

impl fmt::Display for ScreenshotError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScreenshotError::Config(err) => write!(f, "staging the demo account failed: {err}"),
            ScreenshotError::Render(message) => write!(f, "rendering failed: {message}"),
            ScreenshotError::Io { path, source } => {
                write!(f, "cannot write {}: {source}", path.display())
            }
            ScreenshotError::Encode { path, source } => {
                write!(f, "cannot encode {}: {source}", path.display())
            }
        }
    }
}

impl std::error::Error for ScreenshotError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ScreenshotError::Config(err) => Some(err),
            ScreenshotError::Render(_) => None,
            ScreenshotError::Io { source, .. } => Some(source),
            ScreenshotError::Encode { source, .. } => Some(source),
        }
    }
}

impl From<RevenantError> for ScreenshotError {
    fn from(err: RevenantError) -> Self {
        ScreenshotError::Config(err)
    }
}

/// Render every store's screenshots into `out_dir/<store>/<shot>.png`.
///
/// Returns the written paths in order.
///
/// # Errors
///
/// Fails on the first shot that cannot be staged, rendered, or written.
pub fn render_all(out_dir: &Path) -> Result<Vec<PathBuf>, ScreenshotError> {
    let mut written = Vec::new();
    for store in Store::ALL {
        let store_dir = out_dir.join(store.dir_name());
        std::fs::create_dir_all(&store_dir).map_err(|source| ScreenshotError::Io {
            path: store_dir.clone(),
            source,
        })?;
        for shot in &SHOTS {
            let path = store_dir.join(format!("{}.png", shot.slug));
            let image = render_shot(store, shot)?;
            image
                .save(&path)
                .map_err(|source| ScreenshotError::Encode {
                    path: path.clone(),
                    source,
                })?;
            written.push(path);
        }
    }
    Ok(written)
}

/// Render one framed screenshot.
fn render_shot(store: Store, shot: &listing::Shot) -> Result<image::RgbaImage, ScreenshotError> {
    // Each shot gets its own throwaway config directory, so no state carries
    // from one staged account into the next.
    let config_dir = tempfile::tempdir().map_err(|source| ScreenshotError::Io {
        path: std::env::temp_dir(),
        source,
    })?;
    let config = shot.config_store(config_dir.path(), store)?;
    let layout = compose::Layout::for_store(store);
    let window = window::render(config, shot.stage(), layout.window_scale())?;
    compose::frame(store, shot, &layout, &window)
}
