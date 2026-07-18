// SPDX-License-Identifier: Apache-2.0
//! Output formatting and safe file writing.
//!
//! Small, dependency-light helpers: human-readable sizes, the default
//! output-path conventions for signed files, and an atomic write (temp file +
//! rename, with a direct-write fallback when a sandbox forbids creating the temp
//! file).

use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use tempfile::NamedTempFile;

const BYTES_PER_KB: u64 = 1024;

/// Format a byte count as a human-readable KB string, e.g. `123.4 KB`.
///
/// Rounds to one decimal place (half-up) with integer arithmetic, so the output
/// matches a `{:.1f} KB` format to the displayed precision without a
/// floating-point cast.
#[must_use]
pub(crate) fn format_size_kb(size_bytes: usize) -> String {
    let bytes = u64::try_from(size_bytes).unwrap_or(u64::MAX);
    // Tenths of a KB, rounded to nearest: (bytes*10 + KB/2) / KB.
    let tenths = (bytes.saturating_mul(10).saturating_add(BYTES_PER_KB / 2)) / BYTES_PER_KB;
    format!("{}.{} KB", tenths / 10, tenths % 10)
}

/// The final path component as a string, or the whole path when it has no final
/// component.
#[must_use]
pub(crate) fn file_name(path: &Path) -> String {
    path.file_name()
        .unwrap_or(path.as_os_str())
        .to_string_lossy()
        .into_owned()
}

/// Default output path for a signed PDF: `<stem>_signed.pdf` beside the input.
///
/// `<stem>` is the file name without its final extension, so `report.pdf`
/// becomes `report_signed.pdf` and `x.tar.pdf` becomes `x.tar_signed.pdf`.
#[must_use]
pub(crate) fn default_output_path(pdf_path: &Path) -> PathBuf {
    let stem = pdf_path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    pdf_path.with_file_name(format!("{stem}_signed.pdf"))
}

/// Default output path for a detached signature: the input with its final
/// extension replaced by `.pdf.p7s` (so `report.pdf` -> `report.pdf.p7s`).
#[must_use]
pub(crate) fn default_detached_output_path(pdf_path: &Path) -> PathBuf {
    pdf_path.with_extension("pdf.p7s")
}

/// Write `data` to `path` atomically: to a temp file in the same directory,
/// flushed and renamed over the target so an interrupted write never leaves a
/// partially written file.
///
/// If the directory forbids creating a temp file (a sandboxed Save Panel grants
/// access only to the chosen path), falls back to a direct write of that path.
///
/// # Errors
///
/// Returns the underlying [`io::Error`] if the data cannot be written.
pub(crate) fn atomic_write(path: &Path, data: &[u8]) -> io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new(""));
    let dir = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };

    match NamedTempFile::new_in(dir) {
        Ok(mut tmp) => {
            tmp.write_all(data)?;
            tmp.as_file().sync_all()?;
            tmp.persist(path).map_err(|e| e.error)?;
            Ok(())
        }
        // Sandbox: can only write to the exact path chosen in the Save Panel.
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => direct_write(path, data),
        Err(e) => Err(e),
    }
}

/// Write directly to `path`, flushing to disk.
fn direct_write(path: &Path, data: &[u8]) -> io::Result<()> {
    let mut file = File::create(path)?;
    file.write_all(data)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size_kb_rounds_to_one_decimal() {
        assert_eq!(format_size_kb(0), "0.0 KB");
        assert_eq!(format_size_kb(1024), "1.0 KB");
        assert_eq!(format_size_kb(1536), "1.5 KB");
        // 1600/1024 = 1.5625 -> 1.6
        assert_eq!(format_size_kb(1600), "1.6 KB");
        // 1587/1024 = 1.549... -> 1.5
        assert_eq!(format_size_kb(1587), "1.5 KB");
    }

    #[test]
    fn default_paths_follow_naming_conventions() {
        assert_eq!(
            default_output_path(Path::new("document.pdf")),
            Path::new("document_signed.pdf")
        );
        assert_eq!(
            default_output_path(Path::new("x.tar.pdf")),
            Path::new("x.tar_signed.pdf")
        );
        assert_eq!(
            default_detached_output_path(Path::new("document.pdf")),
            Path::new("document.pdf.p7s")
        );
        assert_eq!(
            default_detached_output_path(Path::new("noext")),
            Path::new("noext.pdf.p7s")
        );
    }

    #[test]
    fn atomic_write_creates_file_with_contents() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.bin");
        atomic_write(&path, b"hello").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"hello");
    }

    #[test]
    fn atomic_write_overwrites_existing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.bin");
        std::fs::write(&path, b"old data here").unwrap();
        atomic_write(&path, b"new").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
    }
}
