//! Destination naming for batch signing.
//!
//! Every input's output name is reserved before the first signing request, and
//! the final write claims its name exclusively. Between them these two rules are
//! what keep a batch from replacing a file it did not create -- including one
//! still queued as a later input.

use std::collections::{HashMap, HashSet};
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::views;

pub(super) struct BatchOutputPath {
    /// The name the input derives on its own, before any collision suffix.
    pub(super) base: PathBuf,
    planned: PathBuf,
    next_suffix: u64,
}

/// Reserve a distinct, currently-unused destination for every batch input.
///
/// File names are derived before any signing request is made. Collisions within
/// the batch, and files already present in the selected directory, receive a
/// numeric suffix rather than being overwritten.
pub(super) fn batch_output_paths(
    files: &[PathBuf],
    output_dir: &Path,
    detached: bool,
) -> Vec<Option<BatchOutputPath>> {
    let mut reserved = HashSet::with_capacity(files.len());
    let mut next_suffixes = HashMap::new();
    files
        .iter()
        .map(|path| {
            let base = views::sign::default_output(path, detached)
                .file_name()
                .map(|name| output_dir.join(name))?;
            let (planned, next_suffix) = unique_output_path(&base, &reserved, &mut next_suffixes);
            reserved.insert(planned.clone());
            Some(BatchOutputPath {
                base,
                planned,
                next_suffix,
            })
        })
        .collect()
}

/// Pick the requested path when available, otherwise add `_2`, `_3`, ...
/// before its final extension until both the filesystem and this batch agree
/// that the name is unused.
fn unique_output_path(
    output: &Path,
    reserved: &HashSet<PathBuf>,
    next_suffixes: &mut HashMap<PathBuf, u64>,
) -> (PathBuf, u64) {
    if !reserved.contains(output) && !output.exists() {
        return (output.to_path_buf(), 2);
    }

    let next_suffix = next_suffixes.entry(output.to_path_buf()).or_insert(2);
    loop {
        let index = *next_suffix;
        *next_suffix += 1;
        let candidate = numbered_output_path(output, index);
        if !reserved.contains(&candidate) && !candidate.exists() {
            return (candidate, *next_suffix);
        }
    }
}

fn numbered_output_path(path: &Path, index: u64) -> PathBuf {
    let mut name = path.file_stem().unwrap_or_default().to_os_string();
    name.push(format!("_{index}"));
    if let Some(extension) = path.extension() {
        name.push(".");
        name.push(extension);
    }
    path.with_file_name(name)
}

/// Persist a batch output without replacing an existing filesystem entry.
///
/// The filesystem is the final authority on whether two names collide: this
/// also covers case-insensitive aliases and files created after planning. A
/// retry continues the original base name's numeric suffix sequence.
pub(super) fn write_unique_file(output: &BatchOutputPath, data: &[u8]) -> io::Result<PathBuf> {
    let mut candidate = output.planned.clone();
    let mut next_suffix = output.next_suffix;
    loop {
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(mut file) => {
                if let Err(err) = file.write_all(data) {
                    // The exclusive create already claimed the name, so bailing
                    // out here would leave a short file that looks exactly like a
                    // signed document. Take the name back instead.
                    drop(file);
                    if let Err(cleanup) = std::fs::remove_file(&candidate) {
                        log::error!(
                            "failed to remove the partial output {}: {cleanup}",
                            candidate.display()
                        );
                    }
                    return Err(err);
                }
                return Ok(candidate);
            }
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
                candidate = numbered_output_path(&output.base, next_suffix);
                next_suffix += 1;
            }
            Err(err) => return Err(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{batch_output_paths, write_unique_file, BatchOutputPath};

    fn planned_paths(outputs: Vec<Option<BatchOutputPath>>) -> Vec<Option<PathBuf>> {
        outputs
            .into_iter()
            .map(|output| output.map(|output| output.planned))
            .collect()
    }

    #[test]
    fn batch_outputs_disambiguate_same_named_inputs() {
        let dir = tempfile::tempdir().unwrap();
        let files = vec![
            PathBuf::from("first").join("contract.pdf"),
            PathBuf::from("second").join("contract.pdf"),
            PathBuf::from("third").join("contract.pdf"),
        ];

        assert_eq!(
            planned_paths(batch_output_paths(&files, dir.path(), false)),
            vec![
                Some(dir.path().join("contract_signed.pdf")),
                Some(dir.path().join("contract_signed_2.pdf")),
                Some(dir.path().join("contract_signed_3.pdf")),
            ]
        );
    }

    #[test]
    fn batch_outputs_skip_existing_and_reserved_detached_names() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("contract.pdf.p7s"), b"existing").unwrap();
        let files = vec![
            PathBuf::from("first").join("contract.pdf"),
            PathBuf::from("second").join("contract.pdf"),
        ];

        assert_eq!(
            planned_paths(batch_output_paths(&files, dir.path(), true)),
            vec![
                Some(dir.path().join("contract.pdf_2.p7s")),
                Some(dir.path().join("contract.pdf_3.p7s")),
            ]
        );
    }

    #[test]
    fn batch_write_uses_a_suffix_instead_of_replacing_an_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("contract_signed.pdf");
        let planned = BatchOutputPath {
            base: output.clone(),
            planned: output.clone(),
            next_suffix: 2,
        };
        let first = write_unique_file(&planned, b"first signature").unwrap();

        let second = write_unique_file(&planned, b"second signature").unwrap();

        assert_eq!(first, output);
        assert_eq!(second, dir.path().join("contract_signed_2.pdf"));
        assert_eq!(std::fs::read(first).unwrap(), b"first signature");
        assert_eq!(std::fs::read(second).unwrap(), b"second signature");
    }

    #[test]
    fn batch_write_continues_the_planned_suffix_series_after_a_race() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("contract_signed.pdf");
        std::fs::write(&base, b"existing signature").unwrap();
        let files = vec![PathBuf::from("contract.pdf")];
        let planned = batch_output_paths(&files, dir.path(), false)
            .pop()
            .flatten()
            .unwrap();
        assert_eq!(planned.planned, dir.path().join("contract_signed_2.pdf"));

        std::fs::write(&planned.planned, b"racing signature").unwrap();
        let written = write_unique_file(&planned, b"new signature").unwrap();

        assert_eq!(written, dir.path().join("contract_signed_3.pdf"));
        assert_eq!(std::fs::read(&base).unwrap(), b"existing signature");
        assert_eq!(
            std::fs::read(&planned.planned).unwrap(),
            b"racing signature"
        );
        assert_eq!(std::fs::read(written).unwrap(), b"new signature");
    }
}
