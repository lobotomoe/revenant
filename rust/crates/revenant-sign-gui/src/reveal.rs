//! Reveal a file in the platform file manager after signing, mirroring the
//! Python client's "show in Finder/Explorer" behaviour.
//!
//! This is a best-effort convenience: a failure to launch the file manager is
//! logged but never surfaced to the user, since the file itself was written
//! successfully and that is the outcome that matters.

use std::path::Path;
use std::process::Command;

/// Open the platform file manager with `path` selected (or its folder on Linux).
pub(crate) fn in_file_manager(path: &Path) {
    let spawned = if cfg!(target_os = "macos") {
        Command::new("open").arg("-R").arg(path).spawn()
    } else if cfg!(target_os = "windows") {
        // `explorer /select,<path>` highlights the file in its folder.
        Command::new("explorer")
            .arg(format!("/select,{}", path.display()))
            .spawn()
    } else {
        // No portable "select the file" call on Linux; open the folder instead.
        let target = path.parent().unwrap_or(path);
        Command::new("xdg-open").arg(target).spawn()
    };

    if let Err(err) = spawned {
        log::warn!("could not reveal {} in file manager: {err}", path.display());
    }
}
