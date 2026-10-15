//! Render the app-store screenshots into a directory.
//!
//! Usage: `store-screenshots <out-dir>`. Writes one folder per store, each with
//! the listing's shots in upload order. See `revenant_sign_gui::store_screenshots`.

use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();

    let mut args = std::env::args_os().skip(1);
    let (Some(out_dir), None) = (args.next(), args.next()) else {
        eprintln!("usage: store-screenshots <out-dir>");
        return ExitCode::from(2);
    };
    let out_dir = PathBuf::from(out_dir);

    match revenant_sign_gui::store_screenshots::render_all(&out_dir) {
        Ok(written) => {
            for path in written {
                println!("{}", path.display());
            }
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("store-screenshots: {err}");
            ExitCode::FAILURE
        }
    }
}
