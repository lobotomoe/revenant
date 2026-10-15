//! The `revenant-gui` executable: logging setup, then the GUI in the library.

fn main() -> eframe::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    revenant_sign_gui::run()
}
