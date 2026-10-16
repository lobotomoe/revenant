//! The macOS menu bar: the app menu (About, Settings, Hide, Quit), File > Open,
//! Window and Help, in the order and with the shortcuts a Mac app is expected to
//! have. About opens the standard About panel AppKit draws for every app.
//!
//! There is deliberately no Edit menu. Its Cut/Copy/Paste items would take
//! Cmd+X/C/V before egui sees them, and egui's text fields handle those keys
//! themselves.

use std::sync::mpsc;

use eframe::egui;
use muda::accelerator::{Accelerator, Code, Modifiers};
use muda::{AboutMetadata, Menu, MenuEvent, MenuItem, PredefinedMenuItem, Submenu};
use revenant_sign_core::constants::VERSION;

use crate::i18n::Localizer;
use crate::links;

const SETTINGS_ID: &str = "settings";
const OPEN_ID: &str = "open";
const HELP_ID: &str = "help";
const REPO_ID: &str = "repo";
const ISSUES_ID: &str = "issues";
const TELEGRAM_ID: &str = "telegram";

/// What a menu item asks the app to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MenuCommand {
    Settings,
    Open,
    /// Open a web page.
    Link(&'static str),
}

impl MenuCommand {
    fn from_id(id: &str) -> Option<Self> {
        match id {
            SETTINGS_ID => Some(Self::Settings),
            OPEN_ID => Some(Self::Open),
            HELP_ID => Some(Self::Link(links::HELP_URL)),
            REPO_ID => Some(Self::Link(links::REPO_URL)),
            ISSUES_ID => Some(Self::Link(links::ISSUES_URL)),
            TELEGRAM_ID => Some(Self::Link(links::TELEGRAM_URL)),
            _ => None,
        }
    }
}

/// The installed menu bar and the commands its items send.
pub(crate) struct MenuBar {
    /// Kept alive for as long as it is the app's main menu.
    menu: Menu,
    commands: mpsc::Receiver<MenuCommand>,
}

impl std::fmt::Debug for MenuBar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MenuBar").finish_non_exhaustive()
    }
}

impl MenuBar {
    /// Build the menu bar in the current language and make it the app's main
    /// menu. Must be called on the main thread, once; [`Self::relabel`] redoes
    /// the labels after a language change.
    pub(crate) fn install(ctx: &egui::Context, l10n: &Localizer) -> muda::Result<Self> {
        let (sender, commands) = mpsc::channel();
        let ctx = ctx.clone();
        // muda keeps the first handler it is given for the life of the process.
        MenuEvent::set_event_handler(Some(move |event: MenuEvent| {
            if let Some(command) = MenuCommand::from_id(event.id.as_ref()) {
                // The receiver lives as long as the app, so a failed send only
                // happens while the app is shutting down.
                if sender.send(command).is_ok() {
                    ctx.request_repaint();
                }
            }
        }));
        let menu = build(l10n)?;
        menu.init_for_nsapp();
        Ok(Self { menu, commands })
    }

    /// Rebuild the menu bar in a newly selected language.
    pub(crate) fn relabel(&mut self, l10n: &Localizer) -> muda::Result<()> {
        let menu = build(l10n)?;
        menu.init_for_nsapp();
        self.menu = menu;
        Ok(())
    }

    /// The commands chosen since the last call.
    pub(crate) fn take_commands(&self) -> Vec<MenuCommand> {
        self.commands.try_iter().collect()
    }
}

fn build(l10n: &Localizer) -> muda::Result<Menu> {
    let command = Modifiers::META;
    let about = PredefinedMenuItem::about(Some(l10n.t("gui.about_revenant")), Some(about(l10n)));
    let settings = MenuItem::with_id(
        SETTINGS_ID,
        l10n.t("gui.menu_settings"),
        true,
        Some(Accelerator::new(command, Code::Comma)),
    );
    let app_menu = Submenu::with_items(
        "Revenant",
        true,
        &[
            &about,
            &PredefinedMenuItem::separator(),
            &settings,
            &PredefinedMenuItem::separator(),
            &PredefinedMenuItem::services(Some(l10n.t("gui.menu_services"))),
            &PredefinedMenuItem::separator(),
            &PredefinedMenuItem::hide(Some(l10n.t("gui.menu_hide_revenant"))),
            &PredefinedMenuItem::hide_others(Some(l10n.t("gui.menu_hide_others"))),
            &PredefinedMenuItem::show_all(Some(l10n.t("gui.menu_show_all"))),
            &PredefinedMenuItem::separator(),
            &PredefinedMenuItem::quit(Some(l10n.t("gui.menu_quit_revenant"))),
        ],
    )?;

    let open = MenuItem::with_id(
        OPEN_ID,
        l10n.t("gui.menu_open"),
        true,
        Some(Accelerator::new(command, Code::KeyO)),
    );
    let file_menu = Submenu::with_items(
        l10n.t("gui.file"),
        true,
        &[
            &open,
            &PredefinedMenuItem::separator(),
            &PredefinedMenuItem::close_window(Some(l10n.t("gui.menu_close_window"))),
        ],
    )?;

    let window_menu = Submenu::with_items(
        l10n.t("gui.menu_window"),
        true,
        &[
            &PredefinedMenuItem::minimize(Some(l10n.t("gui.menu_minimize"))),
            &PredefinedMenuItem::maximize(Some(l10n.t("gui.menu_zoom"))),
            &PredefinedMenuItem::separator(),
            &PredefinedMenuItem::bring_all_to_front(Some(l10n.t("gui.menu_bring_all_to_front"))),
        ],
    )?;
    window_menu.set_as_windows_menu_for_nsapp();

    let help = MenuItem::with_id(HELP_ID, l10n.t("gui.menu_revenant_help"), true, None);
    let repo = MenuItem::with_id(REPO_ID, l10n.t("gui.github"), true, None);
    let issues = MenuItem::with_id(ISSUES_ID, l10n.t("gui.report_a_bug"), true, None);
    let telegram = MenuItem::with_id(TELEGRAM_ID, l10n.t("gui.telegram"), true, None);
    let help_menu = Submenu::with_items(
        l10n.t("gui.menu_help"),
        true,
        &[
            &help,
            &PredefinedMenuItem::separator(),
            &repo,
            &issues,
            &telegram,
        ],
    )?;
    help_menu.set_as_help_menu_for_nsapp();

    Menu::with_items(&[&app_menu, &file_menu, &window_menu, &help_menu])
}

/// What the About panel shows besides the icon, which AppKit takes from the
/// bundle. Name and version are given explicitly so an unbundled build shows
/// them too. No credits: AppKit sets them as plain left-aligned body text that
/// sits oddly under the centred lines above.
fn about(l10n: &Localizer) -> AboutMetadata {
    let copyright = format!(
        "{}\n{}",
        l10n.t("gui.author_aleksandr_kraiz"),
        l10n.t("gui.license_apache_2_0"),
    );
    AboutMetadata {
        name: Some("Revenant".to_owned()),
        short_version: Some(VERSION.to_owned()),
        copyright: Some(copyright),
        ..AboutMetadata::default()
    }
}

#[cfg(test)]
mod tests {
    use super::{MenuCommand, HELP_ID, ISSUES_ID, OPEN_ID, REPO_ID, SETTINGS_ID, TELEGRAM_ID};
    use crate::links;

    #[test]
    fn every_item_id_maps_to_its_command() {
        assert_eq!(
            MenuCommand::from_id(SETTINGS_ID),
            Some(MenuCommand::Settings)
        );
        assert_eq!(MenuCommand::from_id(OPEN_ID), Some(MenuCommand::Open));
        assert_eq!(
            MenuCommand::from_id(HELP_ID),
            Some(MenuCommand::Link(links::HELP_URL))
        );
        assert_eq!(
            MenuCommand::from_id(REPO_ID),
            Some(MenuCommand::Link(links::REPO_URL))
        );
        assert_eq!(
            MenuCommand::from_id(ISSUES_ID),
            Some(MenuCommand::Link(links::ISSUES_URL))
        );
        assert_eq!(
            MenuCommand::from_id(TELEGRAM_ID),
            Some(MenuCommand::Link(links::TELEGRAM_URL))
        );
    }

    #[test]
    fn system_items_send_no_command() {
        assert_eq!(MenuCommand::from_id("quit"), None);
    }
}
