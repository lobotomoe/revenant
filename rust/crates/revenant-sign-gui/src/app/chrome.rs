//! The window chrome around the tab content: a toolbar with the Sign/Verify
//! switch in the middle and the server menu on the right.
//!
//! On macOS the window's title bar is transparent and the toolbar continues it,
//! and Settings and About live in the menu bar. Elsewhere (and on macOS if the
//! menu bar could not be built) a settings menu at the toolbar's right end
//! carries them instead. See [`crate::window_style`].

use eframe::egui::{self, Align, Layout, Margin, UiBuilder};
use revenant_sign_core::config::ConfigLayer;

use super::{Confirm, Dialog, RevenantApp, Tab};
use crate::icons;
use crate::segmented::Segmented;

/// Height of the toolbar row itself.
const TOOLBAR_HEIGHT: f32 = 32.0;

impl RevenantApp {
    pub(super) fn toolbar(&mut self, ui: &mut egui::Ui) {
        // Whole points, so the cast cannot truncate.
        #[allow(clippy::cast_possible_truncation)]
        let title_bar_inset = self.window_style.title_bar_inset as i8;
        let frame = egui::Frame::side_top_panel(ui.style()).inner_margin(Margin {
            left: 12,
            right: 12,
            top: title_bar_inset + 4,
            bottom: 8,
        });
        egui::Panel::top("toolbar")
            .frame(frame)
            .show_inside(ui, |ui| {
                let (row, _) = ui.allocate_exact_size(
                    egui::vec2(ui.available_width(), TOOLBAR_HEIGHT),
                    egui::Sense::hover(),
                );

                let options = [
                    (Tab::Sign, self.l10n.t("gui.sign")),
                    (Tab::Verify, self.l10n.t("gui.verify")),
                ];
                let switch = Segmented::new(&mut self.tab, &options);
                let switch_rect = egui::Rect::from_center_size(row.center(), switch.size(ui));
                ui.put(switch_rect, switch);

                let trailing = egui::Rect::from_min_max(
                    egui::pos2(switch_rect.right(), row.top()),
                    row.right_bottom(),
                );
                let mut dialog = None;
                let mut confirm = None;
                ui.scope_builder(
                    UiBuilder::new()
                        .max_rect(trailing)
                        .layout(Layout::right_to_left(Align::Center)),
                    |ui| {
                        if !self.window_style.menu_bar {
                            self.settings_menu(ui, &mut dialog);
                        }
                        self.server_menu(ui, &mut dialog, &mut confirm);
                    },
                );
                if dialog.is_some() {
                    self.dialog = dialog;
                }
                if confirm.is_some() {
                    self.confirm = confirm;
                }
            });
    }

    /// The server name, opening a menu to connect or disconnect.
    fn server_menu(
        &self,
        ui: &mut egui::Ui,
        dialog: &mut Option<Dialog>,
        confirm: &mut Option<Confirm>,
    ) {
        let configured = self.store.config_layer() != ConfigLayer::Unconfigured;
        let name = if configured {
            self.store
                .active_profile()
                .map(|profile| profile.display_name)
                .unwrap_or_default()
        } else {
            self.l10n.t("gui.no_server_configured").to_owned()
        };
        let title = format!("{}  {name}  {}", icons::SERVER, icons::CARET_DOWN);
        ui.menu_button(title, |ui| {
            if configured {
                if ui.button(self.l10n.t("gui.menu_disconnect")).clicked() {
                    *confirm = Some(Confirm::Disconnect);
                    ui.close();
                }
            } else if ui.button(self.l10n.t("gui.menu_connect")).clicked() {
                *dialog = Some(Dialog::Connect);
                ui.close();
            }
        });
    }

    /// Settings, About and Help, for platforms without a menu bar.
    fn settings_menu(&self, ui: &mut egui::Ui, dialog: &mut Option<Dialog>) {
        let button = ui.menu_button(icons::SETTINGS, |ui| {
            if ui.button(self.l10n.t("gui.menu_settings")).clicked() {
                *dialog = Some(Dialog::Settings);
                ui.close();
            }
            if ui.button(self.l10n.t("gui.about_revenant")).clicked() {
                *dialog = Some(Dialog::About);
                ui.close();
            }
            ui.separator();
            if ui.button(self.l10n.t("gui.menu_revenant_help")).clicked() {
                ui.ctx()
                    .open_url(egui::OpenUrl::new_tab(crate::views::about::HELP_URL));
                ui.close();
            }
        });
        button.response.on_hover_text(self.l10n.t("gui.settings"));
    }
}
