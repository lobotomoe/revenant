//! The Settings window: the UI language, and where there is no menu bar to
//! carry it, the About section. The selection persists through the shared
//! config, so it is remembered across launches and shared with the CLI.
//!
//! A window of its own rather than a modal dialog, so the app stays usable
//! while it is open, as both macOS and Windows expect of settings. Changes
//! apply as they are made; there is nothing to confirm.

use eframe::egui::{self, Align, Layout, RichText, Ui, Vec2, ViewportBuilder, ViewportId};
use revenant_sign_core::config::ConfigStore;
use revenant_sign_core::constants::VERSION;

use crate::i18n::{self, Localizer, SUPPORTED_LOCALES, SYSTEM_LANGUAGE};
use crate::{icons, links};

const VIEWPORT_KEY: &str = "settings_window";

/// The macOS form: a fixed window just big enough for the choices.
const FORM_WIDTH: f32 = 420.0;
const FORM_PADDING: f32 = 20.0;
const FORM_LABEL_WIDTH: f32 = 140.0;
const FORM_ROW_HEIGHT: f32 = 30.0;
/// The margin the central panel adds under the last row.
const PANEL_MARGIN: f32 = 8.0;

/// The settings page: a resizable window of cards.
const PAGE_SIZE: [f32; 2] = [560.0, 480.0];
const PAGE_MIN_SIZE: [f32; 2] = [420.0, 320.0];
const PAGE_PADDING: f32 = 24.0;
const SECTION_GAP: f32 = 24.0;

/// What the app should do after rendering the window.
pub(crate) enum SettingsAction {
    None,
    Close,
    /// Persist and apply a new language setting (a locale code or `"system"`).
    SetLanguage(String),
}

/// How the window presents the settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SettingsLayout {
    /// macOS: a small fixed window with a right-aligned label and the choices
    /// beside it. About is in the app menu.
    Form,
    /// Windows and Linux: a page of cards, titled, with the About section at
    /// the bottom (where Windows puts it).
    Page,
}

/// Bring an already open Settings window to the front.
pub(crate) fn focus(ctx: &egui::Context) {
    ctx.send_viewport_cmd_to(
        ViewportId::from_hash_of(VIEWPORT_KEY),
        egui::ViewportCommand::Focus,
    );
}

pub(crate) fn show(
    ctx: &egui::Context,
    l10n: &Localizer,
    store: &ConfigStore,
    layout: SettingsLayout,
) -> SettingsAction {
    let builder = ViewportBuilder::default().with_title(l10n.t("gui.settings"));
    let builder = match layout {
        SettingsLayout::Form => builder
            .with_inner_size(form_size())
            .with_resizable(false)
            .with_minimize_button(false)
            .with_maximize_button(false),
        SettingsLayout::Page => builder
            .with_inner_size(PAGE_SIZE)
            .with_min_inner_size(PAGE_MIN_SIZE),
    };
    let builder = crate::with_app_icon(builder);

    ctx.show_viewport_immediate(
        ViewportId::from_hash_of(VIEWPORT_KEY),
        builder,
        |ui, _class| {
            if ui.input(|input| input.viewport().close_requested()) {
                return SettingsAction::Close;
            }
            let current = store.language();
            let chosen = egui::CentralPanel::default()
                .show_inside(ui, |ui| match layout {
                    SettingsLayout::Form => form(ui, l10n, &current),
                    SettingsLayout::Page => page(ui, l10n, &current),
                })
                .inner;
            chosen.map_or(SettingsAction::None, SettingsAction::SetLanguage)
        },
    )
}

/// The language choices: "System", then each language under its own name.
fn language_options(l10n: &Localizer) -> Vec<(&str, &str)> {
    let mut options = vec![(SYSTEM_LANGUAGE, l10n.t("gui.system"))];
    options.extend(SUPPORTED_LOCALES.iter().copied());
    options
}

fn form_size() -> Vec2 {
    // The choices are "System" plus every supported language.
    #[allow(clippy::cast_precision_loss)] // a handful of languages
    let rows = (SUPPORTED_LOCALES.len() + 1) as f32;
    Vec2::new(
        FORM_WIDTH,
        rows * FORM_ROW_HEIGHT + 2.0 * FORM_PADDING + PANEL_MARGIN,
    )
}

/// The macOS form. A radio group rather than a pop-up menu: an egui pop-up
/// cannot reach past the edge of its window as a native one does, and in a
/// window this small the list would be cut off.
fn form(ui: &mut Ui, l10n: &Localizer, current: &str) -> Option<String> {
    let mut chosen = None;
    ui.add_space(FORM_PADDING);
    ui.horizontal_top(|ui| {
        ui.allocate_ui_with_layout(
            Vec2::new(FORM_LABEL_WIDTH, FORM_ROW_HEIGHT),
            Layout::right_to_left(Align::Center),
            |ui| ui.label(l10n.t("gui.language_label")),
        );
        ui.vertical(|ui| {
            ui.spacing_mut().item_spacing.y = 0.0;
            for (code, name) in language_options(l10n) {
                let (rect, _) = ui.allocate_exact_size(
                    Vec2::new(ui.available_width(), FORM_ROW_HEIGHT),
                    egui::Sense::hover(),
                );
                let row = ui.put(rect, |ui: &mut Ui| {
                    ui.with_layout(Layout::left_to_right(Align::Center), |ui| {
                        ui.radio(current == code, name)
                    })
                    .inner
                });
                if row.clicked() && current != code {
                    chosen = Some(code.to_owned());
                }
            }
        });
    });
    chosen
}

/// The Windows/Linux page: a title, a card per setting, and About.
fn page(ui: &mut Ui, l10n: &Localizer, current: &str) -> Option<String> {
    let mut chosen = None;
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            egui::Frame::new()
                .inner_margin(PAGE_PADDING)
                .show(ui, |ui| {
                    ui.label(RichText::new(l10n.t("gui.settings")).heading().strong());
                    ui.add_space(SECTION_GAP / 2.0);
                    card(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(icons::LANGUAGE).size(20.0));
                            ui.label(l10n.t("gui.language"));
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                chosen = language_combo(ui, l10n, current);
                            });
                        });
                    });

                    ui.add_space(SECTION_GAP);
                    ui.label(RichText::new(l10n.t("gui.about_revenant")).strong());
                    ui.add_space(4.0);
                    card(ui, |ui| about(ui, l10n));
                });
        });
    chosen
}

fn language_combo(ui: &mut Ui, l10n: &Localizer, current: &str) -> Option<String> {
    let options = language_options(l10n);
    let selected_text = options
        .iter()
        .find(|(code, _)| *code == current)
        .map_or_else(|| i18n::endonym(current), |(_, name)| *name);
    let mut chosen = None;
    egui::ComboBox::from_id_salt("settings_language")
        .selected_text(selected_text)
        .show_ui(ui, |ui| {
            for (code, name) in &options {
                if ui.selectable_label(current == *code, *name).clicked() && current != *code {
                    chosen = Some((*code).to_owned());
                }
            }
        });
    chosen
}

fn card(ui: &mut Ui, content: impl FnOnce(&mut Ui)) {
    crate::style::card(ui).show(ui, |ui| {
        ui.set_width(ui.available_width());
        content(ui);
    });
}

fn about(ui: &mut Ui, l10n: &Localizer) {
    ui.horizontal(|ui| {
        ui.label(RichText::new(icons::ABOUT).size(20.0));
        ui.vertical(|ui| {
            ui.label(RichText::new("Revenant").strong());
            ui.weak(l10n.tf("gui.version_version", &[("version", VERSION)]));
        });
    });
    ui.add_space(8.0);
    ui.label(l10n.t("gui.cross_platform_client_for_arx_cosign_electronic_signatures"));
    ui.weak(l10n.t("gui.author_aleksandr_kraiz"));
    ui.weak(l10n.t("gui.license_apache_2_0"));
    ui.add_space(8.0);
    ui.horizontal(|ui| {
        ui.hyperlink_to(l10n.t("gui.github"), links::REPO_URL);
        ui.hyperlink_to(l10n.t("gui.report_a_bug"), links::ISSUES_URL);
        ui.hyperlink_to(l10n.t("gui.telegram"), links::TELEGRAM_URL);
    });
}
