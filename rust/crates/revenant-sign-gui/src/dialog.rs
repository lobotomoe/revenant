//! The frame every modal dialog shares: a title, the content, and a row of
//! buttons laid out the way the platform lays out its own dialogs.
//!
//! - Windows (a Fluent `ContentDialog`): the action that does the thing comes
//!   first and Cancel last, the buttons share the row equally, and the row sits
//!   on a band of its own.
//! - macOS and GNOME: Cancel comes first and the default action last, at the
//!   trailing edge.
//!
//! Either way Enter presses the default button and Escape the cancel button. A
//! click outside the dialog does nothing: these dialogs hold typed input (a
//! password, a server address) that a stray click must not throw away.

use eframe::egui::{
    self, Align, Color32, CornerRadius, Key, Layout, Margin, Modifiers, RichText, Ui, Vec2,
};

use crate::{style, theme};

/// Padding around the title and content, and around the button row.
const PADDING: i8 = 20;
/// Space between the title and the content.
const TITLE_GAP: f32 = 12.0;
/// The smallest a dialog button gets, so short labels ("OK") still make a
/// comfortable target and a row of buttons lines up.
const BUTTON_MIN_SIZE: Vec2 = Vec2::new(88.0, 30.0);
const BUTTON_GAP: f32 = 8.0;

/// How a platform orders and sizes the buttons of a dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ButtonLayout {
    /// Windows: the default action first, Cancel last, all of equal width
    /// across the row, on a band of their own.
    Fluent,
    /// macOS and GNOME: Cancel first, the default action last, right-aligned.
    Trailing,
}

/// What a button does, which decides where it goes and which key presses it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Role {
    /// Steps back in a multi-step dialog. Always just before the default
    /// action, so Back and Next sit together.
    Back,
    /// The action the dialog is for. Accent-filled, pressed by Enter.
    Default,
    /// An action that destroys something. Takes the default action's place,
    /// but in red and never on Enter, so it is never taken by accident.
    Destructive,
    /// Leaves the dialog without doing anything. Pressed by Escape.
    Cancel,
}

/// One button of a dialog, reporting `action` when chosen.
pub(crate) struct DialogButton<A> {
    pub(crate) label: String,
    pub(crate) role: Role,
    pub(crate) enabled: bool,
    pub(crate) action: A,
}

impl<A> DialogButton<A> {
    pub(crate) fn new(label: impl Into<String>, role: Role, action: A) -> Self {
        Self {
            label: label.into(),
            role,
            enabled: true,
            action,
        }
    }

    pub(crate) fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }
}

/// A modal dialog: an optional title, content, and buttons.
pub(crate) struct DialogFrame<'a> {
    id: &'static str,
    title: Option<&'a str>,
    /// Muted text at the trailing end of the title row (a wizard's "Step 1 of 2").
    title_detail: Option<&'a str>,
    width: f32,
    layout: ButtonLayout,
}

impl<'a> DialogFrame<'a> {
    pub(crate) fn new(id: &'static str, width: f32, layout: ButtonLayout) -> Self {
        Self {
            id,
            title: None,
            title_detail: None,
            width,
            layout,
        }
    }

    pub(crate) fn title(mut self, title: &'a str) -> Self {
        self.title = Some(title);
        self
    }

    pub(crate) fn title_detail(mut self, detail: &'a str) -> Self {
        self.title_detail = Some(detail);
        self
    }

    /// Show the dialog for this frame. Returns what `content` returned and the
    /// action of the button chosen by click, Enter or Escape, if any.
    pub(crate) fn show<A: Copy, R>(
        self,
        ctx: &egui::Context,
        buttons: &[DialogButton<A>],
        content: impl FnOnce(&mut Ui) -> R,
    ) -> (R, Option<A>) {
        let frame = egui::Frame::window(&ctx.global_style()).inner_margin(Margin::ZERO);
        let response = egui::Modal::new(egui::Id::new(self.id))
            .frame(frame)
            .show(ctx, |ui| {
                ui.set_width(self.width);
                ui.spacing_mut().item_spacing.y = 0.0;
                let inner = egui::Frame::new()
                    .inner_margin(Margin::same(PADDING))
                    .show(ui, |ui| {
                        ui.spacing_mut().item_spacing.y = 8.0;
                        self.title_row(ui);
                        content(ui)
                    })
                    .inner;
                let clicked = self.button_row(ui, buttons);
                (inner, clicked)
            });

        let (inner, mut chosen) = response.inner;
        if chosen.is_none() && response.is_top_modal && !response.any_popup_open {
            chosen = keyboard_choice(ctx, buttons);
        }
        (inner, chosen)
    }

    fn title_row(&self, ui: &mut Ui) {
        let Some(title) = self.title else {
            return;
        };
        ui.horizontal(|ui| {
            ui.label(RichText::new(title).heading().strong());
            if let Some(detail) = self.title_detail {
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.colored_label(theme::MUTED, detail);
                });
            }
        });
        ui.add_space(TITLE_GAP - ui.spacing().item_spacing.y);
    }

    fn button_row<A: Copy>(&self, ui: &mut Ui, buttons: &[DialogButton<A>]) -> Option<A> {
        let ordered = ordered(buttons, self.layout);
        match self.layout {
            ButtonLayout::Fluent => {
                let window_radius = ui.visuals().window_corner_radius;
                egui::Frame::new()
                    .fill(band_color(ui))
                    .corner_radius(CornerRadius {
                        nw: 0,
                        ne: 0,
                        sw: window_radius.sw,
                        se: window_radius.se,
                    })
                    .inner_margin(Margin::same(PADDING))
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        #[allow(clippy::cast_precision_loss)] // at most a few buttons
                        let count = ordered.len() as f32;
                        let width = ((ui.available_width() - BUTTON_GAP * (count - 1.0)) / count)
                            .max(BUTTON_MIN_SIZE.x);
                        ui.horizontal(|ui| {
                            ui.spacing_mut().item_spacing.x = BUTTON_GAP;
                            ordered.iter().fold(None, |chosen, button| {
                                add_button(ui, button, Vec2::new(width, BUTTON_MIN_SIZE.y))
                                    .or(chosen)
                            })
                        })
                        .inner
                    })
                    .inner
            }
            ButtonLayout::Trailing => {
                egui::Frame::new()
                    .inner_margin(Margin {
                        left: PADDING,
                        right: PADDING,
                        top: 0,
                        bottom: PADDING,
                    })
                    .show(ui, |ui| {
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            ui.spacing_mut().item_spacing.x = BUTTON_GAP;
                            // Right to left, so the last button is placed first.
                            ordered.iter().rev().fold(None, |chosen, button| {
                                add_button(ui, button, BUTTON_MIN_SIZE).or(chosen)
                            })
                        })
                        .inner
                    })
                    .inner
            }
        }
    }
}

/// The buttons in the order `layout` shows them, left to right.
fn ordered<A>(buttons: &[DialogButton<A>], layout: ButtonLayout) -> Vec<&DialogButton<A>> {
    let rank = |role: Role| match (layout, role) {
        (ButtonLayout::Fluent, Role::Back) | (ButtonLayout::Trailing, Role::Cancel) => 0,
        (ButtonLayout::Fluent, Role::Default | Role::Destructive)
        | (ButtonLayout::Trailing, Role::Back) => 1,
        (ButtonLayout::Fluent, Role::Cancel)
        | (ButtonLayout::Trailing, Role::Default | Role::Destructive) => 2,
    };
    let mut ordered: Vec<_> = buttons.iter().collect();
    ordered.sort_by_key(|button| rank(button.role));
    ordered
}

fn add_button<A: Copy>(ui: &mut Ui, button: &DialogButton<A>, min_size: Vec2) -> Option<A> {
    let widget = match button.role {
        Role::Default => style::primary_button(button.label.clone()),
        Role::Destructive => {
            egui::Button::new(RichText::new(button.label.clone()).color(theme::ERROR))
        }
        Role::Back | Role::Cancel => egui::Button::new(button.label.clone()),
    };
    ui.add_enabled(button.enabled, widget.min_size(min_size))
        .clicked()
        .then_some(button.action)
}

/// The button Escape or Enter presses this frame, if either was pressed.
fn keyboard_choice<A: Copy>(ctx: &egui::Context, buttons: &[DialogButton<A>]) -> Option<A> {
    let with_role = |role: Role| {
        buttons
            .iter()
            .find(|button| button.role == role && button.enabled)
            .map(|button| button.action)
    };
    if ctx.input_mut(|input| input.consume_key(Modifiers::NONE, Key::Escape)) {
        return with_role(Role::Cancel);
    }
    let default = with_role(Role::Default)?;
    ctx.input_mut(|input| input.consume_key(Modifiers::NONE, Key::Enter))
        .then_some(default)
}

/// The button band's fill: a step darker than the dialog in light mode and a
/// step lighter in dark mode, as Fluent does.
fn band_color(ui: &Ui) -> Color32 {
    if ui.visuals().dark_mode {
        Color32::from_white_alpha(8)
    } else {
        Color32::from_black_alpha(10)
    }
}

#[cfg(test)]
mod tests {
    use super::{ordered, ButtonLayout, DialogButton, Role};

    fn wizard_buttons() -> Vec<DialogButton<&'static str>> {
        vec![
            DialogButton::new("Next", Role::Default, "next"),
            DialogButton::new("Cancel", Role::Cancel, "cancel"),
            DialogButton::new("Back", Role::Back, "back"),
        ]
    }

    fn labels(buttons: &[DialogButton<&'static str>], layout: ButtonLayout) -> Vec<&'static str> {
        ordered(buttons, layout)
            .iter()
            .map(|button| button.action)
            .collect()
    }

    #[test]
    fn windows_puts_the_action_first_and_cancel_last() {
        assert_eq!(
            labels(&wizard_buttons(), ButtonLayout::Fluent),
            ["back", "next", "cancel"]
        );
    }

    #[test]
    fn mac_and_gnome_put_cancel_first_and_the_action_last() {
        assert_eq!(
            labels(&wizard_buttons(), ButtonLayout::Trailing),
            ["cancel", "back", "next"]
        );
    }

    #[test]
    fn a_destructive_action_takes_the_default_place() {
        let buttons = vec![
            DialogButton::new("Cancel", Role::Cancel, "cancel"),
            DialogButton::new("Disconnect", Role::Destructive, "disconnect"),
        ];
        assert_eq!(
            labels(&buttons, ButtonLayout::Fluent),
            ["disconnect", "cancel"]
        );
        assert_eq!(
            labels(&buttons, ButtonLayout::Trailing),
            ["cancel", "disconnect"]
        );
    }
}
