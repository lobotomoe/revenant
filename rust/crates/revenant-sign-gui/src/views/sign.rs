//! Sign tab. Its content follows the config layer, mirroring the Python client:
//! prompt to connect, prompt to log in, or the signing form.
//!
//! The form itself ([`SignForm`]) is pure UI state; browsing files, spawning the
//! signing job, and revealing the result are side effects the app performs in
//! response to the returned [`SignAction`].

use std::path::{Path, PathBuf};

use eframe::egui;
use revenant_sign_core::appearance::AVAILABLE_FONTS;
use revenant_sign_core::config::{ConfigLayer, ConfigStore};
use revenant_sign_core::pdf::{PageSpec, Position};
use revenant_sign_core::signing::EmbeddedSignatureOptions;

use super::account::{self, AccountAction};
use crate::i18n::Localizer;
use crate::theme;

/// Minimum size of the centered "Sign" button.
const SIGN_BUTTON_MIN: [f32; 2] = [220.0, 34.0];

/// Below this available width, the settings/card section stacks instead of
/// splitting into two columns (egui has no automatic column reflow).
const TWO_COLUMN_MIN_WIDTH: f32 = 720.0;

/// Position presets offered in the appearance combo, in display order.
const POSITIONS: [Position; 5] = [
    Position::BottomRight,
    Position::BottomLeft,
    Position::BottomCenter,
    Position::TopLeft,
    Position::TopRight,
];

/// Bounds for the explicit page-number spinner (1-based in the UI, 0-based in
/// [`PageSpec::Index`]). The upper bound is a sanity cap, not a real PDF limit.
const MIN_PAGE: usize = 1;
const MAX_PAGE: usize = 9999;
/// Max digits and width of the explicit page-number field.
const PAGE_DIGITS: usize = 4;
const PAGE_FIELD_WIDTH: f32 = 52.0;
/// Busy-overlay modal geometry.
const OVERLAY_WIDTH: f32 = 300.0;
const OVERLAY_INNER_PAD: f32 = 24.0;
const OVERLAY_SPINNER_SIZE: f32 = 32.0;

/// What the app should do after rendering the tab.
pub(crate) enum SignAction {
    None,
    /// Open the connect dialog.
    Connect,
    /// Open the login wizard.
    Login,
    /// Open a native picker to choose the input PDF.
    BrowsePdf,
    /// Open a native picker to choose a stamp image.
    BrowseImage,
    /// Open a native save dialog for the output path.
    BrowseOutput,
    /// Start signing the current form (single file or batch).
    Sign,
    /// Cancel an in-progress batch after the current file.
    CancelBatch,
}

/// Embedded (in-document) vs. detached (`.p7s`) signature.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Embedded,
    Detached,
}

/// Progress of a signing job, surfaced under the Sign button.
enum SignStatus {
    Idle,
    Signing,
    /// Success line (already localized).
    Done(String),
    /// Failure line (already localized or a raw error).
    Failed(String),
}

/// Progress of an in-flight batch run.
struct BatchProgress {
    /// 1-based index of the file currently being signed.
    current: usize,
    total: usize,
    filename: String,
}

/// Persistent state of the signing form (layer 2).
pub(crate) struct SignForm {
    pdf_path: String,
    image_path: String,
    output_path: String,
    /// Whether the user set the output path by hand; if not, it auto-derives.
    output_edited: bool,
    mode: Mode,
    position: Position,
    page: PageSpec,
    /// Editing buffer for the explicit page-number field (1-based digits).
    page_input: String,
    font: String,
    invisible: bool,
    reason: String,
    status: SignStatus,
    /// Files queued for batch signing (>1 selects batch mode).
    batch: Vec<PathBuf>,
    /// Present while a batch run is in flight.
    batch_progress: Option<BatchProgress>,
}

impl SignForm {
    pub(crate) fn new(default_font: String) -> Self {
        Self {
            pdf_path: String::new(),
            image_path: String::new(),
            output_path: String::new(),
            output_edited: false,
            mode: Mode::Embedded,
            position: Position::BottomRight,
            page: PageSpec::Last,
            page_input: MIN_PAGE.to_string(),
            font: default_font,
            invisible: false,
            reason: String::new(),
            status: SignStatus::Idle,
            batch: Vec::new(),
            batch_progress: None,
        }
    }

    /// Set the input PDF (from the picker or a drop) and refresh the auto output.
    pub(crate) fn set_pdf(&mut self, path: &Path) {
        self.pdf_path = path.to_string_lossy().into_owned();
        self.status = SignStatus::Idle;
        self.refresh_auto_output();
    }

    /// Load one or more files: a single file uses the single-file field; several
    /// switch to batch mode.
    pub(crate) fn set_files(&mut self, mut paths: Vec<PathBuf>) {
        match paths.len() {
            0 => {}
            1 => {
                self.batch.clear();
                self.set_pdf(&paths.remove(0));
            }
            _ => {
                self.batch = paths;
                self.status = SignStatus::Idle;
                self.batch_progress = None;
            }
        }
    }

    pub(crate) fn is_batch(&self) -> bool {
        !self.batch.is_empty()
    }

    pub(crate) fn batch_files(&self) -> Vec<PathBuf> {
        self.batch.clone()
    }

    pub(crate) fn begin_batch(&mut self) {
        self.batch_progress = Some(BatchProgress {
            current: 0,
            total: self.batch.len(),
            filename: String::new(),
        });
        self.status = SignStatus::Idle;
    }

    pub(crate) fn on_batch_progress(&mut self, current: usize, total: usize, filename: String) {
        self.batch_progress = Some(BatchProgress {
            current,
            total,
            filename,
        });
    }

    pub(crate) fn on_batch_done(&mut self, message: String, ok: bool) {
        self.batch_progress = None;
        self.status = if ok {
            SignStatus::Done(message)
        } else {
            SignStatus::Failed(message)
        };
    }

    pub(crate) fn set_image(&mut self, path: &Path) {
        self.image_path = path.to_string_lossy().into_owned();
    }

    pub(crate) fn set_output(&mut self, path: &Path) {
        self.output_path = path.to_string_lossy().into_owned();
        self.output_edited = true;
    }

    pub(crate) fn pdf_path(&self) -> &str {
        self.pdf_path.trim()
    }

    pub(crate) fn is_detached(&self) -> bool {
        self.mode == Mode::Detached
    }

    /// The output path to write to. An explicit entry is normalized so a bare or
    /// relative name lands next to the input PDF with the right extension; an
    /// empty entry falls back to the derived default. `None` until a PDF is set.
    pub(crate) fn resolved_output(&self) -> Option<PathBuf> {
        let pdf = self.pdf_path.trim();
        if pdf.is_empty() {
            return None;
        }
        let input = Path::new(pdf);
        let explicit = self.output_path.trim();
        if explicit.is_empty() {
            return Some(default_output(input, self.is_detached()));
        }
        Some(normalize_output(
            Path::new(explicit),
            input,
            self.is_detached(),
        ))
    }

    /// The default output path for the current PDF and mode, for the save dialog.
    pub(crate) fn default_output(&self) -> Option<PathBuf> {
        let pdf = self.pdf_path.trim();
        (!pdf.is_empty()).then(|| default_output(Path::new(pdf), self.is_detached()))
    }

    pub(crate) fn embedded_options(&self) -> EmbeddedSignatureOptions {
        let image = self.image_path.trim();
        EmbeddedSignatureOptions {
            page: self.page,
            position: self.position,
            reason: self.reason.trim().to_owned(),
            visible: !self.invisible,
            font: Some(self.font.clone()),
            image_path: (!image.is_empty()).then(|| image.to_owned()),
            ..Default::default()
        }
    }

    pub(crate) fn begin_signing(&mut self) {
        self.status = SignStatus::Signing;
    }

    pub(crate) fn on_signed_ok(&mut self, message: String) {
        self.status = SignStatus::Done(message);
    }

    pub(crate) fn on_signed_failed(&mut self, message: String) {
        self.status = SignStatus::Failed(message);
    }

    /// Drop a finished result line. The Done/Failed messages are pre-localized at
    /// sign time, so after a language switch they would show in the old language;
    /// clearing them avoids a stale, wrong-language line. A job in flight is left
    /// running.
    pub(crate) fn reset_result(&mut self) {
        if matches!(self.status, SignStatus::Done(_) | SignStatus::Failed(_)) {
            self.status = SignStatus::Idle;
        }
    }

    fn refresh_auto_output(&mut self) {
        if self.output_edited {
            return;
        }
        let pdf = self.pdf_path.trim();
        self.output_path = if pdf.is_empty() {
            String::new()
        } else {
            default_output(Path::new(pdf), self.is_detached())
                .to_string_lossy()
                .into_owned()
        };
    }

    /// The fully-configured signing screen: input + image on top, then two
    /// columns (settings left, signer card right), then a large centered Sign
    /// button and status line.
    fn ui(&mut self, ui: &mut egui::Ui, l10n: &Localizer, store: &ConfigStore) -> SignScreen {
        let mut action = SignAction::None;
        let mut account_action = AccountAction::None;
        ui.add_space(8.0);

        // Top (full width): the file(s) to sign and the optional stamp image.
        let top = self.input_section(ui, l10n);
        merge(&mut action, top);

        ui.add_space(6.0);
        ui.separator();
        ui.add_space(6.0);

        // Signature settings and the signer card sit side by side when there is
        // room, and stack when the window is too narrow -- egui does not reflow
        // columns on its own, so we pick the layout from the available width.
        let position = self.position;
        let appearance_enabled = self.appearance_enabled();
        // Captured before the columns: `ui.columns` can overflow and shift the
        // layout's content bounds, which would throw off centering the button.
        let full_width = ui.available_width();
        if full_width >= TWO_COLUMN_MIN_WIDTH {
            ui.columns(2, |cols| {
                if let [left, right] = cols {
                    let settings = self.settings_column(left, l10n);
                    merge(&mut action, settings);
                    // Signer card, then the placement preview fills the space
                    // beneath it -- balancing the columns without overflow.
                    account_action = account::show(right, l10n, store);
                    right.add_space(10.0);
                    super::preview::signature_preview(right, l10n, position, appearance_enabled);
                }
            });
        } else {
            let settings = self.settings_column(ui, l10n);
            merge(&mut action, settings);
            ui.add_space(10.0);
            account_action = account::show(ui, l10n, store);
            ui.add_space(10.0);
            super::preview::signature_preview(ui, l10n, position, appearance_enabled);
        }

        // Bottom: the primary action and result line, centered within the full
        // width (allocated explicitly so a prior overflowing columns row cannot
        // shift it). The in-progress state is a full-window overlay instead, so
        // it can't be clipped off the bottom of the form.
        ui.add_space(12.0);
        ui.allocate_ui_with_layout(
            egui::vec2(full_width, 0.0),
            egui::Layout::top_down(egui::Align::Center),
            |ui| {
                merge(&mut action, self.sign_button(ui, l10n));
                self.result_line(ui);
            },
        );
        merge(&mut action, self.progress_overlay(ui.ctx(), l10n));

        SignScreen {
            sign: action,
            account: account_action,
        }
    }

    /// The top section: two drop zones -- the required PDF (or batch) on the
    /// left, the optional stamp image on the right. Each is click-to-browse and
    /// a drop target; the app routes drops using the stored zone rect.
    fn input_section(&mut self, ui: &mut egui::Ui, l10n: &Localizer) -> SignAction {
        let mut action = SignAction::None;

        let pdf_title = crate::style::zone_title(l10n.t("gui.pdf_file_label"));
        let image_title = crate::style::zone_title(l10n.t("gui.image_opt_label"));
        let pdf_name = self.pdf_zone_name();
        let image_name = crate::style::zone_basename(&self.image_path);
        let appearance_enabled = self.appearance_enabled();

        ui.columns(2, |cols| {
            if let [left, right] = cols {
                let pdf = crate::style::drop_zone(
                    left,
                    crate::icons::PDF,
                    &pdf_title,
                    pdf_name.as_deref(),
                    l10n.t("gui.drop_pdf_hint"),
                    crate::style::PDF_EXTS,
                );
                if pdf.clicked {
                    action = SignAction::BrowsePdf;
                }
                right.add_enabled_ui(appearance_enabled, |ui| {
                    let image = crate::style::drop_zone(
                        ui,
                        crate::icons::IMAGE,
                        &image_title,
                        image_name.as_deref(),
                        l10n.t("gui.drop_image_hint"),
                        crate::style::IMAGE_EXTS,
                    );
                    if image.clicked {
                        action = SignAction::BrowseImage;
                    }
                });
            }
        });

        // Batch: list the queued files below the zones.
        if self.is_batch() {
            ui.add_space(4.0);
            self.batch_list(ui, l10n);
        }
        action
    }

    /// The PDF zone's body text: the file name, a batch count, or nothing (which
    /// falls back to the drop hint).
    fn pdf_zone_name(&self) -> Option<String> {
        if self.is_batch() {
            return Some(format!("{} PDF", self.batch.len()));
        }
        crate::style::zone_basename(&self.pdf_path)
    }

    /// The left column: mode, appearance controls with a live preview, and the
    /// output path.
    fn settings_column(&mut self, ui: &mut egui::Ui, l10n: &Localizer) -> SignAction {
        let mut action = SignAction::None;

        let prev_mode = self.mode;
        ui.horizontal(|ui| {
            ui.selectable_value(&mut self.mode, Mode::Embedded, l10n.t("gui.embedded"));
            ui.selectable_value(&mut self.mode, Mode::Detached, l10n.t("gui.detached_p7s"));
        });
        if self.mode != prev_mode {
            self.refresh_auto_output();
        }

        let detached = self.is_detached();
        let appearance_enabled = self.appearance_enabled();

        // Appearance controls. The live preview lives under the signer card
        // (see `ui`), not here, so this column stays short and the fixed-size
        // preview can never overflow onto the card.
        ui.add_enabled_ui(appearance_enabled, |ui| {
            self.position_combo(ui, l10n);
            self.page_selector(ui, l10n);
            self.font_combo(ui, l10n);
        });

        ui.add_enabled_ui(!detached, |ui| {
            ui.checkbox(&mut self.invisible, l10n.t("gui.invisible_signature"));
        });
        ui.add_enabled_ui(!detached, |ui| {
            ui.horizontal(|ui| {
                ui.label(l10n.t("gui.reason_label"));
                ui.add(crate::style::text_edit(&mut self.reason).desired_width(f32::INFINITY));
            });
        });

        // Output path (auto-derived per file in batch mode, so hidden there).
        if !self.is_batch() {
            ui.horizontal(|ui| {
                ui.label(l10n.t("gui.output_opt_label"));
                // Pin Browse to the right so it stays visible; the text field
                // fills the space between the label and the button.
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button(l10n.t("gui.browse_ellipsis")).clicked() {
                        action = SignAction::BrowseOutput;
                    }
                    if ui
                        .add(
                            crate::style::text_edit(&mut self.output_path)
                                .desired_width(f32::INFINITY),
                        )
                        .changed()
                    {
                        self.output_edited = true;
                    }
                });
            });
            // Show exactly where the file will be written, so a bare or relative
            // name is never a mystery.
            if let Some(resolved) = self.resolved_output() {
                ui.label(
                    egui::RichText::new(format!("{}  {}", crate::icons::SAVE, resolved.display()))
                        .small()
                        .color(theme::MUTED),
                );
            }
        }
        action
    }

    /// The large centered Sign button. Its label and gating follow the mode
    /// (single vs. batch, embedded vs. detached) and busy state.
    fn sign_button(&self, ui: &mut egui::Ui, l10n: &Localizer) -> SignAction {
        let busy = matches!(self.status, SignStatus::Signing) || self.batch_progress.is_some();
        let has_input = self.is_batch() || !self.pdf_path.trim().is_empty();
        let label = if self.is_batch() {
            l10n.tf("gui.sign_n_pdfs", &[("n", &self.batch.len().to_string())])
        } else if self.is_detached() {
            l10n.t("gui.sign_detached").to_owned()
        } else {
            l10n.t("gui.sign_pdf").to_owned()
        };
        let mut action = SignAction::None;
        let button = crate::style::primary_button(format!("{}  {label}", crate::icons::SIGN))
            .min_size(egui::vec2(SIGN_BUTTON_MIN[0], SIGN_BUTTON_MIN[1]));
        if ui.add_enabled(!busy && has_input, button).clicked() {
            action = SignAction::Sign;
        }
        action
    }

    /// Whether the visible-signature appearance controls apply (embedded and
    /// not marked invisible).
    fn appearance_enabled(&self) -> bool {
        !self.is_detached() && !self.invisible
    }

    /// Render the batch file list with per-item remove buttons.
    fn batch_list(&mut self, ui: &mut egui::Ui, l10n: &Localizer) {
        let mut remove = None;
        egui::ScrollArea::vertical()
            .max_height(90.0)
            .show(ui, |ui| {
                for (index, path) in self.batch.iter().enumerate() {
                    ui.horizontal(|ui| {
                        if ui.small_button(l10n.t("gui.remove")).clicked() {
                            remove = Some(index);
                        }
                        let name = path
                            .file_name()
                            .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
                        ui.label(name);
                    });
                }
            });
        if let Some(index) = remove {
            self.batch.remove(index);
        }
    }

    fn position_combo(&mut self, ui: &mut egui::Ui, l10n: &Localizer) {
        ui.horizontal(|ui| {
            ui.label(l10n.t("gui.position_label"));
            egui::ComboBox::from_id_salt("sign_position")
                .selected_text(position_label(l10n, self.position))
                .show_ui(ui, |ui| {
                    for pos in POSITIONS {
                        ui.selectable_value(&mut self.position, pos, position_label(l10n, pos));
                    }
                });
        });
    }

    /// Page selection: `Last`/`First` presets plus a numeric spinner for any
    /// explicit page. Editing the spinner switches to explicit mode, so a signer
    /// can target a page well beyond the old fixed list.
    fn page_selector(&mut self, ui: &mut egui::Ui, l10n: &Localizer) {
        ui.horizontal(|ui| {
            ui.label(l10n.t("gui.page_label"));
            if ui
                .selectable_label(self.page == PageSpec::Last, l10n.t("gui.page_last"))
                .clicked()
            {
                self.page = PageSpec::Last;
            }
            if ui
                .selectable_label(self.page == PageSpec::First, l10n.t("gui.page_first"))
                .clicked()
            {
                self.page = PageSpec::First;
            }
            let is_index = matches!(self.page, PageSpec::Index(_));
            // A fixed-width, digit-only field (1-based). Unlike `DragValue`, it
            // cannot grow with its content and blow up the layout.
            let field = ui.add(
                crate::style::text_edit(&mut self.page_input)
                    .char_limit(PAGE_DIGITS)
                    .desired_width(PAGE_FIELD_WIDTH)
                    .horizontal_align(egui::Align::Center),
            );
            if field.changed() {
                self.page_input.retain(|c| c.is_ascii_digit());
                if let Ok(number) = self.page_input.parse::<usize>() {
                    let clamped = number.clamp(MIN_PAGE, MAX_PAGE);
                    self.page = PageSpec::Index(clamped - 1);
                }
            } else if field.gained_focus() && !is_index {
                // Focusing the field switches to explicit-page mode.
                let number = self
                    .page_input
                    .parse::<usize>()
                    .unwrap_or(MIN_PAGE)
                    .clamp(MIN_PAGE, MAX_PAGE);
                self.page = PageSpec::Index(number - 1);
            }
        });
    }

    fn font_combo(&mut self, ui: &mut egui::Ui, l10n: &Localizer) {
        ui.horizontal(|ui| {
            ui.label(l10n.t("gui.font_label"));
            egui::ComboBox::from_id_salt("sign_font")
                .selected_text(&self.font)
                .show_ui(ui, |ui| {
                    for font in AVAILABLE_FONTS {
                        ui.selectable_value(&mut self.font, font.to_owned(), font);
                    }
                });
        });
    }

    /// Render the completed-result line (success or failure) below the button.
    /// In-progress state lives in [`Self::progress_overlay`] instead.
    fn result_line(&self, ui: &mut egui::Ui) {
        match &self.status {
            SignStatus::Done(message) => {
                ui.add_space(4.0);
                ui.colored_label(theme::OK, message);
            }
            SignStatus::Failed(message) => {
                ui.add_space(4.0);
                ui.colored_label(theme::ERROR, message);
            }
            SignStatus::Idle | SignStatus::Signing => {}
        }
    }

    /// A full-window modal shown while a signing job runs, so the busy state is
    /// unmistakable and never clipped by the form layout. A batch run also gets a
    /// progress bar, the current file, and a Cancel button; single signing just
    /// shows a spinner. Returns [`SignAction::CancelBatch`] if the user cancels.
    fn progress_overlay(&self, ctx: &egui::Context, l10n: &Localizer) -> SignAction {
        let signing = matches!(self.status, SignStatus::Signing);
        if !signing && self.batch_progress.is_none() {
            return SignAction::None;
        }
        let mut action = SignAction::None;
        egui::Modal::new(egui::Id::new("signing_overlay")).show(ctx, |ui| {
            ui.set_width(OVERLAY_WIDTH);
            ui.vertical_centered(|ui| {
                ui.add_space(10.0);
                ui.add(egui::Spinner::new().size(OVERLAY_SPINNER_SIZE));
                ui.add_space(12.0);
                if let Some(progress) = &self.batch_progress {
                    // `u16::from` is lossless, sidestepping the float-cast lint.
                    let done =
                        u16::try_from(progress.current.saturating_sub(1)).unwrap_or(u16::MAX);
                    let total = u16::try_from(progress.total).unwrap_or(u16::MAX);
                    let fraction = if total == 0 {
                        0.0
                    } else {
                        f32::from(done) / f32::from(total)
                    };
                    ui.add(
                        egui::ProgressBar::new(fraction)
                            .show_percentage()
                            .desired_width(OVERLAY_WIDTH - OVERLAY_INNER_PAD),
                    );
                    ui.add_space(6.0);
                    ui.label(l10n.tf(
                        "gui.signing_n_of_total_filename",
                        &[
                            ("n", &progress.current.to_string()),
                            ("total", &progress.total.to_string()),
                            ("filename", &progress.filename),
                        ],
                    ));
                    ui.add_space(12.0);
                    if ui.button(l10n.t("gui.cancel")).clicked() {
                        action = SignAction::CancelBatch;
                    }
                } else {
                    ui.label(l10n.t("gui.signing_ellipsis"));
                }
                ui.add_space(10.0);
            });
        });
        action
    }
}

/// `document.pdf` -> `document_signed.pdf`, or `document.pdf.p7s` when detached.
/// Matches the CLI's naming so the two clients agree on defaults.
pub(crate) fn default_output(pdf: &Path, detached: bool) -> PathBuf {
    if detached {
        pdf.with_extension("pdf.p7s")
    } else {
        let stem = pdf.file_stem().unwrap_or_default().to_string_lossy();
        pdf.with_file_name(format!("{stem}_signed.pdf"))
    }
}

/// Turn a user-entered output path into a concrete target. A relative or bare
/// name (e.g. `contract`) resolves against the input PDF's directory rather than
/// the process's working directory -- which, for a GUI launched from a bundle,
/// is unpredictable -- and a missing or mismatched extension is corrected to
/// `.pdf` (embedded) or `.p7s` (detached). This keeps a typed name from silently
/// landing who-knows-where with no extension.
fn normalize_output(entered: &Path, input_pdf: &Path, detached: bool) -> PathBuf {
    let anchored = if entered.is_absolute() {
        entered.to_path_buf()
    } else {
        input_pdf
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(entered)
    };
    ensure_extension(anchored, detached)
}

/// Give a bare name the extension the signing mode requires (`.pdf` embedded,
/// `.p7s` detached). An extension the user typed is respected as-is -- we only
/// fill in the blank, never override an explicit choice.
fn ensure_extension(path: PathBuf, detached: bool) -> PathBuf {
    if path.extension().is_some() {
        return path;
    }
    let wanted = if detached { "p7s" } else { "pdf" };
    let mut name = path.into_os_string();
    name.push(".");
    name.push(wanted);
    PathBuf::from(name)
}

fn position_label(l10n: &Localizer, position: Position) -> &str {
    match position {
        Position::BottomRight => l10n.t("gui.pos_bottom_right"),
        Position::BottomLeft => l10n.t("gui.pos_bottom_left"),
        Position::BottomCenter => l10n.t("gui.pos_bottom_center"),
        Position::TopLeft => l10n.t("gui.pos_top_left"),
        Position::TopRight => l10n.t("gui.pos_top_right"),
    }
}

/// The result of rendering the Sign tab: the signing intent plus any account-
/// panel intent (the latter only exists at the fully-configured layer).
pub(crate) struct SignScreen {
    pub(crate) sign: SignAction,
    pub(crate) account: AccountAction,
}

impl SignScreen {
    /// A screen with no account panel (the connect/login prompt layers).
    fn prompt_only(sign: SignAction) -> Self {
        Self {
            sign,
            account: AccountAction::None,
        }
    }
}

/// Keep the last non-`None` action, so a later section does not erase an intent
/// raised by an earlier one.
fn merge(action: &mut SignAction, next: SignAction) {
    if !matches!(next, SignAction::None) {
        *action = next;
    }
}

pub(crate) fn show(
    ui: &mut egui::Ui,
    l10n: &Localizer,
    layer: ConfigLayer,
    form: &mut SignForm,
    store: &ConfigStore,
) -> SignScreen {
    match layer {
        ConfigLayer::Unconfigured => SignScreen::prompt_only(prompt(
            ui,
            l10n,
            "gui.connect_to_a_server_to_sign_documents",
            crate::icons::CONNECT,
            "gui.connect",
            SignAction::Connect,
        )),
        ConfigLayer::ServerConfigured => SignScreen::prompt_only(prompt(
            ui,
            l10n,
            "gui.server_connected_log_in_to_sign_documents",
            crate::icons::LOGIN,
            "gui.log_in",
            SignAction::Login,
        )),
        ConfigLayer::FullyConfigured => form.ui(ui, l10n, store),
    }
}

/// A centered message with a single call-to-action button (layers 0 and 1).
fn prompt(
    ui: &mut egui::Ui,
    l10n: &Localizer,
    message_key: &str,
    icon: &str,
    button_key: &str,
    on_click: SignAction,
) -> SignAction {
    let mut action = SignAction::None;
    ui.vertical_centered(|ui| {
        ui.add_space(32.0);
        ui.label(l10n.t(message_key));
        ui.add_space(12.0);
        let label = format!("{icon}  {}", l10n.t(button_key));
        if ui.add(crate::style::primary_button(label)).clicked() {
            action = on_click;
        }
    });
    action
}

#[cfg(test)]
mod tests {
    use super::{default_output, Mode, SignForm};
    use std::path::{Path, PathBuf};

    #[test]
    fn default_output_embedded_appends_signed() {
        assert_eq!(
            default_output(Path::new("/tmp/doc.pdf"), false),
            PathBuf::from("/tmp/doc_signed.pdf")
        );
    }

    #[test]
    fn default_output_detached_appends_p7s() {
        assert_eq!(
            default_output(Path::new("/tmp/doc.pdf"), true),
            PathBuf::from("/tmp/doc.pdf.p7s")
        );
    }

    #[test]
    fn set_pdf_auto_derives_output() {
        let mut form = SignForm::new("noto-sans".to_owned());
        form.set_pdf(Path::new("/tmp/a.pdf"));
        assert_eq!(
            form.resolved_output(),
            Some(PathBuf::from("/tmp/a_signed.pdf"))
        );
    }

    #[test]
    fn switching_to_detached_updates_auto_output() {
        let mut form = SignForm::new("noto-sans".to_owned());
        form.set_pdf(Path::new("/tmp/a.pdf"));
        form.mode = Mode::Detached;
        form.refresh_auto_output();
        assert_eq!(
            form.resolved_output(),
            Some(PathBuf::from("/tmp/a.pdf.p7s"))
        );
    }

    #[test]
    fn manual_output_survives_mode_switch() {
        let mut form = SignForm::new("noto-sans".to_owned());
        form.set_pdf(Path::new("/tmp/a.pdf"));
        form.set_output(Path::new("/custom/out.pdf"));
        form.mode = Mode::Detached;
        form.refresh_auto_output();
        assert_eq!(
            form.resolved_output(),
            Some(PathBuf::from("/custom/out.pdf"))
        );
    }

    #[test]
    fn bare_output_name_resolves_next_to_input_with_extension() {
        let mut form = SignForm::new("noto-sans".to_owned());
        form.set_pdf(Path::new("/docs/passport.pdf"));
        form.set_output(Path::new("contract"));
        // Relative bare name -> input's directory, plus the embedded extension.
        assert_eq!(
            form.resolved_output(),
            Some(PathBuf::from("/docs/contract.pdf"))
        );
        // Detached mode gives it the .p7s extension instead.
        form.mode = Mode::Detached;
        assert_eq!(
            form.resolved_output(),
            Some(PathBuf::from("/docs/contract.p7s"))
        );
    }

    #[test]
    fn typed_extension_is_respected() {
        let mut form = SignForm::new("noto-sans".to_owned());
        form.set_pdf(Path::new("/docs/passport.pdf"));
        form.set_output(Path::new("signed.pdf"));
        assert_eq!(
            form.resolved_output(),
            Some(PathBuf::from("/docs/signed.pdf"))
        );
    }

    #[test]
    fn embedded_options_carry_high_page_index() {
        use revenant_sign_core::pdf::PageSpec;
        let mut form = SignForm::new("noto-sans".to_owned());
        // A page well past the old fixed cap of 5 (0-based index 41 == page 42).
        form.page = PageSpec::Index(41);
        assert_eq!(form.embedded_options().page, PageSpec::Index(41));
    }

    #[test]
    fn embedded_options_reflect_invisible_and_font() {
        let mut form = SignForm::new("ghea-grapalat".to_owned());
        form.invisible = true;
        let options = form.embedded_options();
        assert!(!options.visible);
        assert_eq!(options.font.as_deref(), Some("ghea-grapalat"));
        assert!(options.image_path.is_none());
    }
}
